import datetime as dt
import gzip
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from update_blocklist import (
    MergeStats,
    build_header,
    extract_candidates,
    normalize_domain,
    write_chunks,
    write_outputs,
)


# Check domain cleanup and strict DNS validation.
class NormalizeDomainTests(unittest.TestCase):
    def test_normalizes_domains_and_urls(self):
        cases = {
            "Example.COM.": "example.com",
            "*.ads.example.com": "ads.example.com",
            "https://User:pass@Example.com:443/path?q=1": "example.com",
            "bücher.example": "xn--bcher-kva.example",
            "||tracker.example^": "tracker.example",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_domain(value), expected)

    def test_rejects_invalid_domains(self):
        for value in (
            "localhost",
            "127.0.0.1",
            "::1",
            "bad_domain.example",
            "-bad.example",
            "example.123",
            "",
        ):
            with self.subTest(value=value):
                self.assertIsNone(normalize_domain(value))


# Check supported list formats and ignored rule types.
class ExtractCandidatesTests(unittest.TestCase):
    def test_hosts_line(self):
        candidates, reason = extract_candidates("0.0.0.0 ads.example tracker.example # comment")
        self.assertIsNone(reason)
        self.assertEqual(candidates, ["ads.example", "tracker.example"])

    def test_adblock_rule(self):
        candidates, reason = extract_candidates("||ads.example^$third-party")
        self.assertIsNone(reason)
        self.assertEqual(candidates, ["ads.example^"])

    def test_url_line(self):
        candidates, reason = extract_candidates("https://phish.example/login")
        self.assertIsNone(reason)
        self.assertEqual(candidates, ["https://phish.example/login"])

    def test_skips_non_network_rules(self):
        for line, expected_reason in (
            ("! comment", "comment_or_header"),
            ("@@||allowed.example^", "exception_rule"),
            ("example.com##.ad", "cosmetic_rule"),
            ("/advert[0-9]+/", "regex_rule"),
        ):
            with self.subTest(line=line):
                candidates, reason = extract_candidates(line)
                self.assertEqual(candidates, [])
                self.assertEqual(reason, expected_reason)


# Check chunk headers, size limits, cleanup, and gzip copies.
class ChunkWriterTests(unittest.TestCase):
    def test_restored_ascii_header_and_chunk_label(self):
        generated_at = dt.datetime(2026, 7, 18, tzinfo=dt.timezone.utc)
        header = build_header(generated_at, info="chunk2").decode("utf-8")

        self.assertTrue(header.startswith("! ______ ____ __\n"))
        self.assertEqual(header.count("! AD-List-Merger"), 1)
        self.assertIn("! Github page: https://github.com/HyRespt/AD-List-Merger/", header)
        self.assertIn("! Info: chunk2", header)
        self.assertNotIn("! Unique domains:", header)
        self.assertNotIn("! Sources processed:", header)

    def test_chunks_stay_under_limit_and_gzip_round_trips(self):
        domains = [f"subdomain-{index:04d}.example.com" for index in range(200)]
        generated_at = dt.datetime(2026, 7, 18, tzinfo=dt.timezone.utc)

        with tempfile.TemporaryDirectory() as temporary_directory:
            chunk_dir = Path(temporary_directory) / "chunks"
            stale = chunk_dir / "combined_blocklist_part_999.txt"
            chunk_dir.mkdir(parents=True)
            stale.write_text("stale\n", encoding="utf-8")

            chunk_paths = write_chunks(
                domains,
                chunk_dir,
                max_bytes=700,
                generated_at=generated_at,
            )

            self.assertGreater(len(chunk_paths), 1)
            self.assertFalse(stale.exists())

            # Rebuild the original domain order from every generated part.
            recovered = []
            for index, chunk_path in enumerate(chunk_paths, start=1):
                self.assertLessEqual(chunk_path.stat().st_size, 700)
                text = chunk_path.read_text(encoding="utf-8")
                self.assertEqual(text.count("! ______ ____ __"), 1)
                self.assertIn(f"! Info: chunk{index}", text)
                recovered.extend(
                    line for line in text.splitlines() if line and not line.startswith("!")
                )

                gzip_path = chunk_path.with_suffix(chunk_path.suffix + ".gz")
                self.assertTrue(gzip_path.is_file())
                with gzip.open(gzip_path, "rt", encoding="utf-8") as compressed:
                    self.assertEqual(compressed.read(), text)

            self.assertEqual(recovered, domains)


# Check the final set of files written to the repository.
class OutputWriterTests(unittest.TestCase):
    def test_only_chunks_are_plaintext_and_full_gzip_has_one_header(self):
        generated_at = dt.datetime(2026, 7, 18, tzinfo=dt.timezone.utc)
        domains = {"ads.example.com", "tracker.example.com"}
        occurrences = Counter(
            {
                "ads.example.com": 3,
                "tracker.example.com": 1,
            }
        )
        stats = MergeStats(source_count=2, successful_sources=2)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            for obsolete_name in (
                "combined_blocklist.txt",
                "duplicate_blocklist.txt",
                "duplicate_addresses.txt",
                "duplicate_addresses.txt.gz",
            ):
                (output_dir / obsolete_name).write_text("obsolete\n", encoding="utf-8")

            manifest = write_outputs(
                output_dir,
                domains,
                occurrences,
                stats,
                chunk_size_bytes=2_000,
                generated_at=generated_at,
            )

            self.assertFalse((output_dir / "combined_blocklist.txt").exists())
            self.assertFalse((output_dir / "duplicate_blocklist.txt").exists())
            self.assertFalse((output_dir / "duplicate_addresses.txt").exists())
            self.assertFalse((output_dir / "duplicate_addresses.txt.gz").exists())

            combined_gzip = output_dir / "combined_blocklist.txt.gz"
            self.assertTrue(combined_gzip.is_file())
            with gzip.open(combined_gzip, "rt", encoding="utf-8") as compressed:
                combined_text = compressed.read()
            self.assertEqual(combined_text.count("! ______ ____ __"), 1)
            self.assertIn("! Info: combined_blocklist.txt.gz", combined_text)
            self.assertNotIn("! Info: chunk", combined_text)
            self.assertIn("ads.example.com\n", combined_text)
            self.assertIn("tracker.example.com\n", combined_text)

            duplicate_gzip = output_dir / "duplicate_blocklist.txt.gz"
            self.assertTrue(duplicate_gzip.is_file())
            with gzip.open(duplicate_gzip, "rt", encoding="utf-8") as compressed:
                duplicate_text = compressed.read()
            self.assertIn("ads.example.com - 3 occurrences", duplicate_text)
            self.assertNotIn("tracker.example.com", duplicate_text)

            # The manifest must list gzip files and chunks, not root plaintext.
            generated_paths = {item["path"] for item in manifest["files"]}
            self.assertIn("combined_blocklist.txt.gz", generated_paths)
            self.assertIn("duplicate_blocklist.txt.gz", generated_paths)
            self.assertNotIn("combined_blocklist.txt", generated_paths)
            self.assertNotIn("duplicate_blocklist.txt", generated_paths)


if __name__ == "__main__":
    unittest.main()

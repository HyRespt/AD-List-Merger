#!/usr/bin/env python3
"""Download, normalize, merge, split, and compress DNS blocklists."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import ipaddress
import io
import json
import logging
import os
import re
import shutil
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOGGER = logging.getLogger("ad-list-merger")

# Basic application and download settings.
APP_NAME = "AD-List-Merger"
APP_VERSION = "2.1"
REPOSITORY_URL = "https://github.com/HyRespt/AD-List-Merger/"
DEFAULT_CHUNK_SIZE_MB = 40.0
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 90.0
DEFAULT_RETRIES = 3

# Regex and markers for supported blocklist formats.
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HOSTS_LINE_RE = re.compile(r"^(?P<address>\S+)\s+(?P<hosts>.+)$")
DNSMASQ_RE = re.compile(r"^(?:address|server)=/(?P<domains>[^/]+)/")
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
COMMENT_PREFIXES = ("!", "#", "[")


@dataclass
class MergeStats:
    """Store counters used in logs and manifest.json."""

    source_count: int = 0
    successful_sources: int = 0
    failed_sources: int = 0
    lines_processed: int = 0
    valid_domains_added: int = 0
    duplicate_occurrences: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    source_results: list[dict[str, object]] = field(default_factory=list)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    # Read optional command-line and environment settings.
    parser = argparse.ArgumentParser(
        description="Merge ad-blocking sources into full and 40 MB chunked lists."
    )
    parser.add_argument("--sources", default="lists.txt", help="Source URL file")
    parser.add_argument("--output-dir", default=".", help="Generated file directory")
    parser.add_argument(
        "--chunk-size-mb",
        dest="chunk_size_mb",
        type=float,
        default=float(os.getenv("CHUNK_SIZE_MB", DEFAULT_CHUNK_SIZE_MB)),
        help="Maximum uncompressed chunk size in decimal MB (default: 40)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help="HTTP connection timeout in seconds",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=DEFAULT_READ_TIMEOUT,
        help="HTTP read timeout in seconds",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Retry count for transient HTTP errors",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    return parser.parse_args(argv)


def read_source_urls(path: Path) -> list[str]:
    """Read unique HTTP(S) source URLs while preserving their order."""
    seen: set[str] = set()
    urls: list[str] = []

    # Ignore blank lines, comments, invalid URLs, and repeated sources.
    with path.open("r", encoding="utf-8-sig") as source_file:
        for line_number, raw_line in enumerate(source_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = urlsplit(line)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                LOGGER.warning("Ignoring invalid source URL at %s:%d: %s", path, line_number, line)
                continue
            if line in seen:
                LOGGER.debug("Ignoring duplicate source URL: %s", line)
                continue
            seen.add(line)
            urls.append(line)

    return urls


def build_session(retries: int) -> requests.Session:
    # Retry temporary connection, rate-limit, and server errors.
    retry_policy = Retry(
        total=max(0, retries),
        connect=max(0, retries),
        read=max(0, retries),
        status=max(0, retries),
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_policy, pool_connections=10, pool_maxsize=10)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": f"{APP_NAME}/{APP_VERSION} (+{REPOSITORY_URL})",
            "Accept": "text/plain, text/*;q=0.9, */*;q=0.1",
        }
    )
    return session


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def normalize_domain(candidate: str) -> str | None:
    """Return a normalized ASCII domain, or None if the candidate is invalid."""
    value = candidate.strip().strip("\ufeff").lower()
    if not value:
        return None

    value = value.strip("|")
    value = value.lstrip("*.").rstrip(".")

    # Extract a hostname from complete URLs, protocol-relative URLs, or host:port text.
    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.hostname or ""
    else:
        value = re.split(r"[/?#^$|]", value, maxsplit=1)[0]
        if "@" in value:
            value = value.rsplit("@", 1)[1]
        if value.startswith("[") and "]" in value:
            value = value[1 : value.index("]")]
        elif value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                value = host

    value = value.lstrip("*.").rstrip(".")
    if not value or _is_ip_address(value):
        return None

    # Convert international domain names to DNS-safe ASCII.
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return None

    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 or not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return None

    # A numeric-only final label is not a valid public DNS suffix and is commonly an IP typo.
    if labels[-1].isdigit():
        return None

    return ascii_domain


def extract_candidates(raw_line: str | bytes) -> tuple[list[str], str | None]:
    """Extract possible domains from a supported blocklist line.

    The second return value is a skip reason when the whole line should be ignored.
    """
    if isinstance(raw_line, bytes):
        line = raw_line.decode("utf-8", errors="replace")
    else:
        line = raw_line

    line = line.strip().strip("\ufeff")
    if not line:
        return [], "empty_line"
    if line.startswith("@@"):
        return [], "exception_rule"
    if line.startswith(COMMENT_PREFIXES):
        return [], "comment_or_header"
    if any(marker in line for marker in COSMETIC_MARKERS):
        return [], "cosmetic_rule"
    if len(line) >= 2 and line.startswith("/") and line.endswith("/"):
        return [], "regex_rule"

    dnsmasq_match = DNSMASQ_RE.match(line)
    if dnsmasq_match:
        return [item for item in dnsmasq_match.group("domains").split("/") if item], None

    # Hosts files may contain multiple hostnames and an inline comment.
    host_line = line.split("#", 1)[0].strip()
    hosts_match = HOSTS_LINE_RE.match(host_line)
    if hosts_match and _is_ip_address(hosts_match.group("address")):
        hosts = hosts_match.group("hosts").split()
        candidates = [host for host in hosts if host not in {"localhost", "localhost.localdomain"}]
        return candidates, None if candidates else "hosts_line_without_domain"

    # Remove Adblock modifiers. The target before '$' remains the network rule.
    network_rule = line.split("$", 1)[0].strip()
    if not network_rule:
        return [], "empty_network_rule"

    if network_rule.startswith("||"):
        return [network_rule[2:]], None
    if network_rule.startswith("|"):
        return [network_rule[1:].rstrip("|")], None

    # Inline comments are accepted for plain domain lists when preceded by whitespace.
    network_rule = re.split(r"\s+#", network_rule, maxsplit=1)[0].strip()
    if not network_rule:
        return [], "empty_network_rule"

    # Unknown prose normally contains whitespace; do not turn arbitrary words into domains.
    if any(char.isspace() for char in network_rule):
        return [], "unsupported_line"

    return [network_rule], None


def collect_domains(
    urls: Sequence[str],
    session: requests.Session,
    timeout: tuple[float, float],
) -> tuple[set[str], Counter[str], MergeStats]:
    """Download sources and collect unique domains plus occurrence counts."""

    domains: set[str] = set()
    occurrences: Counter[str] = Counter()
    stats = MergeStats(source_count=len(urls))

    for index, url in enumerate(urls, start=1):
        LOGGER.info("[%d/%d] Fetching %s", index, len(urls), url)
        before_count = len(domains)
        source_lines = 0
        try:
            # Stream large source lists instead of loading them into RAM.
            with session.get(url, timeout=timeout, stream=True) as response:
                response.raise_for_status()
                for raw_line in response.iter_lines(decode_unicode=False):
                    source_lines += 1
                    stats.lines_processed += 1
                    candidates, skip_reason = extract_candidates(raw_line)
                    if skip_reason:
                        stats.skip_reasons[skip_reason] += 1
                        continue

                    valid_on_line = False
                    for candidate in candidates:
                        domain = normalize_domain(candidate)
                        if domain is None:
                            stats.skip_reasons["invalid_domain"] += 1
                            continue
                        valid_on_line = True
                        occurrences[domain] += 1
                        if domain in domains:
                            stats.duplicate_occurrences += 1
                        else:
                            domains.add(domain)
                            stats.valid_domains_added += 1
                    if not valid_on_line and candidates:
                        stats.skip_reasons["line_without_valid_domain"] += 1
        except requests.RequestException as exc:
            stats.failed_sources += 1
            stats.skip_reasons["source_request_error"] += 1
            stats.source_results.append(
                {"url": url, "status": "failed", "error": str(exc), "lines": source_lines}
            )
            LOGGER.warning("Failed to fetch %s: %s", url, exc)
            continue

        stats.successful_sources += 1
        stats.source_results.append(
            {
                "url": url,
                "status": "ok",
                "lines": source_lines,
                "new_domains": len(domains) - before_count,
            }
        )

    return domains, occurrences, stats


def build_header(
    generated_at: dt.datetime,
    *,
    info: str,
) -> bytes:
    """Build the compact original-style ASCII and information header."""
    lines = [
         "! ______      ____       __",
         "!/\\  _  \\    /\\  _`\\    /\\ \\        /'\\_/`\\",
         "!\\ \\ \\L\\ \\   \\ \\ \\/\\ \\  \\ \\ \\      /\\      \\",
         "! \\ \\  __ \\   \\ \\ \\ \\ \\  \\ \\ \\  __ \\ \\ \\__\\ \\",
         "!  \\ \\ \\/\\ \\   \\ \\ \\_\\ \\  \\ \\ \\L\\ \\ \\ \\ \\_/\\ \\",
         "!   \\ \\_\\ \\_\\   \\ \\____/   \\ \\____/  \\ \\_\\\\ \\_\\",
         "!    \\/_/\\/_/    \\/___/     \\/___/    \\/_/ \\/_/",
        "!",
        "! AD-List-Merger",
        f"! Version: {APP_VERSION}",
        f"! Github page: {REPOSITORY_URL}",
        f"! Last modified: {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"! Info: {info}",
        "!",
        "",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def atomic_write_lines(path: Path, header: bytes, lines: Iterable[str]) -> None:
    """Write plaintext safely by replacing the file only when complete."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as output:
        output.write(header)
        for line in lines:
            output.write(line.encode("utf-8"))
            output.write(b"\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def gzip_file(source: Path, destination: Path) -> None:
    """Create a reproducible gzip copy (fixed gzip metadata timestamp)."""
    temporary = destination.with_name(destination.name + ".tmp")
    with source.open("rb") as source_file, temporary.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0) as gz_output:
            shutil.copyfileobj(source_file, gz_output, length=1024 * 1024)
        raw_output.flush()
        os.fsync(raw_output.fileno())
    temporary.replace(destination)


def atomic_write_gzip_lines(path: Path, header: bytes, lines: Iterable[str]) -> None:
    """Write a reproducible gzip text file without creating a plaintext copy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            compresslevel=9,
            mtime=0,
        ) as gz_output:
            gz_output.write(header)
            for line in lines:
                gz_output.write(line.encode("utf-8"))
                gz_output.write(b"\n")
        raw_output.flush()
        os.fsync(raw_output.fileno())
    temporary.replace(path)


def clean_old_chunks(chunk_dir: Path) -> None:
    """Delete stale chunk files before writing the new set."""

    chunk_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("combined_blocklist_part_*.txt", "combined_blocklist_part_*.txt.gz"):
        for path in chunk_dir.glob(pattern):
            path.unlink()


def write_chunks(
    sorted_domains: Sequence[str],
    chunk_dir: Path,
    max_bytes: int,
    generated_at: dt.datetime,
) -> list[Path]:
    """Split domains on full lines and gzip every generated chunk."""

    if max_bytes <= 0:
        raise ValueError("Chunk size must be greater than zero")

    clean_old_chunks(chunk_dir)
    chunk_paths: list[Path] = []
    part_number = 0
    output = None
    output_path: Path | None = None
    current_size = 0
    domains_in_current_chunk = 0

    def open_chunk(number: int, first_line_size: int = 0) -> tuple[Path, object, int]:
        # Every chunk gets its own number in the restored info header.
        path = chunk_dir / f"combined_blocklist_part_{number:03d}.txt"
        header = build_header(generated_at, info=f"chunk{number}")
        if len(header) + first_line_size > max_bytes:
            raise ValueError("Chunk size is too small to hold the header and one domain")
        stream = path.open("wb")
        stream.write(header)
        return path, stream, len(header)

    try:
        for domain in sorted_domains:
            encoded_line = (domain + "\n").encode("utf-8")
            if output is None:
                part_number += 1
                output_path, output, current_size = open_chunk(part_number, len(encoded_line))
                domains_in_current_chunk = 0

            # Start a new file before the current chunk exceeds its limit.
            if domains_in_current_chunk and current_size + len(encoded_line) > max_bytes:
                output.close()
                output = None
                if output_path is None:
                    raise RuntimeError("Missing chunk output path")
                chunk_paths.append(output_path)
                part_number += 1
                output_path, output, current_size = open_chunk(part_number, len(encoded_line))
                domains_in_current_chunk = 0

            output.write(encoded_line)
            current_size += len(encoded_line)
            domains_in_current_chunk += 1

        if output is None:
            # Keep a valid empty chunk for an explicitly empty input sequence.
            part_number = 1
            output_path = chunk_dir / "combined_blocklist_part_001.txt"
            header = build_header(generated_at, info="chunk1")
            if len(header) > max_bytes:
                raise ValueError("Chunk size is too small to hold the header")
            output = output_path.open("wb")
            output.write(header)

        output.close()
        output = None
        if output_path is None:
            raise RuntimeError("Missing final chunk output path")
        chunk_paths.append(output_path)
    finally:
        if output is not None:
            output.close()

    # Confirm the limit and make a gzip copy of every text chunk.
    for chunk_path in chunk_paths:
        if chunk_path.stat().st_size > max_bytes:
            raise RuntimeError(f"Chunk exceeded size limit: {chunk_path}")
        gzip_file(chunk_path, chunk_path.with_suffix(chunk_path.suffix + ".gz"))

    return chunk_paths


def sha256_file(path: Path) -> str:
    """Return the SHA-256 checksum without loading the full file."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def describe_file(path: Path, root: Path) -> dict[str, object]:
    """Create a small manifest entry for one generated file."""

    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_duplicate_report_gzip(path: Path, occurrences: Counter[str]) -> int:
    """Write only repeated domains to one unsplit gzip report."""

    # Keep domains that appeared more than once across all sources.
    duplicates = [(domain, count) for domain, count in occurrences.items() if count > 1]
    duplicates.sort()
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            compresslevel=9,
            mtime=0,
        ) as gz_output:
            with io.TextIOWrapper(gz_output, encoding="utf-8", newline="\n") as output:
                output.write("Duplicate addresses found in the input:\n\n")
                for domain, count in duplicates:
                    output.write(f"{domain} - {count} occurrences\n")
        raw_output.flush()
        os.fsync(raw_output.fileno())
    temporary.replace(path)
    return len(duplicates)


def write_outputs(
    output_dir: Path,
    domains: set[str],
    occurrences: Counter[str],
    stats: MergeStats,
    chunk_size_bytes: int,
    generated_at: dt.datetime,
) -> dict[str, object]:
    """Create permitted outputs and return their manifest information."""

    output_dir.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    header = build_header(generated_at, info="combined_blocklist.txt.gz")

    # Write the complete list directly to gzip; no root plaintext copy is kept.
    full_gzip_path = output_dir / "combined_blocklist.txt.gz"
    atomic_write_gzip_lines(full_gzip_path, header, sorted_domains)

    duplicate_gzip_path = output_dir / "duplicate_blocklist.txt.gz"
    duplicate_domain_count = write_duplicate_report_gzip(duplicate_gzip_path, occurrences)

    # Plaintext is published only as size-limited chunks.
    chunk_dir = output_dir / "chunks"
    chunk_paths = write_chunks(
        sorted_domains,
        chunk_dir,
        chunk_size_bytes,
        generated_at,
    )
    chunk_gzip_paths = [path.with_suffix(path.suffix + ".gz") for path in chunk_paths]

    all_output_paths = [
        full_gzip_path,
        duplicate_gzip_path,
        *chunk_paths,
        *chunk_gzip_paths,
    ]

    # Remove obsolete plaintext and old duplicate filenames after all new files exist.
    for obsolete_name in (
        "combined_blocklist.txt",
        "duplicate_blocklist.txt",
        "duplicate_addresses.txt",
        "duplicate_addresses.txt.gz",
    ):
        obsolete_path = output_dir / obsolete_name
        if obsolete_path.exists():
            obsolete_path.unlink()

    # Record source results, processing totals, sizes, and checksums.
    manifest = {
        "application": APP_NAME,
        "version": APP_VERSION,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "chunk_size_bytes": chunk_size_bytes,
        "domain_count": len(sorted_domains),
        "duplicate_domain_count": duplicate_domain_count,
        "sources": {
            "configured": stats.source_count,
            "successful": stats.successful_sources,
            "failed": stats.failed_sources,
            "results": stats.source_results,
        },
        "processing": {
            "lines_processed": stats.lines_processed,
            "valid_domains_added": stats.valid_domains_added,
            "duplicate_occurrences": stats.duplicate_occurrences,
            "skip_reasons": dict(sorted(stats.skip_reasons.items())),
        },
        "files": [describe_file(path, output_dir) for path in all_output_paths],
    }

    manifest_path = output_dir / "manifest.json"
    temporary = manifest_path.with_name(manifest_path.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(manifest_path)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    """Run the merger and return a shell-friendly exit code."""

    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )

    source_path = Path(args.sources)
    output_dir = Path(args.output_dir)
    # Use decimal megabytes so 40 MB is exactly 40,000,000 bytes.
    chunk_size_bytes = int(args.chunk_size_mb * 1_000_000)

    if args.chunk_size_mb <= 0:
        LOGGER.error("--chunk-size-mb must be greater than zero")
        return 2
    if not source_path.is_file():
        LOGGER.error("Source list file not found: %s", source_path)
        return 2

    urls = read_source_urls(source_path)
    if not urls:
        LOGGER.error("No valid source URLs found in %s", source_path)
        return 2

    session = build_session(args.retries)
    try:
        domains, occurrences, stats = collect_domains(
            urls,
            session,
            timeout=(args.connect_timeout, args.read_timeout),
        )
    finally:
        session.close()

    # Do not replace a previously working list after a total download failure.
    if stats.successful_sources == 0:
        LOGGER.error("All source downloads failed; existing outputs were left untouched")
        return 1
    if not domains:
        LOGGER.error("No valid domains were collected; existing outputs were left untouched")
        return 1

    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    manifest = write_outputs(
        output_dir,
        domains,
        occurrences,
        stats,
        chunk_size_bytes,
        generated_at,
    )

    LOGGER.info("Generated %d unique domains", manifest["domain_count"])
    LOGGER.info(
        "Sources: %d successful, %d failed",
        stats.successful_sources,
        stats.failed_sources,
    )
    LOGGER.info("Chunks: %d", sum(1 for item in manifest["files"] if str(item["path"]).endswith(".txt") and str(item["path"]).startswith("chunks/")))
    LOGGER.info("Full gzip list: %s", output_dir / "combined_blocklist.txt.gz")
    return 0


if __name__ == "__main__":
    sys.exit(main())

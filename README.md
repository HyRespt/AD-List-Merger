# AD-List-Merger

AD-List-Merger downloads the URLs in `lists.txt`, extracts valid DNS names, removes duplicates, and publishes AdGuard Home-compatible plain-domain blocklists.

## Generated files

Each workflow run creates and commits:

- `combined_blocklist.txt.gz` — the complete list in one gzip file, with one ASCII-art header and the short line `! Info: combined_blocklist.txt.gz`
- `chunks/combined_blocklist_part_001.txt`, `...002.txt`, etc. — the complete list split on line boundaries, with each uncompressed file no larger than 40 MB (40,000,000 bytes). Every chunk has the restored ASCII-art header and a short line such as `! Info: chunk1`
- A matching `.txt.gz` file for every chunk
- `duplicate_blocklist.txt.gz` — one unsplit gzip report containing domains seen more than once and their occurrence counts
- `manifest.json` — domain totals, source status, file sizes, and SHA-256 hashes

The root `combined_blocklist.txt` and plaintext duplicate report are temporary concepts only and are not generated, uploaded, or committed. Only the chunked plaintext files are published.

The workflow also uploads the same generated files as a seven-day GitHub Actions artifact.

## Use with AdGuard Home

Add every plain `.txt` chunk URL as a separate DNS blocklist. For this repository, the URLs follow this pattern:

```text
https://raw.githubusercontent.com/HyRespt/AD-List-Merger/main/chunks/combined_blocklist_part_001.txt
https://raw.githubusercontent.com/HyRespt/AD-List-Merger/main/chunks/combined_blocklist_part_002.txt
```

Check `manifest.json` or the `chunks` directory after each run to see how many parts exist. Chunk files are regenerated safely, and stale higher-numbered parts are deleted when the merged list becomes smaller.

## Tests folder

Keep the `tests` folder in the repository. GitHub Actions runs it before rebuilding the lists, so a broken parser, oversized chunk, missing gzip file, or incorrect information header is caught before generated files are committed.

## Run locally

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python update_blocklist.py
```

The default chunk limit is 40 MB (40,000,000 bytes). Override it with either method:

```bash
python update_blocklist.py --chunk-size-mb 25
CHUNK_SIZE_MB=25 python update_blocklist.py
```

Useful options:

```text
--sources lists.txt
--output-dir .
--connect-timeout 10
--read-timeout 90
--retries 3
--log-level INFO
```

## Source list format

Put one HTTP or HTTPS URL per line in `lists.txt`. Blank lines and lines beginning with `#` are ignored. Duplicate source URLs are fetched only once.

Supported input styles include plain domains, hosts-file rows, Adblock/AdGuard `||domain^` network rules, full URLs, and common dnsmasq `address=/domain/...` rows. Exception, cosmetic, comment, and regular-expression rules are skipped rather than converted into unsafe DNS blocks.

## Automation

The workflow runs daily at 00:00 UTC and can also be started manually from the Actions tab. It runs the test suite, generates and verifies all outputs, uploads a workflow artifact, and commits changed generated files back to the repository.

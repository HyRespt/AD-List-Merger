import re
import requests
from collections import Counter
import datetime

# Read the list URLs from lists.txt (skip blank lines and lines starting with '#')
try:
    with open("lists.txt", "r") as f:
        SOURCE_URLS = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
except Exception as e:
    print("Error reading lists.txt:", e)
    SOURCE_URLS = []

# Output file paths
OUTPUT_FILE = "combined_blocklist.txt"
DUPLICATE_FILE = "duplicate_addresses.txt"

# Set to hold unique domains
domains = set()

# Counter to record how many times each domain is encountered
domain_occurrences = Counter()

# Regex allowing underscores and hyphens in domain labels.
# If you want to allow other special characters, add them to the character sets.
domain_regex = re.compile(
    r'^(?:[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?\.)+[a-z0-9_]{2,}$',
    re.IGNORECASE
)

# Counters for reporting purposes
lines_processed = 0
skip_reasons = Counter()

valid_domains_added = 0  # How many new domains passed validation and were added
duplicates_during_processing = 0  # How many times we encountered domains that were already in the set

def clean_domain(domain):
    """Remove leading/trailing whitespace/wildcards and convert to lowercase."""
    domain = domain.strip().lower()
    domain = domain.lstrip('*').lstrip('.')
    domain = domain.rstrip('*').rstrip('.')
    return domain

def is_valid_domain(domain):
    """Check if the domain is valid (per our extended regex), allowing underscores."""
    if '*' in domain:
        return False
    if '.' in domain:
        return bool(domain_regex.match(domain))
    # For single-label 'domains', allow them if >=2 chars made up of alnum + underscore
    return len(domain) > 1 and all(ch.isalnum() or ch == '_' for ch in domain)

def add_domain(candidate):
    """Validate and add the candidate domain to the set if valid. Also count occurrences."""
    global valid_domains_added, duplicates_during_processing
    candidate = clean_domain(candidate)
    if is_valid_domain(candidate):
        # Increase the occurrence count regardless of whether it's a duplicate
        domain_occurrences[candidate] += 1
        if candidate in domains:
            duplicates_during_processing += 1
        else:
            valid_domains_added += 1
            domains.add(candidate)
    else:
        skip_reasons["invalid_domain"] += 1

def process_line(line):
    """Process a single line from any list: skip or add domain."""
    global lines_processed
    line = line.strip()
    lines_processed += 1
    if not line:
        skip_reasons["empty_line"] += 1
        return
    # Skip comments or exception rules (those starting with "!", "#" or "@@")
    if line.startswith(('!', '#', '@@')):
        skip_reasons["comment_or_exception"] += 1
        return
    # Process hosts file style lines (e.g., "0.0.0.0 example.com")
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', line):
        parts = line.split()
        if len(parts) > 1:
            for candidate in parts[1:]:
                add_domain(candidate)
        else:
            skip_reasons["hosts_format_but_no_domain"] += 1
        return
    # Lines that include a $domain= directive (Adblock syntax)
    if "$domain=" in line:
        match = re.search(r"domain=([^,$]+)", line)
        if match:
            domain_str = match.group(1)
            for candidate in domain_str.split('|'):
                add_domain(candidate)
        else:
            skip_reasons["malformed_domain_directive"] += 1
        return
    # Adblock Plus syntax "||" (e.g., "||example.com^")
    if line.startswith("||"):
        rule = line[2:]
        parts = re.split(r'[\/\^\|\$]', rule, maxsplit=1)
        if parts:
            add_domain(parts[0])
        else:
            skip_reasons["adblock_plus_rule_invalid"] += 1
        return
    # Rules starting with a single "|" ("|http://..." or "|example.com")
    if line.startswith("|"):
        rule = line.lstrip("|")
        if rule.startswith("http://") or rule.startswith("https://"):
            rule = rule.split("://", 1)[1]
        candidate = re.split(r'[\/\^\$]', rule, maxsplit=1)[0]
        add_domain(candidate)
        return
    # Otherwise, assume it's a plain domain line
    add_domain(line)

headers = {
    "User-Agent": "AD-List-Merger/1.1 (compatible; +https://github.com/HyRespt/AD-List-Merger/)"
}

# Fetch and process each source URL
for url in SOURCE_URLS:
    try:
        resp = requests.get(url, timeout=30, headers=headers)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print(f"Warning: Timeout when fetching {url}")
        skip_reasons["request_timeout"] += 1
        continue
    except requests.exceptions.HTTPError as e:
        print(f"Warning: HTTP error when fetching {url} – {e}")
        skip_reasons["request_http_error"] += 1
        continue
    except requests.exceptions.ConnectionError as e:
        print(f"Warning: Connection error when fetching {url} – {e}")
        skip_reasons["request_connection_error"] += 1
        continue
    except Exception as e:
        print(f"Warning: Could not fetch {url} – {e}")
        skip_reasons["request_unknown_error"] += 1
        continue

    # Split lines and process
    for line in resp.text.splitlines():
        process_line(line)

# Create header for output files
header_lines = [
     "! ______      ____       __",
     "!/\\  _  \\    /\\  _`\\    /\\ \\        /'\\_/`\\",
     "!\\ \\ \\L\\ \\   \\ \\ \\/\\ \\  \\ \\ \\      /\\      \\",
     "! \\ \\  __ \\   \\ \\ \\ \\ \\  \\ \\ \\  __ \\ \\ \\__\\ \\",
     "!  \\ \\ \\/\\ \\   \\ \\ \\_\\ \\  \\ \\ \\L\\ \\ \\ \\ \\_/\\ \\",
     "!   \\ \\_\\ \\_\\   \\ \\____/   \\ \\____/  \\ \\_\\\\ \\_\\",
     "!    \\/_/\\/_/    \\/___/     \\/___/    \\/_/ \\/_/",
    "!",
    "! AD-List-Merger",
    "! Version: 1.1",
    "! Github page: https://github.com/HyRespt/AD-List-Merger/",
    f"! Last modified: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
    "!"
]
header = "\n".join(header_lines) + "\n\n"

# Write header + sorted unique domains to the combined output file
with open(OUTPUT_FILE, "w") as outfile:
    outfile.write(header)
    for domain in sorted(domains):
        outfile.write(domain + "\n")

print(f"\nCombined blocklist saved to {OUTPUT_FILE}")
print(f" Total unique domains: {len(domains)}")
print(f" Total lines processed: {lines_processed}")
print(f" Valid domains added: {valid_domains_added}")
print(f" Total duplicates encountered while processing: {duplicates_during_processing}")

# Create a separate file listing duplicate addresses (domains that appeared >1 time)
duplicate_domains = {domain: count for domain, count in domain_occurrences.items() if count > 1}
if duplicate_domains:
    with open(DUPLICATE_FILE, "w") as dup_file:
        dup_file.write("Duplicate addresses found in the input:\n\n")
        for domain, count in sorted(duplicate_domains.items()):
            dup_file.write(f"{domain} - {count} occurrences\n")
    print(f"\nDuplicate addresses list saved to {DUPLICATE_FILE}")
else:
    print("\nNo duplicate addresses found in the input.")

# Final duplicate check by reading the combined output file (skipping header lines)
with open(OUTPUT_FILE, "r") as infile:
    # Exclude header lines that start with "!"
    lines = [line.strip() for line in infile if line.strip() and not line.strip().startswith('!')]
counter = Counter(lines)
duplicates_in_file = [line for line, count in counter.items() if count > 1]

if duplicates_in_file:
    total_duplicated_occurrences = sum((count - 1) for _, count in counter.items() if count > 1)
    print(f"\nDuplicates found in the output file! ({total_duplicated_occurrences} total duplicates among {len(duplicates_in_file)} distinct lines)")
    for dup in duplicates_in_file:
        print(f" - {dup} (occurs {counter[dup]} times)")
else:
    print("\nNo duplicates found in the final output file!")

print("\nSkipped lines details:")
for reason, count in skip_reasons.items():
    print(f" {reason}: {count}")

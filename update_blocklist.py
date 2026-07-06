import re
import requests
from collections import Counter
import datetime
import gzip

# Read the list URLs from lists.txt
try:
    with open("lists.txt", "r") as f:
        SOURCE_URLS = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
except Exception as e:
    print("Error reading lists.txt:", e)
    SOURCE_URLS = []

OUTPUT_FILE = "combined_blocklist.txt.gz"
DUPLICATE_FILE = "duplicate_addresses.txt"

domains = set()
domain_occurrences = Counter()

# Regex
domain_regex = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
    re.IGNORECASE
)

lines_processed = 0
skip_reasons = Counter()
valid_domains_added = 0
duplicates_during_processing = 0

def clean_domain(domain):
    """Remove whitespace, wildcards, paths, and ports."""
    domain = domain.strip().lower()
    domain = domain.lstrip('*.').rstrip('*.')
    
    if '/' in domain:
        domain = domain.split('/', 1)[0]
    if ':' in domain:
        domain = domain.split(':', 1)[0]
        
    return domain

def is_valid_domain(domain):
    """Check if the domain is a strictly valid FQDN for AdGuard Home."""
    if not domain or '*' in domain:
        return False
        
    # IP Block
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return False
        
    # fix localhost
    if '.' in domain:
        return bool(domain_regex.match(domain))
        
    return False

def add_domain(candidate):
    """Validate, count, and add the domain."""
    global valid_domains_added, duplicates_during_processing
    candidate = clean_domain(candidate)
    
    if is_valid_domain(candidate):
        domain_occurrences[candidate] += 1
        if candidate in domains:
            duplicates_during_processing += 1
        else:
            valid_domains_added += 1
            domains.add(candidate)
    else:
        skip_reasons["invalid_domain"] += 1

def process_line(line):
    """Process a single line from any list."""
    global lines_processed
    line = line.strip()
    lines_processed += 1
    
    if not line:
        skip_reasons["empty_line"] += 1
        return
        
    # Skip comment lines etc.
    if line.startswith(('!', '#', '@@')):
        skip_reasons["comment_or_exception"] += 1
        return

    # Delete HTML rules
    if '##' in line or '#?#' in line:
        skip_reasons["cosmetic_rule"] += 1
        return
        
    # Process hosts file style lines
    if line.startswith(('0.0.0.0', '127.0.0.1', '::1')):
        line = line.split('#')[0].strip()
        parts = line.split()
        if len(parts) > 1:
            for candidate in parts[1:]:
                add_domain(candidate)
        else:
            skip_reasons["hosts_format_but_no_domain"] += 1
        return

    # Adblock syntax modifier cleaner
    raw_rule = line
    if '$' in raw_rule:
        raw_rule = raw_rule.split('$', 1)[0]
    if '^' in raw_rule:
        raw_rule = raw_rule.split('^', 1)[0]

    # Adblock Plus syntax "||"
    if raw_rule.startswith("||"):
        candidate = raw_rule[2:]
        add_domain(candidate)
        return
        
    # Rules starting with a single "|"
    if raw_rule.startswith("|"):
        candidate = raw_rule[1:]
        if candidate.startswith("http://"):
            candidate = candidate[7:]
        elif candidate.startswith("https://"):
            candidate = candidate[8:]
        add_domain(candidate)
        return
        
    # Plain domain
    add_domain(raw_rule)

headers = {
    "User-Agent": "AD-List-Merger/1.3 (compatible; +https://github.com/HyRespt/AD-List-Merger/)"
}

# Fetch and process each source URL
for url in SOURCE_URLS:
    try:
        # RAM optimization
        resp = requests.get(url, timeout=30, headers=headers, stream=True)
        resp.raise_for_status()
        
        for line in resp.iter_lines(decode_unicode=True):
            if line is not None:
                process_line(line)
                
    except requests.exceptions.Timeout:
        print(f"Warning: Timeout when fetching {url}")
        skip_reasons["request_timeout"] += 1
        continue
    except requests.exceptions.RequestException as e:
        print(f"Warning: Error when fetching {url} – {e}")
        skip_reasons["request_error"] += 1
        continue

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
    "! Version: 1.3",
    "! Github page: https://github.com/HyRespt/AD-List-Merger/",
    f"! Last modified: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
    "!"
]
header = "\n".join(header_lines) + "\n\n"

# GZIP
with gzip.open(OUTPUT_FILE, "wt", encoding="utf-8") as outfile:
    outfile.write(header)
    for domain in sorted(domains):
        outfile.write(domain + "\n")

print(f"\nCombined blocklist compressed and saved to {OUTPUT_FILE}")
print(f" Total unique domains: {len(domains)}")
print(f" Total lines processed: {lines_processed}")
print(f" Valid domains added: {valid_domains_added}")
print(f" Total duplicates encountered while processing: {duplicates_during_processing}")

# Create duplicate addresses
duplicate_domains = {domain: count for domain, count in domain_occurrences.items() if count > 1}
if duplicate_domains:
    with open(DUPLICATE_FILE, "w") as dup_file:
        dup_file.write("Duplicate addresses found in the input:\n\n")
        for domain, count in sorted(duplicate_domains.items()):
            dup_file.write(f"{domain} - {count} occurrences\n")
    print(f"\nDuplicate addresses list saved to {DUPLICATE_FILE}")
else:
    print("\nNo duplicate addresses found in the input.")

print("\nSkipped lines details:")
for reason, count in skip_reasons.items():
    print(f" {reason}: {count}")

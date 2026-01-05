import argparse
import re
import sys
from typing import List

import requests


def banner() -> None:
    print(
        r"""
       __        _____                     __     _______           __         
      / /____   / ___/___  _____________  / /_   / ____(_)___  ____/ /__  _____
 __  / / ___/   \__ \/ _ \/ ___/ ___/ _ \/ __/  / /_  / / __ \/ __  / _ \/ ___/
/ /_/ (__  )   ___/ /  __/ /__/ /  /  __/ /_   / __/ / / / / / /_/ /  __/ /    
\____/____/   /____/\___/\___/_/   \___/\__/  /_/   /_/_/ /_/\__,_/\___/_/    
"""
    )


def _find_secrets(js: str) -> List[str]:
    # Hardcoded values used in comparisons (client-side auth logic)
    auth_pattern = re.compile(
        r"(?:==|===)\s*[\"']([^\"']+)[\"']"
    )

    # Suspicious strings (contain digits, length >= 6)
    string_pattern = re.compile(
        r"[\"']([A-Za-z0-9_\-]*\d[A-Za-z0-9_\-]{5,})[\"']"
    )

    results: List[str] = []
    results.extend(auth_pattern.findall(js))
    results.extend(string_pattern.findall(js))

    # Deduplicate results
    seen = set()
    unique: List[str] = []
    for r in results:
        if r not in seen:
            seen.add(r)
            unique.append(r)

    return unique


def scan_js(url: str, output_file: str) -> None:
    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    if response.status_code != 200:
        print(f"[!] Failed to fetch {url} (Status: {response.status_code})")
        return

    js_content = response.text
    matches = _find_secrets(js_content)

    with open(output_file, "w", encoding="utf-8") as f:
        if matches:
            header = f"[+] Potential secrets found in {url}:"
            print(header)
            print(header, file=f)

            for value in matches:
                line = f" - {value}"
                print(line)
                print(line, file=f)
        else:
            msg = f"[-] No secrets found in {url}"
            print(msg)
            print(msg, file=f)


def main(argv: List[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    banner()

    parser = argparse.ArgumentParser(
        description="JS Secret Finder – scans JavaScript files for exposed client-side secrets"
    )
    parser.add_argument("url", help="URL of the JavaScript file to scan")
    parser.add_argument(
        "-o",
        "--output",
        default="output.txt",
        help="Output file (default: output.txt)",
    )

    args = parser.parse_args(argv)
    scan_js(args.url, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

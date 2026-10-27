#!/usr/bin/env python3
sub-takeover v3 — Professional Bulk Subdomain Takeover Engine.
Creator kArmasec

import sys
import os
import json
import csv
import argparse
import asyncio
import aiohttp
import dns.asyncresolver
import dns.exception
import random
import string

C_GRN = "\033[38;2;0;255;136m"
C_RED = "\033[38;2;255;34;68m"
C_ORG = "\033[38;2;255;140;0m"
C_CYN = "\033[38;2;0;255;255m"
C_PUR = "\033[38;2;255;0;255m"
C_RST = "\033[0m"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

FINGERPRINTS = {
    "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "github.io": ["There isn't a GitHub Pages site here."],
    "herokuapp.com": ["No such app", "heroku | no such app"],
    "myshopify.com": ["Sorry, this shop is currently unavailable."],
    "fastly.net": ["Fastly error: unknown domain"],
    "tumblr.com": ["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address."],
    "readme.io": ["The requested URL was not found on this server."],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["The page you have requested does not exist."],
    "cloudfront.net": ["Bad request", "ERROR: The request could not be satisfied"],
    "zendesk.com": ["Help Center Closed"],
    "wordpress.com": ["Do you want to register"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "pantheonsite.io": ["The gods are wise, but do not know of the site which you seek"],
    "netlify.app": ["Not found - Request ID"],
    "cargo.site": ["404 Not Found"],
    "unbounce.com": ["The requested URL was not found on this server."],
    "teamwork.com": ["Oops - We didn't find your site."],
    "feedpress.me": ["The feed has not been found."],
    "freshdesk.com": ["May be offline"],
    "intercom.help": ["This page doesn't exist"],
    "jetbrains.space": ["Space not found"],
    "webflow.io": ["The page you are looking for doesn't exist or has been moved"],
}

def load_targets(args):
    domains = []
    if args.file:
        if not os.path.exists(args.file):
            print(f"{C_RED}[!] File not found: {args.file}{C_RST}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    domains.append(d)
        print(f"{C_GRN}[+] Loaded {len(domains)} domains from {args.file}{C_RST}")
    elif args.domain:
        domains.append(args.domain)

    if not domains:
        print(f"{C_RED}[!] No targets provided. Use -d or -f.{C_RST}")
        sys.exit(1)
    return domains

async def get_wildcard_ips(domain, resolver):
    wildcard_ips = set()
    for _ in range(2): # Reduced to 2 for speed in bulk
        rand_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        try:
            answers = await resolver.resolve(f"{rand_sub}.{domain}", 'A')
            for rdata in answers:
                wildcard_ips.add(rdata.address)
        except Exception:
            pass
    return wildcard_ips

async def get_subdomains(domain):
    subs = set()
    try:
        async with aiohttp.ClientSession() as session:
            # Timeout increased for bulk
            async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=45) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        for sub in entry.get("name_value", "").split("\n"):
                            sub = sub.strip().lower()
                            if sub and "*" not in sub and sub.endswith(domain):
                                subs.add(sub)
    except Exception:
        pass
    return list(subs)

async def resolve_subdomain(sub, resolver, wildcard_ips):
    try:
        answers = await resolver.resolve(sub, 'CNAME')
        for rdata in answers:
            return str(rdata.target).strip(".")
    except (dns.exception.DNSException, Exception):
        pass

    try:
        answers = await resolver.resolve(sub, 'A')
        for rdata in answers:
            if rdata.address in wildcard_ips:
                return "WILDCARD"
            return rdata.address
    except Exception:
        pass
    return None

async def check_takeover(session, sub, cname):
    if not cname or cname == "WILDCARD":
        return None

    for service, signatures in FINGERPRINTS.items():
        if service in cname:
            for proto in ["https", "http"]:
                try:
                    url = f"{proto}://{sub}"
                    async with session.get(url, timeout=10, allow_redirects=True) as resp:
                        text = await resp.text()
                        for sig in signatures:
                            if sig.lower() in text.lower():
                                return {"subdomain": sub, "cname": cname, "service": service, "signature": sig, "url": url}
                except Exception:
                    pass
    return None

async def worker(sub, resolver, session, results, lock, total, counter, wildcard_ips):
    counter[0] += 1
    # Print less frequently in bulk mode to avoid terminal lag
    if counter[0] % 5 == 0 or counter[0] == total:
        sys.stdout.write(f"\r{C_CYN}[*] Progress: {counter[0]}/{total}{C_RST}")
        sys.stdout.flush()

    cname = await resolve_subdomain(sub, resolver, wildcard_ips)
    if not cname or cname == "WILDCARD":
        return

    takeover = await check_takeover(session, sub, cname)
    if takeover:
        async with lock:
            print(f"\n{C_RED}[TAKEOVER!] {sub} -> {cname} ({takeover['service']}){C_RST}")
            results.append(takeover)

async def main():
    parser = argparse.ArgumentParser(description="Professional Bulk Subdomain Takeover Scanner")
    parser.add_argument("-d", "--domain", help="Single root domain (e.g., example.com)")
    parser.add_argument("-f", "--file", help="File with list of domains (one per line)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist (optional)")
    parser.add_argument("-o", "--output", default="takeover_report", help="Output filename prefix")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent threads (default: 50)")
    args = parser.parse_args()

    print(f"{C_PUR}=== Sub-Takeover v3 — Bulk Engine ==={C_RST}\n")

    domains = load_targets(args)

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.timeout = 3
    resolver.lifetime = 3
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    all_subs_with_wildcards = []

    # 1. Gather all subdomains from all targets
    for idx, domain in enumerate(domains, 1):
        print(f"\n{C_CYN}[{idx}/{len(domains)}] Processing target: {domain}{C_RST}")

        wildcard_ips = await get_wildcard_ips(domain, resolver)
        if wildcard_ips:
            print(f"{C_ORG}[!] Wildcard IPs: {', '.join(wildcard_ips)}{C_RST}")

        subs = await get_subdomains(domain)
        if args.wordlist and os.path.exists(args.wordlist):
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word:
                        subs.append(f"{word}.{domain}")

        print(f"{C_GRN}[+] Found {len(subs)} subdomains.{C_RST}")

        # Save with wildcard IPs so the worker knows what to ignore
        for sub in subs:
            all_subs_with_wildcards.append((sub, wildcard_ips))

    if not all_subs_with_wildcards:
        print(f"{C_RED}[-] No subdomains found across all targets.{C_RST}")
        sys.exit(1)

    # 2. Scan all gathered subdomains
    total = len(all_subs_with_wildcards)
    print(f"\n{C_CYN}[*] Starting takeover scan on {total} total subdomains...{C_RST}\n")

    connector = aiohttp.TCPConnector(ssl=False, limit=args.threads)
    lock = asyncio.Lock()
    results = []
    counter = [0]

    async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
        tasks = []
        for sub, wildcard_ips in all_subs_with_wildcards:
            tasks.append(worker(sub, resolver, session, results, lock, total, counter, wildcard_ips))
        await asyncio.gather(*tasks)

    print(f"\n\n{C_GRN}[+] Scan complete.{C_RST}")

    # 3. Save Results
    if results:
        json_file = f"{args.output}.json"
        csv_file = f"{args.output}.csv"

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

        with open(csv_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["subdomain", "cname", "service", "signature", "url"])
            writer.writeheader()
            writer.writerows(results)

        print(f"{C_GRN}[+] Saved {len(results)} vulnerabilities to:{C_RST}")
        print(f"    - {json_file}")
        print(f"    - {csv_file}")
    else:
        print(f"{C_ORG}[-] No takeovers found.{C_RST}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Stopped by user.{C_RST}")

happy haxing 

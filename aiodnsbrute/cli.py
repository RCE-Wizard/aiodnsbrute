#!/usr/bin/env python3
"""
aiodnsbrute: asynchronous DNS bruteforcer
"""
import os
import sys
import random
import string
import asyncio
import itertools
import click
import socket
import datetime
from tqdm import tqdm
from typing import List, Optional, Dict, Any

# ─── Optional uvloop for faster event loop ─────────────────────────────────
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# ─── Dependency checks ───────────────────────────────────────────────────────
try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except ModuleNotFoundError:
    print("❌ Missing module 'dns'.  pip install dnspython", file=sys.stderr)
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    print("❌ Missing module 'dotenv'.  pip install python-dotenv", file=sys.stderr)
    sys.exit(1)

# Load .env for DB creds
load_dotenv()

# ─── ConsoleLogger ──────────────────────────────────────────────────────────
class ConsoleLogger:
    def __init__(self, verbosity: int):
        self.verbosity = verbosity

    def info(self, msg: str):
        if self.verbosity >= 1:
            tqdm.write(f"[*] {msg}")

    def success(self, msg: str):
        tqdm.write(click.style("[+]", fg="green") + f" {msg}")

    def warning(self, msg: str):
        if self.verbosity >= 1:
            tqdm.write(f"[!] {msg}")

    def error(self, msg: str):
        tqdm.write(f"[x] {msg}")

    def debug(self, msg: str):
        if self.verbosity >= 2:
            tqdm.write(f"[D] {msg}")

# ─── AioDNSBrute ─────────────────────────────────────────────────────────────
class AioDNSBrute:
    def __init__(self,
                 *,
                 verbosity: int = 0,
                 max_tasks: int = 200,
                 timeout: float = 3.0):
        self.verbosity = verbosity
        self.max_tasks = max_tasks
        self.timeout = timeout
        self.logger = ConsoleLogger(verbosity)
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.tries = 1
        self.resolver.retry_servfail = False

    async def _lookup(self, host: str) -> (str, List[str], Optional[Exception]):
        try:
            ans = await asyncio.wait_for(
                self.resolver.resolve(host, "A"),
                timeout=self.timeout
            )
            return host, [r.address for r in ans], None
        except Exception as e:
            return host, [], e

    def run(self,
            prefixes: List[str],
            domains: List[str],
            resolvers: Optional[List[str]],
            wildcard: bool,
            verify: bool,
            show_bar: bool) -> List[Dict[str,Any]]:

        # verify first domain
        if verify and domains:
            self.logger.info(f"Verifying DNS for {domains[0]}…")
            try:
                socket.gethostbyname(domains[0])
            except socket.gaierror as e:
                self.logger.error(f"Cannot resolve {domains[0]}: {e}")
                sys.exit(1)

        # custom nameservers?
        if resolvers:
            self.resolver.nameservers = resolvers
            self.resolver.rotate = True
            self.logger.info(f"Using custom resolvers: {resolvers}")

        # wildcard detection
        ignore_map: Dict[str, set] = {}
        if wildcard:
            for dom in domains:
                rnd = ''.join(random.choices(string.ascii_lowercase+string.digits, k=63))
                test = f"{rnd}.{dom}"
                _, ips, _ = asyncio.run(self._lookup(test))
                ignore_map[dom] = set(ips)
                if ips:
                    self.logger.warning(f"Wildcard detected on {dom}; ignoring {ips}")
                else:
                    self.logger.info(f"No wildcard on {dom}.")
        else:
            for dom in domains:
                ignore_map[dom] = set()
            self.logger.info("Wildcard detection disabled.")

        results: List[Dict[str,Any]] = []

        async def worker(batch: List[str], bar: Optional[tqdm]):
            tasks = [asyncio.create_task(self._lookup(host)) for host in batch]
            for fut in asyncio.as_completed(tasks):
                host, ips, err = await fut
                if bar:
                    bar.update(1)

                if err:
                    # ignore NXDOMAIN / timeout
                    if isinstance(err, (dns.resolver.NXDOMAIN,
                                        dns.resolver.NoNameservers,
                                        asyncio.TimeoutError)) or \
                       (isinstance(err, socket.gaierror) and err.errno == socket.EAI_NONAME):
                        continue
                    self.logger.warning(f"Error on {host}: {err}")
                    continue

                dom = host.split('.',1)[1]
                if not ips or set(ips)==ignore_map.get(dom,set()):
                    continue

                self.logger.success(f"{host:<30}\t{ips}")
                results.append({
                    "domain": host,
                    "ip": ips,
                    "last_seen": datetime.datetime.utcnow().isoformat()
                })

        async def scan_one(dom: str):
            wordlist = [f"{p}.{dom}" for p in prefixes]
            total = len(wordlist)
            bar = tqdm(total=total, unit="req", desc=f"Bruteforcing domain {dom}") if show_bar else None

            it = iter(wordlist)
            while True:
                batch = list(itertools.islice(it, self.max_tasks))
                if not batch:
                    break
                await worker(batch, bar)

            if bar:
                bar.close()

        # run each domain
        for dom in domains:
            asyncio.run(scan_one(dom))

        self.logger.info(f"Done – found {len(results)} subdomains over {len(domains)} domains.")
        return results

# ─── save_to_db ──────────────────────────────────────────────────────────────
def save_to_db(results: List[Dict[str,Any]]):
    try:
        import psycopg2
    except ModuleNotFoundError:
        print("❌ Missing psycopg2-binary, pip install psycopg2-binary", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(
        host=os.getenv("DB_HOST","localhost"),
        port=int(os.getenv("DB_PORT",5432)),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS dns_brute_results (
      domain TEXT PRIMARY KEY,
      ips TEXT[],
      last_seen TIMESTAMPTZ
    )
    """)
    for r in results:
        cur.execute("""
          INSERT INTO dns_brute_results(domain,ips,last_seen)
          VALUES (%s,%s,NOW())
          ON CONFLICT(domain) DO UPDATE
            SET ips = EXCLUDED.ips,
                last_seen = NOW()
        """, (r["domain"], r["ip"]))
    conn.commit()
    cur.close()
    conn.close()
    tqdm.write(click.style("[+] Saved results to database", fg="green"))

# ─── CLI ─────────────────────────────────────────────────────────────────────
@click.command()
@click.option("-w","--wordlist", required=True,
              help="prefix wordlist file")
@click.option("-F","--domains-file", type=click.File("r"),
              help="file with one domain per line (or CSV)")
@click.argument("domain", required=False)
@click.option("-t","--max-tasks", default=200, show_default=True,
              help="max concurrent DNS queries")
@click.option("-T","--timeout", default=3.0, show_default=True,
              help="seconds per DNS lookup before timing out")
@click.option("-r","--resolver-file", type=click.File("r"),
              help="custom DNS resolvers, one per line")
@click.option("--wildcard/--no-wildcard", default=True,
              help="auto-detect & skip wildcard IPs")
@click.option("--verify/--no-verify", default=True,
              help="verify domain resolves before bruting")
@click.option("--no-progress", is_flag=True,
              help="hide progress bars")
@click.option("-v","--verbosity", count=True,
              help="-v for info, -vv for debug")
@click.option("--to-db/--no-to-db", default=False,
              help="save results into Postgres")
@click.option("-o","--output", type=click.Choice(["off","csv","json"]),
              default="off", show_default=True,
              help="export format")
@click.option("-f","--outfile", type=click.File("w"),
              help="file path for CSV/JSON output")
def main(wordlist, domains_file, domain, max_tasks, timeout,
         resolver_file, wildcard, verify,
         no_progress, verbosity, to_db,
         output, outfile):

    # domains
    if domains_file:
        data = domains_file.read().replace(",", "\n")
        domains = [d.strip() for d in data.splitlines() if d.strip()]
    elif domain:
        domains = [domain]
    else:
        click.echo("❌ must supply DOMAIN or -F/--domains-file", err=True)
        sys.exit(1)

    # prefixes
    with open(wordlist) as f:
        prefixes = [w.strip() for w in f if w.strip()]
    if not prefixes:
        click.echo("❌ wordlist is empty", err=True)
        sys.exit(1)

    # custom resolvers
    resolvers = None
    if resolver_file:
        resolvers = [ln.strip() for ln in resolver_file if ln.strip() and not ln.startswith("#")]

    # output file handling
    close_me = None
    if output != "off":
        if not outfile:
            path = f"brute_results.{output}"
            outfile = open(path, "w", encoding="utf-8")
            close_me = outfile
        if outfile is sys.stdout:
            verbosity = 0

    # run
    brute = AioDNSBrute(verbosity=verbosity,
                        max_tasks=max_tasks,
                        timeout=timeout)
    all_results = brute.run(
        prefixes=prefixes,
        domains=domains,
        resolvers=resolvers,
        wildcard=wildcard,
        verify=verify,
        show_bar=not no_progress
    )

    # export
    if output == "csv" and outfile:
        import csv
        w = csv.writer(outfile)
        w.writerow(["domain","ips","last_seen"])
        for r in all_results:
            w.writerow([r["domain"], ";".join(r["ip"]), r["last_seen"]])
    if output == "json" and outfile:
        import json
        json.dump(all_results, outfile, indent=2)

    if close_me:
        close_me.close()

    if to_db:
        save_to_db(all_results)

if __name__ == "__main__":
    main()
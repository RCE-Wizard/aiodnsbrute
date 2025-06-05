import random
import string
import asyncio
import functools
import os
import uvloop
import aiodns
import click
import socket
from tqdm import tqdm
from aiodnsbrute.logger import ConsoleLogger


class aioDNSBrute(object):
    """aiodnsbrute implements fast domain name brute forcing using Python's asyncio module."""

    def __init__(self, verbosity=0, max_tasks=512):
        """Constructor.

        Args:
            verbosity: set output verbosity: 0 (default) is none, 3 is debug
            max_tasks: the maximum number of tasks asyncio will queue (default 512)
        """
        self.tasks = []
        self.errors = []
        self.fqdn = []
        self.ignore_hosts = []
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, rotate=True)
        self.sem = asyncio.BoundedSemaphore(max_tasks)
        self.max_tasks = max_tasks
        self.verbosity = verbosity
        self.logger = ConsoleLogger(verbosity)

    async def _dns_lookup(self, name):
        """Performs a DNS request using aiodns, self.lookup_type is set by the run function."""
        if self.lookup_type == "query":
            return await self.resolver.query(name, "A")
        elif self.lookup_type == "gethostbyname":
            return await self.resolver.gethostbyname(name, socket.AF_INET)

    def _dns_result_callback(self, name, future):
        """Handles the pycares object passed by the _dns_lookup function."""
        self.sem.release()
        err_number = None
        ips = []
        cname = False
        row = ""
        r = None
        
        # Handle known exceptions, barf on other ones
        if future.exception() is not None:
            try:
                err_number = future.exception().args[0]
                # err_text = future.exception().args[1]  # Not used, so removed
            except (IndexError, AttributeError):
                self.logger.error(f"Couldn't parse exception: {future.exception()}")
            if err_number == 4:
                pass  # Domain name not found
            elif err_number == 12:
                self.logger.warn(f"Timeout for {name}")
            elif err_number == 1:
                pass  # Server answered with no data
            else:
                self.logger.error(
                    f"{name} generated an unexpected exception: {future.exception()}"
                )
        else:
            if self.lookup_type == "query":
                try:
                    result = future.result()
                    ips = [ip.host for ip in result]
                    row = f"{name:<30}\t{ips}"
                except Exception as e:
                    self.logger.error(f"Error parsing query result for {name}: {e}")
            elif self.lookup_type == "gethostbyname":
                try:
                    r = future.result()
                    ips = [ip for ip in getattr(r, "addresses", [])]
                    if name == getattr(r, "name", ""):
                        cname = False
                        n = f"""{name:<30}\t{f"{'':<35}" if self.verbosity >= 2 else ""}"""
                    else:
                        cname = True
                        short_cname = f"{r.name[:28]}.." if len(r.name) > 30 else r.name
                        n = f'{name}{"**" if self.verbosity <= 1 else ""}'
                        n = f'''{n:<30}\t{f"CNAME {short_cname:<30}" if self.verbosity >= 2 else ""}'''
                    row = f"{n:<30}\t{ips}"
                except Exception as e:
                    self.logger.error(f"Error parsing gethostbyname result for {name}: {e}")
            # store the result
            if set(ips) != set(self.ignore_hosts):
                self.logger.success(row)
                dns_lookup_result = {"domain": name, "ip": ips}
                if self.lookup_type == "gethostbyname" and cname and r:
                    dns_lookup_result["cname"] = getattr(r, "name", "")
                    dns_lookup_result["aliases"] = getattr(r, "aliases", [])
                self.fqdn.append(dns_lookup_result)
            self.logger.debug(future.result())
        if future in self.tasks:
            self.tasks.remove(future)
        if self.verbosity >= 1 and hasattr(self, "pbar"):
            self.pbar.update()

    async def _queue_lookups(self, wordlist, domain):
        """Takes a list of words and adds them to the async loop also passing the original lookup domain name."""
        for word in wordlist:
            await self.sem.acquire()
            host = f"{word.strip()}.{domain}"
            task = asyncio.ensure_future(self._dns_lookup(host))
            task.add_done_callback(functools.partial(self._dns_result_callback, host))
            self.tasks.append(task)
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def run(
        self, wordlist, domain, resolvers=None, wildcard=True, verify=True, query=True
    ):
        """
        Sets up the bruteforce job, does domain verification, sets resolvers, checks for wildcard
        response to lookups, and sets the query type to be used. After all this, open the wordlist
        file and start the brute force - with ^C handling to cleanup nicely.
        """
        self.logger.info(
            f"Brute forcing {domain} with a maximum of {self.max_tasks} concurrent tasks..."
        )
        if verify:
            self.logger.info(f"Using local resolver to verify {domain} exists.")
            try:
                socket.gethostbyname(domain)
            except socket.gaierror as err:
                self.logger.error(
                    f"Couldn't resolve {domain}, use the --no-verify switch to ignore this error."
                )
                raise SystemExit(
                    self.logger.error(f"Error from host lookup: {err}")
                )
        else:
            self.logger.warn("Skipping domain verification. YOLO!")
        if resolvers:
            self.resolver.nameservers = resolvers
        self.logger.info(
            f"Using recursive DNS with the following servers: {self.resolver.nameservers}"
        )

        if wildcard:
            random_sld = (
                lambda: f'{"".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(63))}'
            )
            wc_check = None
            try:
                self.lookup_type = "query"
                wc_check = self.loop.run_until_complete(
                    self._dns_lookup(f"{random_sld()}.{domain}")
                )
            except aiodns.error.DNSError:
                self.logger.info(
                    f"No wildcard response was detected for this domain."
                )
                wc_check = None
            finally:
                # Handle both query and gethostbyname results
                if wc_check is not None:
                    if self.lookup_type == "query" and hasattr(wc_check, "__iter__"):
                        self.ignore_hosts = [host.host for host in wc_check]
                        self.logger.warn(
                            f"Wildcard response detected, ignoring answers containing {self.ignore_hosts}"
                        )
                    elif self.lookup_type == "gethostbyname" and hasattr(wc_check, "addresses"):
                        self.ignore_hosts = list(getattr(wc_check, "addresses", []))
                        self.logger.warn(
                            f"Wildcard response detected, ignoring answers containing {self.ignore_hosts}"
                        )
        else:
            self.logger.warn("Wildcard detection is disabled")

        if query:
            self.logger.info(
                "Using pycares `query` function to perform lookups, CNAMEs cannot be identified"
            )
            self.lookup_type = "query"
        else:
            self.logger.info(
                "Using pycares `gethostbyname` function to perform lookups, CNAME data will be appended to results (** denotes CNAME, show actual name with -vv)"
            )
            self.lookup_type = "gethostbyname"

        with open(wordlist, encoding="utf-8", errors="ignore") as words:
            w = words.read().splitlines()
        self.logger.info(f"Wordlist loaded, proceeding with {len(w)} DNS requests")
        try:
            if self.verbosity >= 1:
                self.pbar = tqdm(
                    total=len(w), unit="rec", maxinterval=0.1, mininterval=0
                )
            self.loop.run_until_complete(self._queue_lookups(w, domain))
        except KeyboardInterrupt:
            self.logger.warn("Caught keyboard interrupt, cleaning up...")
            for task in asyncio.all_tasks(self.loop):
                task.cancel()
            self.loop.stop()
        finally:
            self.loop.close()
            if self.verbosity >= 1 and hasattr(self, "pbar"):
                self.pbar.close()
            self.logger.info(f"Completed, {len(self.fqdn)} subdomains found")
        return self.fqdn


@click.command()
@click.option(
    "--wordlist",
    "-w",
    help="Wordlist to use for brute force.",
    default=f"{os.path.dirname(os.path.realpath(__file__))}/wordlists/bitquark_20160227_subdomains_popular_1000",
)
@click.option(
    "--max-tasks",
    "-t",
    default=512,
    help="Maximum number of tasks to run asynchronosly.",
)
@click.option(
    "--resolver-file",
    "-r",
    type=click.File("r"),
    default=None,
    help="A text file containing a list of DNS resolvers to use, one per line, comments start with #. Default: use system resolvers",
)
@click.option(
    "--verbosity", "-v", count=True, default=1, help="Increase output verbosity"
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["csv", "json", "off"]),
    default="off",
    help="Output results to DOMAIN.csv/json (extension automatically appended when not using -f).",
)
@click.option(
    "--outfile",
    "-f",
    type=click.File("w"),
    help="Output filename. Use '-f -' to send file output to stdout overriding normal output.",
)
@click.option(
    "--query/--gethostbyname",
    default=True,
    help="DNS lookup type to use query (default) should be faster, but won't return CNAME information.",
)
@click.option(
    "--wildcard/--no-wildcard",
    default=True,
    help="Wildcard detection, enabled by default",
)
@click.option(
    "--verify/--no-verify",
    default=True,
    help="Verify domain name is sane before beginning, enabled by default",
)
@click.version_option("0.3.2")
@click.argument("domain", required=True)
def main(**kwargs):
    """aiodnsbrute is a command line tool for brute forcing domain names utilizing Python's asyncio module.

    credit: blark (@markbaseggio)
    """
    output = kwargs.get("output")
    verbosity = int(kwargs.get("verbosity", 0) or 0)
    max_tasks = int(kwargs.get("max_tasks", 512) or 512)
    wildcard = bool(kwargs.get("wildcard", True))
    verify = bool(kwargs.get("verify", True))
    query = bool(kwargs.get("query", True))
    resolvers = kwargs.get("resolver_file")
    outfile = kwargs.get("outfile", None)

    # Ensure outfile is a valid file object or None
    if output != "off":
        # turn off output if we want JSON/CSV to stdout, hacky
        if outfile is not None and hasattr(outfile, "write"):
            verbosity = 0
        if outfile is None:
            outfile = open(f'{kwargs["domain"]}.{output}', "w")
    if resolvers:
        lines = resolvers.read().splitlines()
        resolvers = [x.strip() for x in lines if (x and not x.startswith("#"))]

    bf = aioDNSBrute(verbosity=verbosity, max_tasks=max_tasks)
    results = bf.run(
        wordlist=kwargs.get("wordlist"),
        domain=kwargs.get("domain"),
        resolvers=resolvers,
        wildcard=wildcard,
        verify=verify,
        query=query,
    )

    # Only write output if outfile is a valid file object
    if output == "json" and outfile is not None and hasattr(outfile, "write"):
        import json
        json.dump(results, outfile)

    if output == "csv" and outfile is not None and hasattr(outfile, "write"):
        import csv
        writer = csv.writer(outfile)
        writer.writerow(["Hostname", "IPs", "CNAME", "Aliases"])
        for r in results:
            writer.writerow([
                r.get("domain"),
                r.get("ip", [""])[0] if isinstance(r.get("ip"), list) else r.get("ip", ""),
                r.get("cname", ""),
                r.get("aliases", [""])[0] if isinstance(r.get("aliases", []), list) else r.get("aliases", ""),
            ])


if __name__ == "__main__":
    main()

import asyncio
from queue import Empty, Queue
import threading

from nmap.nmap import PortScanner
from common.messaging.vumos.vumos import VumosServiceStatus
from common.messaging.vumos import ScheduledVumosService

import ipaddress

loop = asyncio.get_event_loop()


async def task(service: ScheduledVumosService, _: None = None):
    print("Start Scanning")

    # Calculate ip address list
    ip_ranges: str = service.get_config('ip_ranges')
    targets = [item for l in (list(map(lambda x: [str(ip) for ip in ipaddress.IPv4Network(
        x.strip())], ip_ranges.split(',')))) for item in l]

    service.set_status(VumosServiceStatus(
        'running', f"Scanning... done {0}/{len(targets)} targets"))

    # Create nmap instance
    nmap = PortScanner()

    # Fill queue
    target_queue = Queue()
    for target in targets:
        target_queue.put(target)

    def run_next(thread: int):
        print('Ye ' + str(thread))
        try:
            # Get next target
            target = target_queue.get(block=False)

            # Scan
            print(f"[T{thread}]: Started scanning {target}")
            result = nmap.scan(target, arguments='-sV -sS -O')

            scan = result["scan"]

            # Send data
            if len(scan.keys()) > 0:
                host = list(scan.keys())[0]
                scan = scan[host]

                # Notify found host
                domains = []

                hostnames = []
                if 'hostnames' in scan:
                    hostnames = scan['hostnames']

                for hostname in hostnames:
                    if hostname['name'] != "":
                        domains.append(hostname)

                extra = {}

                if "vendor" in scan:
                    extra['vendor'] = scan['vendor']
                if "status" in scan:
                    extra['status'] = scan['status']
                if "osmatch" in scan:
                    extra['osmatch'] = scan['osmatch']

                print(extra)

                asyncio.run(service.send_target_data(
                    host, domains, extra=extra))

                # Notify found services
                tcp = {}
                if 'tcp' in scan:
                    tcp = scan['tcp']
                for port in tcp.keys():
                    found = tcp[port]

                    name = found['product']
                    if 'extrainfo' in found:
                        name += f" {found['extrainfo']}"

                    asyncio.run(service.send_service_data(
                        host,
                        port,
                        name=name,
                        protocol=found['name'],
                        version=found['version'],
                        extra={
                            "nmap": {
                                "state": found['state'],
                                "reason": found['reason'],
                                "conf": found['conf'],
                                "cpe": found['cpe']
                            }
                        }
                    ))
                pass

            # Set status
            service.set_status(VumosServiceStatus(
                'running', f"Scanning... done {len (targets) - target_queue.qsize()}/{len(targets)} targets"))

            run_next(thread)
        except Empty as e:
            print(f"[T{thread}]: Stopped")
            return

    # Scan targets
    threads: threading.Thread = []
    for threadi in range(min(10, len(targets))):
        threads.append(threading.Thread(target=run_next, args=(threadi,)))

    for thread in threads:
        thread.start()

    # Wait for thread finishes
    for thread in threads:
        thread.join()

    print(f"Finished Scanning")


# Initialize Vumos service
service = ScheduledVumosService(
    "Ranged Periodic Nmap Scanner",
    "A nmap scanner (Only IP addresses and ports) that performs extensive scans in IP ranges periodically",
    conditions=lambda s: True, task=task, parameters=[
        {
            "name": "Flags",
            "description": "Flags to be used when scanning",
            "key": "flags",
            "value": {
                "type": "string",
                "default": "-p- -sV --version-all -A -sC -f -O -oX {outputfile} -Pn {target}"
            }
        },
        {
            "name": "Redo Days",
            "description": "Days between scanning runs for each host",
            "key": "redo_days",
            "value": {
                "type": "integer",
                "default": 7
            }
        },
        {
            "name": "IP Ranges",
            "description": "Comma separated CIDR IP ranges to scan",
            "key": "ip_ranges",
            "value": {
                "type": "string",
                "default": "10.10.1.1"  # "10.10.10.0/24,192.168.15.0/24"
            }
        }])

loop.run_until_complete(service.connect(loop))
loop.run_until_complete(service.loop())

import asyncio
from queue import Queue
from multiprocessing import Manager
from typing import Dict

from nmap.nmap import PortScannerAsync
from common.messaging.vumos import ScheduledVumosService, VumosService

loop = asyncio.get_event_loop()


async def perform_scan(service: VumosService, flags: str, ranges: str):
    # Calculate ip address list
    ip_ranges = ranges.replace(',', ' ')

    targets = Manager().Queue()
    services = Manager().Queue()

    # Result processor function
    def on_host_result(host, result):
        if not result:
            return

        scan = result["scan"]

        # Send data
        if len(scan.keys()) > 0:
            print(f"Scanned [{host}]")
            scan = scan[host]

            parsed_keys = [
                "hostnames",
                "addresses",
                "tcp"
            ]

            # Notify found host
            domains = []

            hostnames = []
            if 'hostnames' in scan:
                hostnames = scan['hostnames']

            for hostname in hostnames:
                if hostname['name'] != "":
                    domains.append(hostname['name'])

            extra = {}

            for key in scan.keys():
                if not key in parsed_keys:
                    extra[key] = scan[key]

            targets.put((host, domains, extra))

            # Notify found services
            tcp = {}
            if 'tcp' in scan:
                tcp = scan['tcp']
            for port in tcp.keys():
                found = tcp[port]

                parsed_keys = [
                    "hostnames",
                    "addresses",
                    "tcp"
                ]

                name = found['product']
                if 'extrainfo' in found:
                    name += f" {found['extrainfo']}"

                services.put((
                    host,
                    port,
                    name,
                    found['name'],
                    found['version'],
                    {
                        "nmap": {
                            "state": found['state'],
                            "reason": found['reason'],
                            "conf": found['conf'],
                            "cpe": found['cpe']
                        }
                    }
                ))

    # Create nmap instance and run scan
    nmap = PortScannerAsync()

    nmap.scan(hosts=ip_ranges,
              arguments=flags, callback=on_host_result)

    # Wait for scan finish
    while nmap.still_scanning() or (not targets.empty()) or (not services.empty()):
        while not targets.empty():
            await service.send_target_data(*targets.get())
            await asyncio.sleep(0.5)

        while not services.empty():
            await service.send_service_data(*services.get())
            await asyncio.sleep(0.5)

        await asyncio.sleep(1)


async def task(service: ScheduledVumosService, _: None = None):
    print("Start Scanning")
    await perform_scan(service, service.get_config('flags'), service.get_config('ip_ranges'))
    print(f"Finished Scanning")


async def scan_range(service: ScheduledVumosService, arguments: Dict):
    await perform_scan(service, arguments['flags'], arguments['ip_ranges'])

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
                "default": "-A -f"
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
                "default": "10.10.10.10"
            }
        }],
    actions=[
        {
            "name": "Scan range",
            "description": "Pontually scans an ip range given",
            "arguments": [
                {
                    "name": "Flags",
                    "description": "Flags to be used when scanning",
                    "key": "flags",
                    "value": {
                        "type": "string",
                        "default": "-A -f"
                    }
                },
                {
                    "name": "IP Ranges",
                    "description": "The IP ranges to be scanned",
                    "key": "ip_ranges",
                    "value": {
                        "type": "string"
                    }
                }
            ],
            "key": "scan_range",
        }
    ],
    pool_interval=3600 * 24 * 7)


service.on_action("scan_range", scan_range)

loop.run_until_complete(service.connect(loop))
service.loop(loop)

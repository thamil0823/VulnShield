import nmap

def run_scan(target):

    scanner = nmap.PortScanner()

    scanner.scan(target, arguments="-F")

    results = []

    for host in scanner.all_hosts():

        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                results.append({
                    "Port": port,
                    "State": scanner[host][proto][port]["state"],
                    "Service": scanner[host][proto][port]["name"]
                })

    return results
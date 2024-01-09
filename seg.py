#!/usr/bin/env python3
# Python Port Scanner for Network Segmentation Test with Output to File
# Note: Run with appropriate permissions and legal authorization
#Author Vasilis Orlof (vasilis.orlof@a2secure.com) and ChatGPT :) 

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

NMAP_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))
            return port, True
        except:
            return port, False

def scan_host(host, ports_to_scan, threads, output_file):
    with ThreadPoolExecutor(max_workers=threads) as executor, open(output_file, 'a') as file:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports_to_scan}
        for future in future_to_port:
            port, status = future.result()
            if status:
                result = f"Host: {host}, Port {port} is open\n"
                print(result)
                file.write(result)

def main():
    parser = argparse.ArgumentParser(description="Simple python port scanner using Nmap Top Ports")
    parser.add_argument("--host", help="IP address of the Host to scan")
    parser.add_argument("--hostfile", help="File with a list of hosts to scan, one per line")
    parser.add_argument("--start-port", type=int, help="Start port number (default: Nmap top ports)")
    parser.add_argument("--end-port", type=int, help="End port number (default: Nmap top ports)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads to use (default: 100)")

    # Check if help is requested
    args, unknown = parser.parse_known_args()
    if '-h' in unknown or '--help' in unknown:
        parser.print_help()
        sys.exit()

    # Prompt for network ID at the start
    network_id = input("Enter the network ID or name for this segmentation test: ")
    print(f"Running segmentation test on network: {network_id}")
    output_file = f"{network_id}_scan_results.txt"
    print(f"Results will be saved to {output_file}")

    ports_to_scan = NMAP_TOP_PORTS if args.start_port is None or args.end_port is None else range(args.start_port, args.end_port + 1)

    if args.host:
        scan_host(args.host, ports_to_scan, args.threads, output_file)
    elif args.hostfile:
        with open(args.hostfile, 'r') as file:
            hosts = file.read().splitlines()
            for host in hosts:
                if host:
                    print(f"Scanning host: {host}")
                    scan_host(host, ports_to_scan, args.threads, output_file)

if __name__ == "__main__":
    main()

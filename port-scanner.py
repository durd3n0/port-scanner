#!/usr/bin/env python3
"""
***********************************************
*  Python NMAP Port Scanner                   *
***********************************************
Use this tool **only** on systems you own or 
have explicit permission to scan. Unauthorized 
scanning may violate laws or policies.
***********************************************
"""

try:
    import nmap
except ImportError:
    print("[!] Python nmap module not found.")
    print("    Install it using: pip install python-nmap")
    import sys
    sys.exit(1)

import sys
import argparse


def print_banner():
    banner_text = """
    *************************************
    * Python NMAP Port Scanner          *
    *************************************
    This tool allows you to scan for open 
    ports on a target host using NMAP.
    You can specify the target IP address 
    or hostname and the range of ports to 
    scan.
    *************************************
    """
    print(banner_text)


def get_target(cli_target=None):
    if cli_target:
        return cli_target.strip()
    target = ""
    while not target:
        target = input("[*] Enter target IP address or hostname: ").strip()
        if not target:
            print("[!] Error: Please enter a target.")
    return target


def get_ports(cli_ports=None):
    if cli_ports:
        return cli_ports.strip()
    ports = ""
    while not ports:
        ports = input("[*] Enter port range (e.g., '1-65535', '80,443', '135'): ").strip()
        if not ports:
            print("[!] Error: Please enter a port range.")
    return ports


def get_options(cli_options=None):
    if cli_options:
        return cli_options.strip()
    options = input("[*] Enter Nmap arguments (e.g., -sV -sC) [Press Enter for default: -T4]: ").strip()
    if not options:
        options = "-T4"  # default to faster scan
    return options


def run_scan(target, port_range, options):
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("\n[!] Error: Nmap not found!")
        print("Please install Nmap on your system: https://nmap.org/download.html")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error initializing Nmap: {e}")
        sys.exit(1)

    print(f"[+] Scanning {target} for ports {port_range} with arguments {options}...")
    print("This may take a moment...")

    try:
        nm.scan(target, port_range, arguments=options)
        print("[+] Scan Complete.\n")

        if not nm.all_hosts():
            print(f"[!] Host {target} seems down or did not respond.")
            return

        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print(f"Host : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")

            found_open_port = False  

            for proto in nm[host].all_protocols():
                print(f"\nProtocol : {proto}")
                ports = nm[host][proto].keys()

                if not ports:
                    print("  No ports found in this protocol.")
                    continue

                for port in sorted(ports):
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        found_open_port = True
                    print(f"  Port : {port}\tState : {port_info['state']}\tService : {port_info['name']}")

            if not found_open_port:
                print(f"[+] No *open* ports found on {host} for ports {port_range}.")

            print('----------------------------------------------------')

    except Exception as e:
        print(f"\n[!] Error during scan: {e}")


def main():
    parser = argparse.ArgumentParser(description="Simple Python Nmap Port Scanner")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", help="Port range, e.g., '1-1024' or '80,443'")
    parser.add_argument("-o", "--options", help="Nmap options, e.g., '-sV -sC'")
    args = parser.parse_args()

    while True:
        print_banner()
        target_host = get_target(args.target)
        print(f"[+] Set target to: {target_host}")

        port_range = get_ports(args.ports)
        print(f"[+] Set port range to: {port_range}")

        scan_options = get_options(args.options)
        print(f"[+] Using Nmap arguments: {scan_options}\n")

        run_scan(target_host, port_range, scan_options)

        args.target = None
        args.ports = None
        args.options = None

        choice = input("\n[*] Type 'r' to scan another hostname or 'Enter' to exit: ").strip().lower()
        if choice != "r":
            break


if __name__ == "__main__":
    main()

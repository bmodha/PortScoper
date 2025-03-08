#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, DefaultDict
from dataclasses import dataclass
from pathlib import Path
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from collections import defaultdict
import argparse
import sys
import json
from rich.console import Console
from rich.table import Table

@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    scripts: Dict[str, str] = None

    def __post_init__(self):
        if self.scripts is None:
            self.scripts = {}

@dataclass
class Host:
    ip: str
    hostname: Optional[str]
    ports: List[Port]
    os_matches: List[str]
    status: str

class PortScoper:
    VERSION = "1.0.0"  # Add version constant at class level
    
    def __init__(self):
        self.console = Console()
        self.hosts: List[Host] = []
        self.unique_ports: DefaultDict[int, Set[str]] = defaultdict(set)
        self.enumeration_commands: Dict[str, List[str]] = {}

    def display_banner(self) -> None:
        """Display the tool's banner."""
        banner = f"""[bold cyan]
 ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗ 
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
 ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  ██████╔╝
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗
 ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗██║  ██║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝[/bold cyan]"""
        
        self.console.print(banner)
        self.console.print(f"\n[dim]Version {self.VERSION} - https://github.com/bmodha/PortScoper[/dim]\n")

    def parse_nmap_xml(self, input_file: str) -> None:
        """Parse Nmap XML output file."""
        parser = NmapXMLParser(input_file)
        self.hosts = parser.parse()
        self._process_unique_ports()
        self._generate_enumeration_commands()

    def _process_unique_ports(self) -> None:
        """Process and store unique ports and their services."""
        for host in self.hosts:
            for port in host.ports:
                if port.state == "open":
                    self.unique_ports[port.number].add(port.service)

    def _generate_enumeration_commands(self) -> None:
        """Generate enumeration commands for each unique port/service combination."""
        common_commands = {
            "http": [
                "nmap -sV -p {port} -sC --script=http-enum,http-title,http-headers {target}",
                "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "nikto -h {target} -p {port}"
            ],
            "https": [
                "nmap -sV -p {port} -sC --script=ssl-enum-ciphers,http-enum {target}",
                "gobuster dir -u https://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k",
                "sslscan {target}:{port}"
            ],
            "ssh": [
                "nmap -p {port} -sV -sC --script=ssh-auth-methods,ssh2-enum-algos {target}"
            ],
            "smb": [
                "nmap -p {port} -sV -sC --script=smb-* {target}",
                "enum4linux -a {target}",
                "smbclient -L //{target} -N"
            ],
            "ftp": [
                "nmap -p {port} -sV -sC --script=ftp-* {target}",
                "hydra -L /usr/share/wordlists/user.txt -P /usr/share/wordlists/pass.txt {target} ftp -s {port}"
            ],
            "mysql": [
                "nmap -p {port} -sV -sC --script=mysql-* {target}"
            ],
            "mssql": [
                "nmap -p {port} -sV -sC --script=ms-sql-* {target}"
            ],
            "default": [
                "nmap -sV -p {port} -sC {target}"
            ]
        }

        for port, services in self.unique_ports.items():
            commands = []
            for service in services:
                service_lower = service.lower()
                if service_lower in common_commands:
                    commands.extend(common_commands[service_lower])
                else:
                    commands.extend(common_commands["default"])
            
            self.enumeration_commands[str(port)] = commands

    def generate_excel_report(self, output_file: str) -> None:
        """Generate Excel report with host information."""
        excel_writer = ExcelWriter(self.hosts, output_file)
        excel_writer.save()
        self.console.print(f"[green]Successfully created Excel report: {output_file}[/green]")

    def print_unique_ports_report(self) -> None:
        """Print a table of unique ports and their services."""
        table = Table(title="Unique Ports and Services")
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Services", style="magenta")

        for port in sorted(self.unique_ports.keys()):
            services = ", ".join(sorted(self.unique_ports[port]))
            table.add_row(str(port), services)

        self.console.print(table)

    def print_enumeration_commands(self) -> None:
        """Print enumeration commands for each port."""
        # Create a mapping of ports to hosts that have that port open
        port_to_hosts: DefaultDict[int, List[tuple[str, str]]] = defaultdict(list)
        for host in self.hosts:
            for port in host.ports:
                if port.state == "open":
                    # Store tuple of (ip, service) for each host
                    port_to_hosts[port.number].append((host.ip, port.service))

        # Sort ports numerically
        port_numbers = sorted(port_to_hosts.keys())

        # Print header
        self.console.print("\n[bold yellow]Enumeration Commands by Port Number:[/bold yellow]")
        
        for port in port_numbers:
            # Get all hosts and their services for this port
            hosts_and_services = port_to_hosts[port]
            
            # Print port header with all services found on this port
            unique_services = sorted(set(service for _, service in hosts_and_services))
            services_str = ", ".join(unique_services)
            self.console.print(f"\n[bold cyan]Port {port} - {services_str}[/bold cyan]")
            
            # Get the appropriate commands for each service
            commands = set()  # Use set to avoid duplicate commands
            for _, service in hosts_and_services:
                service_lower = service.lower()
                if service_lower in self.common_commands:
                    commands.update(self.common_commands[service_lower])
                else:
                    commands.update(self.common_commands["default"])
            
            # Print commands for each host
            for host_ip, _ in sorted(hosts_and_services):  # Sort by IP
                self.console.print(f"\n[bold blue]Target: {host_ip}[/bold blue]")
                # Print each command with the IP and port filled in
                for i, cmd_template in enumerate(sorted(commands), 1):
                    cmd = cmd_template.format(target=host_ip, port=port)
                    self.console.print(f"[blue]{i}. {cmd}[/blue]")

    def save_enumeration_commands(self, output_file: str) -> None:
        """Save enumeration commands to a file."""
        # Convert the commands dict to a sorted list of dictionaries
        sorted_commands = []
        for port in sorted(map(int, self.enumeration_commands.keys())):
            port_str = str(port)
            sorted_commands.append({
                "port": port,
                "services": list(self.unique_ports[port]),
                "commands": self.enumeration_commands[port_str]
            })

        with open(output_file, 'w') as f:
            json.dump({"ports": sorted_commands}, f, indent=2)
        self.console.print(f"[green]Saved enumeration commands to: {output_file}[/green]")

    @property
    def common_commands(self) -> Dict[str, List[str]]:
        """Define common enumeration commands for different services."""
        return {
            "http": [
                "nmap -sV -p {port} -sC --script=http-enum,http-title,http-headers {target}",
                "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "nikto -h {target} -p {port}"
            ],
            "https": [
                "nmap -sV -p {port} -sC --script=ssl-enum-ciphers,http-enum {target}",
                "gobuster dir -u https://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k",
                "sslscan {target}:{port}"
            ],
            "ssh": [
                "nmap -p {port} -sV -sC --script=ssh-auth-methods,ssh2-enum-algos {target}"
            ],
            "smb": [
                "nmap -p {port} -sV -sC --script=smb-* {target}",
                "enum4linux -a {target}",
                "smbclient -L //{target} -N"
            ],
            "ftp": [
                "nmap -p {port} -sV -sC --script=ftp-* {target}",
                "hydra -L /usr/share/wordlists/user.txt -P /usr/share/wordlists/pass.txt {target} ftp -s {port}"
            ],
            "mysql": [
                "nmap -p {port} -sV -sC --script=mysql-* {target}"
            ],
            "mssql": [
                "nmap -p {port} -sV -sC --script=ms-sql-* {target}"
            ],
            "default": [
                "nmap -sV -p {port} -sC {target}"
            ]
        }

class NmapXMLParser:
    def __init__(self, input_file: str):
        self.input_file = Path(input_file)
        self.hosts: List[Host] = []

    def parse(self) -> List[Host]:
        """Parse Nmap XML output file."""
        if not self.input_file.exists():
            raise FileNotFoundError(f"File {self.input_file} not found")

        tree = ET.parse(self.input_file)
        root = tree.getroot()
        
        for host_elem in root.findall('.//host'):
            # Get IP address
            addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
            ip = addr_elem.get('addr')
            
            # Get hostname if available
            hostname_elem = host_elem.find('.//hostname')
            hostname = hostname_elem.get('name') if hostname_elem is not None else None
            
            # Get status
            status = host_elem.find('status').get('state')
            
            # Get ports
            ports = []
            for port_elem in host_elem.findall('.//port'):
                port_number = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol')
                
                state_elem = port_elem.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                
                service_elem = port_elem.find('service')
                service = service_elem.get('name') if service_elem is not None else 'unknown'
                version = service_elem.get('product') if service_elem is not None else None
                
                # Get script outputs
                scripts = {}
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output')
                    scripts[script_id] = script_output
                
                ports.append(Port(port_number, protocol, state, service, version, scripts))
            
            # Get OS matches
            os_matches = []
            for os_elem in host_elem.findall('.//osmatch'):
                os_matches.append(os_elem.get('name'))
            
            self.hosts.append(Host(ip, hostname, ports, os_matches, status))
        
        return self.hosts

class ExcelWriter:
    def __init__(self, hosts: List[Host], output_file: str):
        self.hosts = hosts
        self.output_file = output_file
        self.workbook = openpyxl.Workbook()
        self.workbook.remove(self.workbook.active)

    def create_sheet_for_host(self, host: Host) -> None:
        """Create a worksheet for a single host."""
        sheet_name = host.ip.replace('.', '_')
        ws = self.workbook.create_sheet(sheet_name)

        # Set column widths
        ws.column_dimensions['A'].width = 15  # Port
        ws.column_dimensions['B'].width = 15  # Protocol
        ws.column_dimensions['C'].width = 15  # State
        ws.column_dimensions['D'].width = 20  # Service
        ws.column_dimensions['E'].width = 30  # Version
        ws.column_dimensions['F'].width = 40  # Notes

        # Create headers
        headers = ['Port', 'Protocol', 'State', 'Service', 'Version', 'Notes']
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.value = header
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')

        # Add host information
        host_info_row = [
            f"IP: {host.ip}",
            f"Hostname: {host.hostname if host.hostname else 'N/A'}",
            f"Status: {host.status}",
            f"OS: {', '.join(host.os_matches) if host.os_matches else 'N/A'}"
        ]
        
        for col, info in enumerate(host_info_row, 1):
            cell = ws.cell(row=2, column=col)
            cell.value = info
        
        ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=len(headers))
        ws.cell(row=2, column=1).alignment = Alignment(horizontal='left')

        # Add port information
        for idx, port in enumerate(sorted(host.ports, key=lambda x: x.number), 3):
            row = [
                port.number,
                port.protocol,
                port.state,
                port.service,
                port.version if port.version else '',
                ''  # Empty notes column
            ]
            
            for col, value in enumerate(row, 1):
                cell = ws.cell(row=idx, column=col)
                cell.value = value
                cell.alignment = Alignment(horizontal='left')

            if port.scripts:
                notes = []
                for script_id, output in port.scripts.items():
                    notes.append(f"{script_id}: {output}")
                ws.cell(row=idx, column=len(headers)).value = '\n'.join(notes)

    def save(self) -> None:
        """Save the Excel workbook."""
        for host in self.hosts:
            self.create_sheet_for_host(host)
        self.workbook.save(self.output_file)

def main():
    parser = argparse.ArgumentParser(
        description='PortScoper - A comprehensive Nmap output analyzer and enumeration helper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (uses default output filenames)
  python portscoper.py scan.xml

  # Specify custom output files
  python portscoper.py scan.xml -o custom_report.xlsx -c custom_commands.json

Note:
  The input file must be in Nmap XML format. Generate it using:
  nmap -sV -sC -O <target> -oX scan.xml
""")
    
    parser.add_argument(
        'input_file',
        help='Input Nmap XML file (generated using -oX flag)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output Excel file path (default: %(default)s)',
        default='portscoper_report.xlsx'
    )
    parser.add_argument(
        '-c', '--commands',
        help='Output file path for enumeration commands in JSON format (default: %(default)s)',
        default='enumeration_commands.json'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize PortScoper
        scoper = PortScoper()
        
        # Display banner
        scoper.display_banner()
        
        # Parse nmap output
        scoper.console.print("[yellow]Parsing Nmap XML output...[/yellow]")
        scoper.parse_nmap_xml(args.input_file)
        
        # Generate Excel report
        scoper.console.print("[yellow]Generating Excel report...[/yellow]")
        scoper.generate_excel_report(args.output)
        
        # Print unique ports report
        scoper.console.print("\n[yellow]Unique Ports and Services:[/yellow]")
        scoper.print_unique_ports_report()
        
        # Print and save enumeration commands
        scoper.console.print("\n[yellow]Enumeration Commands:[/yellow]")
        scoper.print_enumeration_commands()
        scoper.save_enumeration_commands(args.commands)
        
    except Exception as e:
        scoper.console.print(f"[red]Error: {str(e)}[/red]", style="bold red")
        sys.exit(1)

if __name__ == "__main__":
    main()
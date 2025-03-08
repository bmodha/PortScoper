# PortScoper

A comprehensive Nmap output analyzer and enumeration helper that parses XML output and generates detailed reports with enumeration commands. This is a work in progress, and the main part that needs more work is the list of enumeration commands per service in the common services section. 

## Features

- Parse Nmap XML output files
- Generate organized Excel reports
- Multiple report organization modes (subnet-based or IP-based)
- Merge multiple scan results with different strategies
- Generate targeted enumeration commands
- Support for extensive service types
- Comprehensive service enumeration techniques
- Beautiful console output with rich formatting

## Installation

```bash
# Clone the repository
git clone https://github.com/bmodha/PortScoper.git
cd PortScoper

# Install requirements
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python portscoper.py -i scan.xml
```

### Multiple Input Files

You can analyze multiple Nmap XML files with different merge strategies:

```bash
# Analyze multiple scans (union strategy by default)
python portscoper.py -i scan1.xml scan2.xml scan3.xml

# Use different merge strategies
python portscoper.py -i scan1.xml scan2.xml --merge-strategy intersection
python portscoper.py -i scan1.xml scan2.xml --merge-strategy latest
```

### Report Organization

Choose between two organization modes for the Excel report:

```bash
# Subnet-based organization (default)
python portscoper.py -i scan.xml --organization subnet

# IP-based organization
python portscoper.py -i scan.xml --organization ip
```

#### Subnet-based Organization
- Groups hosts by /24 subnet
- One sheet per subnet
- Summary sheet with subnet statistics
- Better for large networks
- More compact for many hosts

#### IP-based Organization
- One sheet per IP address
- Detailed view of each host
- Summary sheet with host statistics
- Better for individual host analysis
- More granular information

### Custom Output Files

Specify custom output file paths:
```bash
python portscoper.py -i scan.xml -o custom_report.xlsx -c custom_commands.json
```

## Merge Strategies

When analyzing multiple scan files, choose from three merge strategies:

1. `union` (default): Combines all findings from all scans
   - Includes all hosts from all scans
   - Combines all open ports
   - Updates port state if it changes

2. `intersection`: Keeps only findings present in all scans
   - Only includes hosts present in all scans
   - Only includes ports found in all scans
   - Good for finding persistent services

3. `latest`: Uses the most recent scan data
   - Takes the newest data for each host
   - Completely replaces old data
   - Best for current state analysis

## Report Format

### Summary Sheet
- Network/Host overview
- Statistics and key findings
- Hyperlinks to detailed sheets
- Critical service highlighting

### Detailed Sheets (Subnet or IP based)
- Port information
- Service details
- Version detection
- OS detection results
- NSE script outputs
- Comprehensive notes

## Enumeration Commands

Generates targeted enumeration commands for:
- Web Services (HTTP/HTTPS)
- Network Services (SSH, FTP, Telnet)
- Windows Services (SMB, RDP)
- Databases (MySQL, MSSQL, PostgreSQL)
- Mail Services (SMTP, POP3, IMAP)
- And many more...

## Requirements

- Python 3.6+
- openpyxl
- rich

## Input Format

The tool expects Nmap XML output. Generate it using:
```bash
nmap -sV -sC -O <target> -oX scan.xml
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

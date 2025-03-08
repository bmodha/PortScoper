# PortScoper

A comprehensive Nmap output analyzer and enumeration helper that generates Excel reports and enumeration commands. Send an nmap output in the form of an XML into the script, and it outputs an XLSX file with the formatted results for tracking purposes. Additionally, the tool outputs all unique ports discovered in a table, and enumeration commands to continue pentesting.

## Features

- Parse Nmap XML output files
- Generate Excel reports with:
  - Separate sheets for each host
  - Port information (number, protocol, state, service, version)
  - Script outputs
  - Host details (IP, hostname, OS detection)
- List unique ports and their services
- Generate enumeration commands for discovered services
- Organized output by port number
- JSON export of enumeration commands

## Installation

1. Clone the repository:
```bash
git clone https://github.com/bmodha/PortScoper.git
cd PortScoper
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run an Nmap scan with XML output:
```bash
nmap -sV -sC -O <target> -oX scan.xml
```

2. Run PortScoper:
```bash
python portscoper.py scan.xml
```

### Command Line Options

```
usage: portscoper.py [-h] [-o OUTPUT] [-c COMMANDS] input_file

positional arguments:
  input_file            Input Nmap XML file (generated using -oX flag)

optional arguments:
  -h, --help           show this help message and exit
  -o OUTPUT, --output  Output Excel file path (default: portscoper_report.xlsx)
  -c COMMANDS, --commands
                      Output file path for enumeration commands in JSON format (default: enumeration_commands.json)
```

### Example Output

The tool generates:
1. An Excel report with detailed host and port information
2. A summary of unique ports and their services
3. Enumeration commands for each discovered service
4. A JSON file containing all enumeration commands

## Requirements

- Python 3.6+
- openpyxl
- rich

## License

MIT License

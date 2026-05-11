# fuplc CLI Documentation

## Overview
The `fuplc` command-line interface (CLI) provides a modular framework for OT/ICS security assessment. It is designed to be intuitive and powerful, similar to tools like Metasploit, allowing users to perform reconnaissance, scanning, sniffing, simulation, reporting, and controlled attacks on industrial systems.

## Installation
Assuming `fuplc` is installed via pip or as a package on Kali Linux:

```bash
pip install fuplc
# or
apt install fuplc  # if packaged
```

## Basic Usage
```bash
fuplc [global-options] <subcommand> [subcommand-options]
```

## Global Options
- `--verbose` / `-v`: Increase verbosity
- `--output` / `-o`: Specify output file
- `--help` / `-h`: Display help
- `--config`: Specify configuration file (default: ~/.fuplc/config)

## Subcommands

### discover
Discover industrial assets on a network.

```bash
fuplc discover --subnet 192.168.1.0/24
```

Options:
- `--subnet`: Network subnet to scan
- `--protocol`: Specific protocol to look for (e.g., modbus, opcua)

### scan
Perform detailed scanning of a target.

```bash
fuplc scan --target 192.168.1.100
```

Options:
- `--target`: IP address or hostname
- `--ports`: Ports to scan
- `--protocol`: Protocol to use

### sniff
Sniff and parse industrial protocol traffic.

```bash
fuplc sniff --interface eth0 --protocol modbus
```

Options:
- `--interface`: Network interface
- `--protocol`: Protocol to sniff
- `--filter`: Additional packet filter

### simulate
Simulate industrial traffic or environments.

```bash
fuplc simulate --protocol modbus --scenario plc-communication
```

Options:
- `--protocol`: Protocol to simulate
- `--scenario`: Simulation scenario

### report
Generate reports from assessment data.

```bash
fuplc report --input scan_results.json --format plain
```

Options:
- `--input`: Input data file
- `--format`: Output format (plain, json, xml)

### attack
Perform controlled attacks (lab-only, authorized use).

```bash
fuplc attack --target 192.168.1.100 --type modbus-write
```

Options:
- `--target`: Target IP
- `--type`: Attack type

## Modular Execution
Like Metasploit, commands can be chained or scripted:

```bash
fuplc discover --subnet 192.168.1.0/24 | fuplc scan --target -
```

Or use scripts for complex workflows.

## Wizard Mode
For guided assessments:

```bash
fuplc wizard
```

The wizard will:
1. Prompt for subnet discovery
2. Allow target selection or manual IP entry
3. Provide reconnaissance information
4. Guide through assessment steps

## Help System
- `fuplc --help`: Main help
- `fuplc <subcommand> --help`: Subcommand-specific help
- Man pages: `man fuplc`

## Error Handling
Errors are logged using standard conventions with colored output where supported:
- INFO: Blue
- WARNING: Yellow
- ERROR: Red
- DEBUG: Gray (when verbose)

## Configuration
A single configuration file at `~/.fuplc/config` allows setting defaults:

```ini
[default]
verbose = false
output_format = plain
interface = eth0
```

## Examples

### Basic Discovery
```bash
fuplc discover --subnet 192.168.1.0/24 --verbose
```

### Scanning a Target
```bash
fuplc scan --target 192.168.1.100 --protocol modbus
```

### Sniffing Traffic
```bash
fuplc sniff --interface eth0 --protocol opcua --filter "tcp port 4840"
```

### Generating a Report
```bash
fuplc report --input assessment_data.json --output report.txt
```

## Output Formats
Currently supports plain text. Future versions may add JSON and XML.

## Safety Notes
- All operations default to passive/read-only
- Active operations require explicit confirmation
- Use only in authorized environments
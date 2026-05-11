# `fuplc`

> Industrial Control System Security Assessment Framework
> Built for lab environments, defensive validation, protocol research, and authorized OT security testing.

---

## Overview

`fuplc` is an open-source OT/ICS security framework designed for:

* PLC security assessment
* industrial protocol analysis
* detection engineering
* network visibility
* lab-safe attack simulation
* OT research and education

The project focuses on **safe, controlled, and authorized** testing of industrial environments.

Unlike traditional offensive security frameworks, `fuplc` is designed to:

* help defenders understand industrial risk
* validate segmentation and monitoring
* improve OT visibility
* support blue team detection engineering
* emulate industrial traffic in lab environments

---

## Goals

* Provide OT-focused visibility and assessment tooling
* Create reproducible ICS security labs
* Improve industrial detection engineering
* Help engineers learn industrial protocol behavior
* Support research into industrial network security
* Bridge the gap between IT and OT security

---

# Features

## Industrial Asset Discovery

Enumerate and fingerprint:

* PLCs
* HMIs
* OPC UA servers
* industrial switches
* engineering workstations
* Modbus devices
* EtherNet/IP devices

---

## Protocol Analysis

Current protocol support:

* Modbus TCP
* OPC UA
* EtherNet/IP *(planned)*
* DNP3 *(planned)*
* BACnet *(planned)*

Capabilities:

* packet inspection
* protocol fingerprinting
* endpoint enumeration
* security policy inspection
* traffic baselining

---

## OPC UA Security Auditing

Detect:

* anonymous authentication enabled
* insecure security policies
* weak endpoint configurations
* expired or invalid certificates
* insecure token policies

---

## Detection Engineering

Generate:

* Zeek detection scripts
* Suricata rules
* Sigma detections
* IOC reports

Focused on:

* unauthorized write operations
* suspicious engineering activity
* scan behavior
* unusual polling patterns
* lateral movement into OT networks

---

## Lab Simulation

Includes:

* vulnerable PLC simulators
* fake HMI environments
* mock industrial traffic generators
* attack replay scenarios
* sample PCAP datasets

Designed for:

* home labs
* research
* training
* detection validation

---

## Reporting

Generate reports for:

* asset inventory
* insecure configurations
* exposed services
* segmentation gaps
* OT network topology
* Purdue model mapping

---

# Architecture

```text
fuplc/
├── scanner/        # OT asset discovery + enumeration
├── protocols/      # Protocol parsers and analyzers
├── detections/     # Zeek / Suricata / Sigma content
├── simulator/      # PLC + HMI lab simulation
├── reports/        # Report generation
├── pcaps/          # Sample packet captures
├── web/            # Dashboard API + frontend
├── docs/           # Architecture and lab guides
└── scripts/        # Utilities and helpers
```

---

# Tech Stack

## Backend

* Python
* FastAPI
* asyncio
* SQLAlchemy

## Data

* duckdb

## Network Analysis

* Scapy
* PyShark
* Zeek
* Suricata

## Infrastructure

* Docker
* Docker Compose

## Frontend *(planned)*

* React
* TailwindCSS

---

# Example Use Cases

## Asset Inventory

```bash
fuplc scan subnet 192.168.20.0/24
```

Enumerates industrial assets and fingerprints supported protocols.

---

## OPC UA Audit

```bash
fuplc opcua audit 192.168.20.15
```

Checks for:

* anonymous auth
* weak crypto
* insecure endpoints
* expired certificates

---

## Generate Detection Rules

```bash
fuplc detect generate modbus
```

Outputs:

* Zeek scripts
* Suricata signatures
* Sigma rules

---

## Replay Industrial Traffic

```bash
fuplc replay ./pcaps/modbus_attack.pcap
```

Useful for:

* IDS testing
* SOC training
* OT monitoring validation

---

# Home Lab Recommendations

Recommended environment:

* Kali Linux (Host OS) (Tested on this.)
* simulated PLCs
* OT DMZ architecture

---

# Safety & Legal Notice

`fuplc` is intended ONLY for:

* lab environments
* research
* training
* defensive security
* explicitly authorized testing

Industrial systems can control physical processes and critical infrastructure.

Unauthorized interaction with industrial equipment may:

* disrupt operations
* damage equipment
* create safety hazards, up to and including death.
* violate laws and regulations

Do NOT use this project against systems you do not own or explicitly have permission to assess.

---

# Roadmap

## Planned Features

* EtherNet/IP parser
* Purdue model visualization
* passive OT discovery mode
* industrial topology mapping
* anomaly detection engine
* AI-assisted alert correlation
* packet timeline visualization
* distributed sensor architecture

---

# Contributing

Contributions are welcome.

Areas of interest:

* protocol parsers
* detection engineering
* ICS packet analysis
* OT visualization
* lab simulation
* documentation
* PCAP datasets

---

# Disclaimer

This project is provided for educational and defensive purposes only.

The authors assume no liability for misuse or damages resulting from the use of this software.

# Scope of fuplc

## Overview
fuplc is an Industrial Control System Security Assessment Framework focused on reconnaissance for offensive security involving PLCs and industrial protocols. It emphasizes safe, controlled, and authorized testing in lab environments first, with potential expansion to active assessments.

## Core Functionalities
- Reconnaissance and discovery of industrial assets
- Protocol analysis and parsing
- Simulation of industrial traffic and environments
- Reporting and assessment generation
- Modular command-line tools for individual testing

## Supported Protocols
- Modbus
- DNP3
- OPC UA
- EtherNet/IP
- MQTT
- PROFINET
- IO-Link
- EtherCAT
- HTTP
- SSH

## Platforms
- Primary: Kali Linux
- Secondary: General Linux distributions

## Simulation vs. Real Network Analysis
The framework supports both:
- Simulation/emulation for lab environments
- Real network analysis for authorized testing

## Boundaries and Limitations
- Prioritizes lab-safe operations
- No unauthorized active exploitation
- Focus on defensive validation and educational purposes
- Gradual expansion from passive to active assessments as appropriate

## Goals Alignment
- Provide OT-focused visibility and assessment tooling
- Create reproducible ICS security labs
- Improve industrial detection engineering
- Support research into industrial network security
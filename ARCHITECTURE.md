# Architecture of fuplc

## Overview
fuplc is designed as a highly modular framework for OT/ICS security assessment, inspired by tools like nmap. It allows users to perform step-by-step assessments or modular scanning of industrial protocols and assets.

## Main Components
- **Discovery Module**: Enumerates and fingerprints industrial assets (PLCs, HMIs, OPC UA servers, etc.)
- **Protocol Sniff/Parse Module**: Captures, analyzes, and parses industrial protocol traffic
- **Simulation Engine**: Emulates industrial environments and traffic for lab testing
- **Reporting Module**: Generates assessment reports and visualizations
- **CLI Interface**: Command-line tools for user interaction

## Programming Languages and Frameworks
- **Primary Language**: Python (following snake_case conventions)
- **Scripting**: Bash for automation and integration
- **Frameworks**: Standard Python libraries, with potential use of asyncio for asynchronous operations, scapy for network manipulation

## Modularity
- Highly modular design allowing individual components to be tested and used separately
- Plugin-based architecture for extending protocol support and functionalities
- Commands designed to work modularly, similar to nmap scripts

## User Interfaces
- **Primary Interface**: Command-Line Interface (CLI)
- Potential for future web dashboard or API extensions

## Data Flow
1. **User Input**: Via CLI wizard or direct commands
2. **Discovery**: Scan and enumerate industrial assets
3. **Analysis**: Sniff and parse protocol traffic
4. **Simulation**: Generate or emulate traffic if needed
5. **Processing**: Analyze data for security insights
6. **Reporting**: Output results in structured formats

## Design Principles
- **Safety First**: Emphasis on lab environments and authorized testing
- **Extensibility**: Easy to add new protocols and modules
- **Reproducibility**: Consistent results for research and education
- **Performance**: Efficient for real-time analysis where possible
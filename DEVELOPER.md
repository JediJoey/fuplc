# Developer Guide

This document explains how to set up a development environment for `fuplc`, install the package locally, and run the CLI.

## Prerequisites

- Python 3.11 or later
- `pip` available for the chosen Python interpreter
- `virtualenv` or `venv` support
- `nmap` installed and available on `PATH`

## Recommended Setup

Use a virtual environment to avoid Kali system package restrictions and keep development dependencies isolated.

```bash
cd path/to/fuplc
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install -e .
```

If the environment is externally managed by the OS, do not install packages system-wide. Create and activate a virtual environment first.

## Running the CLI

After installation, run the CLI using the `fuplc` entrypoint:

```bash
fuplc discover --subnet 192.168.1.0/24
```

Common commands:

- `fuplc discover --subnet <subnet>`
- `fuplc scan --target <target>`
- `fuplc sniff --interface <iface> --protocol <protocol>`
- `fuplc simulate --protocol <protocol> --scenario <scenario>`
- `fuplc report --input <file> --format plain`
- `fuplc attack --target <target> --type <type>`
- `fuplc wizard`

## Kali Linux Notes

Kali may prevent editable installs in the base Python environment with an `externally-managed-environment` error.

If you encounter this error, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

If you must install in the system environment and understand the risk, you can override using:

```bash
python3 -m pip install --break-system-packages -e .
```

This repository does not recommend overriding system package management.

## Package Structure

- `cli/` — CLI entrypoint and command modules
- `README.md` — user-facing project overview
- `CLI.md` — CLI command documentation
- `ARCHITECTURE.md` — design and architecture notes
- `SCOPE.md` — project scope and supported protocols
- `DEVELOPER.md` — this developer setup guide

## Notes

- `nmap` is required for the `discover` command.
- The package is installed as editable with the `fuplc` console script.
- If the command is not found after install, confirm the virtual environment is activated or the installation succeeded.

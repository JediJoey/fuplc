"""fuplc CLI entrypoint."""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import sys

from .discover import run_discover_command
from .scan import run_scan_command

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.fuplc/config")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def load_config(config_path: str | None) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    path = config_path or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        config.read(path)
    return config


def parse_common_args(args: argparse.Namespace) -> dict[str, object]:
    return {
        "verbose": args.verbose,
        "output": args.output,
        "config": args.config,
    }


def run_discover(args: argparse.Namespace) -> int:
    logging.debug(f"discover args: {args}")
    return run_discover_command(subnet=args.subnet, protocol=args.protocol, verbose=args.verbose)


def run_scan(args: argparse.Namespace) -> int:
    logging.debug(f"scan args: {args}")
    return run_scan_command(ip=args.target, verbose=args.verbose)


def run_sniff(args: argparse.Namespace) -> int:
    logging.info("Running sniff")
    logging.debug(f"sniff args: {args}")
    return 0


def run_simulate(args: argparse.Namespace) -> int:
    logging.info("Running simulate")
    logging.debug(f"simulate args: {args}")
    return 0


def run_report(args: argparse.Namespace) -> int:
    logging.info("Running report")
    logging.debug(f"report args: {args}")
    return 0


def run_attack(args: argparse.Namespace) -> int:
    logging.info("Running attack")
    logging.debug(f"attack args: {args}")
    return 0


def run_wizard(args: argparse.Namespace) -> int:
    logging.info("Starting wizard")
    subnet = input("Enter subnet to discover [e.g. 192.168.1.0/24]: ")
    print(f"Selected subnet: {subnet}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuplc",
        description="Industrial Control System Security Assessment Framework",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity")
    parser.add_argument("-o", "--output", help="Specify output file")
    parser.add_argument("--config", help="Specify configuration file (default: ~/.fuplc/config)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Discover industrial assets on a network")
    discover.add_argument("--subnet", required=True, help="Network subnet to scan")
    discover.add_argument("--protocol", choices=["modbus", "opcua", "ethernetip", "dnp3", "bacnet"], help="Protocol to look for")
    discover.set_defaults(func=run_discover)

    scan = subparsers.add_parser("scan", help="Perform detailed scanning of a target")
    scan.add_argument("--target", required=True, help="IP address or hostname")
    scan.add_argument("--ports", help="Ports to scan")
    scan.add_argument("--protocol", choices=["modbus", "opcua", "ethernetip", "dnp3", "bacnet"], help="Protocol to use")
    scan.set_defaults(func=run_scan)

    sniff = subparsers.add_parser("sniff", help="Sniff and parse industrial protocol traffic")
    sniff.add_argument("--interface", required=True, help="Network interface")
    sniff.add_argument("--protocol", choices=["modbus", "opcua"], help="Protocol to sniff")
    sniff.add_argument("--filter", help="Additional packet filter")
    sniff.set_defaults(func=run_sniff)

    simulate = subparsers.add_parser("simulate", help="Simulate industrial traffic or environments")
    simulate.add_argument("--protocol", choices=["modbus", "opcua"], help="Protocol to simulate")
    simulate.add_argument("--scenario", help="Simulation scenario")
    simulate.set_defaults(func=run_simulate)

    report = subparsers.add_parser("report", help="Generate reports from assessment data")
    report.add_argument("--input", required=True, help="Input data file")
    report.add_argument("--format", choices=["plain", "json", "xml"], default="plain", help="Output format")
    report.set_defaults(func=run_report)

    attack = subparsers.add_parser("attack", help="Perform controlled attacks (lab-only, authorized use)")
    attack.add_argument("--target", required=True, help="Target IP")
    attack.add_argument("--type", required=True, help="Attack type")
    attack.set_defaults(func=run_attack)

    wizard = subparsers.add_parser("wizard", help="Run guided assessment wizard")
    wizard.set_defaults(func=run_wizard)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    config = load_config(args.config)
    logging.debug(f"Loaded config sections: {config.sections()}")

    result = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

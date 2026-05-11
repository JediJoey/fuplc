"""Discover industrial hosts using nmap."""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

INDUSTRIAL_PORTS: dict[str, int | list[int]] = {
    # =========================
    # ICS / SCADA Protocols
    # =========================
    "modbus_tcp": 502,
    "modbus_udp": 502,

    "opcua": 4840,
    "opcua_https": 443,

    "ethernetip": 44818,
    "cip_udp": 2222,

    "profinet_dcp": 34964,
    "profinet_rpc": 34962,
    "profinet_rt": 34963,
    "profinet_io": 34964,

    "siemens_s7": 102,
    "siemens_step7": 102,

    "dnp3_tcp": 20000,
    "dnp3_udp": 20000,

    "bacnet": 47808,
    "bacnet_ipv6": 47809,

    "iec104": 2404,
    "iec101": 2404,

    "iec61850_mms": 102,
    "goose": 102,
    "sv": 102,

    "hart_ip": 5094,

    "fox": 1911,
    "tridium_fox": 1911,

    "codesys_gateway": 1217,
    "codesys_runtime": 2455,

    "omron_fins": 9600,
    "mitsubishi_mc": 5000,
    "mitsubishi_slmp": 5001,

    "fanuc_focas": 8193,
    "fanuc_hssb": 8193,

    "ge_srtp": 18245,

    "beckhoff_ads": 48898,

    "sel_fast_message": 2641,

    "crimson_redlion": 789,

    "pcworx": 1962,
    "interbus": 1962,

    "ethercat": 34980,

    "powerlink": 3819,

    "melsec_q": 5006,

    "wago": 2455,

    "kepware": 49320,

    "ifix_scada": 514,

    "wonderware_suitevoyager": 5413,

    "clearscada": 5481,

    "igss": 12401,

    "indusoft_webstudio": 1234,

    "webaccess": 4592,

    "citect_scada": 20222,

    "movicon": 5343,

    "vt_scada": 3101,

    # =========================
    # Building Automation
    # =========================
    "lonworks": 1628,
    "knx": 3671,
    "enip_bacnet_bridge": 47808,

    # =========================
    # Energy / Utility
    # =========================
    "iec61850": 102,
    "iccps_tase2": 102,
    "opc_hda": 135,

    # =========================
    # OT Infrastructure
    # =========================
    "snmp": 161,
    "snmp_trap": 162,

    "ntp": 123,
    "syslog": 514,

    "mqtt": 1883,
    "mqtt_tls": 8883,

    "amqp": 5672,
    "amqp_tls": 5671,

    "coap": 5683,
    "coaps": 5684,

    "radius": 1812,
    "radius_accounting": 1813,

    "ldap": 389,
    "ldaps": 636,

    "dns": 53,
    "dhcp_server": 67,
    "dhcp_client": 68,

    "ftp": 21,
    "ftps": 990,
    "sftp": 22,
    "tftp": 69,

    "http": 80,
    "https": 443,

    "ssh": 22,
    "telnet": 23,

    "rdp": 3389,
    "vnc": 5900,

    "winrm_http": 5985,
    "winrm_https": 5986,

    "smb": 445,
    "netbios_ns": 137,
    "netbios_dgm": 138,
    "netbios_ssn": 139,

    "postgresql": 5432,
    "mysql": 3306,
    "mssql": 1433,
    "oracle": 1521,

    "redis": 6379,
    "mongodb": 27017,

    "docker_api": 2375,
    "docker_tls": 2376,

    "kubernetes_api": 6443,

    "grafana": 3000,
    "prometheus": 9090,
    "influxdb": 8086,

    # =========================
    # Common VPN / Firewall
    # =========================
    "openvpn": 1194,
    "wireguard": 51820,
    "ipsec_ike": 500,
    "ipsec_nat_t": 4500,

    # =========================
    # Industrial Vendor-Specific
    # =========================
    "rockwell_factorytalk": 4241,
    "rockwell_rslinx": 2221,

    "schneider_umas": 502,
    "schneider_modicon": 502,

    "abb_robotstudio": 5510,

    "yokogawa_stardom": 10001,

    "honeywell_experion": 51111,

    "emerson_deltav": 18507,

    "ge_proficy": 18245,

    "aveva": 5413,

    # =========================
    # Discovery / Broadcast
    # =========================
    "mdns": 5353,
    "ssdp": 1900,
    "llmnr": 5355,

    # =========================
    # Multi-port services
    # =========================
    "ephemeral_windows": [49152, 65535],
    "ephemeral_linux": [32768, 60999],
}

def _normalize_ports(value: int | list[int]) -> list[int]:
    return list(value) if isinstance(value, list) else [value]


DEFAULT_PORT_LIST = sorted(
    {port for value in INDUSTRIAL_PORTS.values() for port in _normalize_ports(value)}
)


class NmapDiscoveryError(RuntimeError):
    pass


def _check_nmap_installed() -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise NmapDiscoveryError("nmap is not installed or not on PATH")
    return nmap_path


def _run_nmap(args: list[str], verbose: bool = False, show_progress: bool = False) -> str:
    command = args.copy()
    if show_progress:
        command = [command[0], "-v", "--stats-every", "5s", *command[1:]]

    if verbose:
        logging.debug("Running nmap: %s", " ".join(command))

    if not show_progress:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if process.returncode != 0:
            raise NmapDiscoveryError(
                f"nmap scan failed with code {process.returncode}: {process.stderr.strip()}"
            )

        return process.stdout

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert process.stderr is not None
    assert process.stdout is not None

    stderr_lines: list[str] = []
    for line in process.stderr:
        stderr_lines.append(line)
        sys.stderr.write(line)
        sys.stderr.flush()

    stdout, _ = process.communicate()
    if process.returncode != 0:
        raise NmapDiscoveryError(
            f"nmap scan failed with code {process.returncode}: {''.join(stderr_lines).strip()}"
        )

    return stdout


def _parse_live_hosts(xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address_elem = host.find("address")
        if address_elem is None:
            continue

        address = address_elem.get("addr")
        if not address:
            continue

        hostnames = [
            hostname.get("name")
            for hostname in host.findall("hostnames/hostname")
            if hostname.get("name")
        ]

        hosts.append({"address": address, "hostnames": hostnames})

    return hosts


def _parse_service_scan(xml_text: str) -> dict[str, list[dict[str, Any]]]:
    root = ET.fromstring(xml_text)
    services_by_host: dict[str, list[dict[str, Any]]] = {}

    for host in root.findall("host"):
        address_elem = host.find("address")
        if address_elem is None:
            continue

        address = address_elem.get("addr")
        if not address:
            continue

        services: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            service_name = service.get("name") if service is not None else None
            reason = port.find("reason")
            services.append(
                {
                    "port": f"{port.get('portid')}/{port.get('protocol')}",
                    "name": service_name or "unknown",
                    "product": service.get("product") if service is not None else None,
                    "reason": reason.get("reason") if reason is not None else None,
                }
            )

        if services:
            services_by_host[address] = services

    return services_by_host


def _port_list_for_protocol(protocol: str | None) -> list[int]:
    if protocol is None:
        return DEFAULT_PORT_LIST

    value = INDUSTRIAL_PORTS.get(protocol.lower())
    if value is None:
        raise ValueError(f"Unsupported protocol: {protocol}")

    ports = _normalize_ports(value)
    return sorted(set(ports))


def _service_description(services: list[dict[str, Any]]) -> str:
    descriptions = []
    for entry in services:
        name = entry.get("name") or "unknown"
        port = entry.get("port")
        descriptions.append(f"{name} ({port})")
    return ", ".join(descriptions)


def discover_subnet(subnet: str, protocol: str | None = None, verbose: bool = False) -> list[dict[str, Any]]:
    nmap_path = _check_nmap_installed()
    logging.info("Discovering hosts on %s", subnet)

    print(f"Scanning subnet {subnet} for live hosts...")
    host_discovery_output = _run_nmap([nmap_path, "-sn", "-oX", "-", subnet], verbose=verbose, show_progress=True)
    live_hosts = _parse_live_hosts(host_discovery_output)

    if not live_hosts:
        return []

    ports = _port_list_for_protocol(protocol)
    port_arg = ",".join(str(port) for port in ports)
    host_addresses = [host["address"] for host in live_hosts]

    print(f"Scanning {len(host_addresses)} live host(s) for open industrial ports...")
    service_scan_output = _run_nmap(
        [nmap_path, "-sV", "-p", port_arg, "-oX", "-", "-T4", *host_addresses],
        verbose=verbose,
        show_progress=True,
    )
    services_by_host = _parse_service_scan(service_scan_output)

    results: list[dict[str, Any]] = []
    for host in live_hosts:
        address = host["address"]
        results.append(
            {
                "address": address,
                "hostnames": host["hostnames"],
                "services": services_by_host.get(address, []),
            }
        )

    return results


def _open_ports_description(services: list[dict[str, Any]]) -> str:
    ports = [entry.get("port") for entry in services if entry.get("port")]
    return ", ".join(ports)


def format_discovery_result(host: dict[str, Any]) -> str:
    hostnames = host["hostnames"]
    services = host["services"]

    parts: list[str] = [host["address"]]

    if hostnames:
        parts.append(f"({', '.join(hostnames)})")

    if services:
        open_ports = _open_ports_description(services)
        if open_ports:
            parts.append(f"[{open_ports}]")
        service_line = _service_description(services)
    else:
        service_line = "No industrial services detected"

    return f"{' '.join(parts)}: {service_line}"


def run_discover_command(subnet: str, protocol: str | None = None, verbose: bool = False) -> int:
    try:
        results = discover_subnet(subnet=subnet, protocol=protocol, verbose=verbose)
    except NmapDiscoveryError as exc:
        logging.error(str(exc))
        return 1
    except ValueError as exc:
        logging.error(str(exc))
        return 1

    if not results:
        print(f"No hosts found on {subnet}")
        return 0

    for host in results:
        print(format_discovery_result(host))

    return 0

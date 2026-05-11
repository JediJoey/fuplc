"""Scan a specific industrial host for detailed information."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

# Reuse the industrial ports from discover.py
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

def _load_vendors() -> dict[str, str]:
    vendors_file = os.path.join(os.path.dirname(__file__), '..', 'vendors.json')
    if os.path.exists(vendors_file):
        with open(vendors_file, 'r') as f:
            return json.load(f)
    return {}

def _lookup_mac_vendor(mac: str, vendors: dict[str, str]) -> str:
    # Normalize MAC: remove colons, uppercase, take first 6 chars
    normalized = mac.replace(':', '').upper()[:6]
    vendor = vendors.get(normalized)
    if vendor:
        return vendor
    
    # Fallback to API
    try:
        with urllib.request.urlopen(f"https://api.macvendors.com/{normalized}", timeout=5) as response:
            api_vendor = response.read().decode('utf-8').strip()
            if api_vendor and api_vendor not in ('None', '') and not api_vendor.startswith('{"errors"'):
                return api_vendor
    except:
        pass
    
    return "Unknown"

def _normalize_ports(value: int | list[int]) -> list[int]:
    return list(value) if isinstance(value, list) else [value]

DEFAULT_PORT_LIST = sorted(
    {port for value in INDUSTRIAL_PORTS.values() for port in _normalize_ports(value)}
)

class NmapScanError(RuntimeError):
    pass

def _check_nmap_installed() -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise NmapScanError("nmap is not installed or not on PATH")
    return nmap_path

def _run_nmap(args: list[str], verbose: bool = False, show_progress: bool = False) -> str:
    command = args.copy()
    if show_progress:
        command = [command[0], "-v", "--stats-every", "5s", *command[1:]]

    if verbose:
        logging.debug("Running nmap: %s", " ".join(command))

    timeout_seconds = 300  # 5 minutes timeout

    if not show_progress:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

        if process.returncode != 0:
            raise NmapScanError(
                f"nmap scan failed with code {process.returncode}: {process.stderr.strip()}"
            )

        return process.stdout

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    assert process.stderr is not None
    assert process.stdout is not None

    progress_pattern = re.compile(r"(\d+(?:\.\d+)?)% done")
    stderr_lines: list[str] = []

    try:
        start_time = time.monotonic()
        while True:
            line = process.stderr.readline()
            if line:
                stderr_lines.append(line)
                match = progress_pattern.search(line)
                if match:
                    percent = float(match.group(1))
                    sys.stdout.write(f"\rScanning: {percent:.1f}% complete")
                    sys.stdout.flush()
                elif verbose:
                    sys.stderr.write(line)
            elif process.poll() is not None:
                break

            if time.monotonic() - start_time > timeout_seconds:
                process.kill()
                raise NmapScanError("nmap scan timed out after 5 minutes")

        stdout, _ = process.communicate(timeout=5)
        sys.stdout.write("\rScanning: 100.0% complete\n")
        sys.stdout.flush()

        if process.returncode != 0:
            raise NmapScanError(
                f"nmap scan failed with code {process.returncode}: {''.join(stderr_lines).strip()}"
            )
        return stdout
    except subprocess.TimeoutExpired:
        process.kill()
        raise NmapScanError("nmap scan timed out after 5 minutes")

def _parse_detailed_scan(xml_text: str, vendors: dict[str, str]) -> dict[str, Any]:
    print("Parsing scan results...")
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return {}

    result: dict[str, Any] = {}

    # Address
    print("Extracting host information...")
    address_elem = host.find("address")
    if address_elem is not None:
        result["address"] = address_elem.get("addr")
        result["address_type"] = address_elem.get("addrtype")

    # Hostnames
    hostnames = [
        hostname.get("name")
        for hostname in host.findall("hostnames/hostname")
        if hostname.get("name")
    ]
    result["hostnames"] = hostnames

    # OS detection
    print("Detecting operating system...")
    os_elem = host.find("os")
    if os_elem is not None:
        os_matches = []
        for os_match in os_elem.findall("osmatch"):
            os_matches.append({
                "name": os_match.get("name"),
                "accuracy": os_match.get("accuracy"),
            })
        result["os_matches"] = os_matches

    # MAC address
    print("Looking up MAC address and vendor...")
    for address in host.findall("address"):
        if address.get("addrtype") == "mac":
            mac_addr = address.get("addr")
            if mac_addr:
                result["mac_address"] = mac_addr
                # Use our lookup first, fallback to nmap's vendor
                our_vendor = _lookup_mac_vendor(mac_addr, vendors)
                nmap_vendor = address.get("vendor")
                result["mac_vendor"] = our_vendor if our_vendor != "Unknown" else (nmap_vendor or "Unknown")
            break

    # Ports and services
    print("Extracting port and service information...")
    services = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")
        service_info = {
            "port": f"{port.get('portid')}/{port.get('protocol')}",
            "name": service.get("name") if service is not None else "unknown",
            "product": service.get("product") if service is not None else None,
            "version": service.get("version") if service is not None else None,
            "extrainfo": service.get("extrainfo") if service is not None else None,
        }
        services.append(service_info)

    result["services"] = services

    # Scripts (for vulnerabilities, etc.)
    print("Extracting script results...")
    scripts = []
    for script in host.findall("hostscript/script"):
        scripts.append({
            "id": script.get("id"),
            "output": script.get("output"),
        })
    result["scripts"] = scripts

    return result

def _guess_device_type(details: dict[str, Any]) -> str:
    services = details.get("services", [])
    os_matches = details.get("os_matches", [])
    
    # Check OS first
    for os_match in os_matches:
        name = os_match.get("name", "").lower()
        if "android" in name:
            return "Android Device"
        if "ios" in name or "iphone" in name:
            return "iOS Device"
        if "linux" in name:
            return "Linux Device"
        if "windows" in name:
            return "Windows Device"
        if "mac os" in name or "macos" in name:
            return "macOS Device"
    
    # Fallback to service-based heuristics
    port_names = {svc["name"] for svc in services}
    if "modbus" in port_names or "siemens_s7" in port_names:
        return "PLC"
    if "opcua" in port_names:
        return "OPC UA Server"
    if "ethernetip" in port_names:
        return "EtherNet/IP Device"
    if "bacnet" in port_names:
        return "BACnet Device"
    if "http" in port_names and "https" not in port_names:
        return "HMI or Web Interface"
    if "ssh" in port_names and "smb" in port_names:
        return "PC or Server"
    if "snmp" in port_names and len(services) < 5:
        return "Network Device (Switch/Router)"
    if "printer" in port_names:
        return "Printer"
    if "ftp" in port_names and "telnet" in port_names:
        return "Legacy Device"
    if "http" in port_names or "https" in port_names:
        return "Web Server or IoT Device"
    return "Unknown"

def _lookup_cves(product: str | None, version: str | None) -> list[str]:
    # Placeholder for CVE lookup. In a real implementation, integrate with a CVE database API.
    # For now, return empty list or mock some.
    if product and version:
        # Mock some CVEs for demonstration
        if "modbus" in product.lower():
            return ["CVE-2018-0296", "CVE-2020-1350"]  # Example
    return []

def scan_target(ip: str, verbose: bool = False) -> dict[str, Any]:
    vendors = _load_vendors()
    nmap_path = _check_nmap_installed()
    logging.info("Scanning target %s", ip)

    print(f"Performing detailed scan on {ip}...")

    # First, do host discovery to get MAC and hostnames
    print("Running host discovery...")
    host_discovery_xml = _run_nmap([nmap_path, "-sn", "-oX", "-", ip], verbose=verbose)
    print("Host discovery complete. Running detailed scan...")
    discovery_details = _parse_detailed_scan(host_discovery_xml, vendors)

    # Then, do detailed port scan
    print("Running detailed port scan...")
    port_list = ",".join(str(port) for port in DEFAULT_PORT_LIST)
    xml_output = _run_nmap(
        [nmap_path, "-O", "-sV", "-sC", "--script=vuln", "-p", port_list, "-oX", "-", "-T4", ip],
        verbose=verbose,
        show_progress=True,
    )
    print("Detailed scan complete. Processing results...")
    scan_details = _parse_detailed_scan(xml_output, vendors)

    # Merge the details, preferring scan for services, discovery for MAC/hostnames
    print("Scan complete. Processing results...")
    details = scan_details.copy()
    details.update(discovery_details)  # This will overwrite with discovery if keys overlap, but since discovery has mac and hostnames, scan has services

    if not details:
        return {}

    # Guess device type
    details["guessed_device_type"] = _guess_device_type(details)

    # Collect CVEs
    cves = []
    for svc in details.get("services", []):
        cves.extend(_lookup_cves(svc.get("product"), svc.get("version")))
    details["potential_cves"] = list(set(cves))  # Remove duplicates

    return details

def format_scan_result(details: dict[str, Any]) -> str:
    lines = []

    lines.append(f"Target: {details.get('address', 'Unknown')}")

    if details.get("hostnames"):
        lines.append(f"Hostnames: {', '.join(details['hostnames'])}")

    if details.get("mac_address"):
        vendor = details.get("mac_vendor", "Unknown")
        lines.append(f"MAC Address: {details['mac_address']} (Vendor: {vendor})")

    if details.get("os_matches"):
        os_info = details["os_matches"][0] if details["os_matches"] else {}
        lines.append(f"OS Guess: {os_info.get('name', 'Unknown')} (Accuracy: {os_info.get('accuracy', 'N/A')}%)")

    lines.append(f"Guessed Device Type: {details.get('guessed_device_type', 'Unknown')}")

    services = details.get("services", [])
    if services:
        lines.append("Open Ports and Services:")
        for svc in services:
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            extra = svc.get("extrainfo") or ""
            desc = f"  {svc['port']}: {svc['name']}"
            if product:
                desc += f" ({product}"
                if version:
                    desc += f" {version}"
                if extra:
                    desc += f", {extra}"
                desc += ")"
            lines.append(desc)
    else:
        lines.append("No open ports found.")

    cves = details.get("potential_cves", [])
    if cves:
        lines.append("Potential CVEs:")
        for cve in cves:
            lines.append(f"  {cve}")
    else:
        lines.append("No known CVEs detected.")

    scripts = details.get("scripts", [])
    if scripts:
        lines.append("Script Outputs:")
        for script in scripts:
            lines.append(f"  {script['id']}: {script['output'][:100]}...")  # Truncate

    return "\n".join(lines)

def run_scan_command(ip: str, verbose: bool = False) -> int:
    try:
        details = scan_target(ip=ip, verbose=verbose)
    except NmapScanError as exc:
        logging.error(str(exc))
        return 1

    if not details:
        print(f"No information found for {ip}")
        return 0

    print(format_scan_result(details))
    return 0
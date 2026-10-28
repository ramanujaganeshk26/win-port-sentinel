import subprocess
from typing import Dict, List, Optional, Tuple, NamedTuple

class PortBinding(NamedTuple):
    proto: str
    local_address: str
    local_port: int
    foreign_address: str
    foreign_port: int
    state: str
    pid: int
    process_name: str = "Unknown"

def _split_host_port(address_str: str) -> Tuple[str, str]:
    if ":" in address_str:
        idx = address_str.rfind(":")
        return address_str[:idx], address_str[idx+1:]
    return address_str, "0"

def parse_netstat(output: str) -> List[dict]:
    records = []
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        local_addr = parts[1]
        foreign_addr = parts[2]
        if proto == "TCP":
            if len(parts) < 5:
                continue
            state = parts[3].upper()
            try:
                pid = int(parts[4])
            except ValueError:
                continue
        else:
            state = "N/A"
            try:
                pid = int(parts[3])
            except ValueError:
                continue

        local_host, local_port_str = _split_host_port(local_addr)
        foreign_host, foreign_port_str = _split_host_port(foreign_addr)

        try:
            l_port = int(local_port_str)
        except ValueError:
            l_port = 0

        try:
            f_port = int(foreign_port_str)
        except ValueError:
            f_port = 0

        records.append({
            "proto": proto,
            "local_address": local_addr,
            "local_host": local_host,
            "local_port": l_port,
            "foreign_address": foreign_addr,
            "foreign_host": foreign_host,
            "foreign_port": f_port,
            "state": state,
            "pid": pid,
        })
    return records

def parse_tasklist(output: str) -> Dict[int, str]:
    pid_map = {}
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2:
            name = parts[0].strip('"')
            pid_str = parts[1].strip('"')
            try:
                pid = int(pid_str)
                pid_map[pid] = name
            except ValueError:
                continue
    return pid_map

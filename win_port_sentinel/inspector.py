import socket
import subprocess
import time
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
            name = parts[0]
            pid_str = parts[1]
            try:
                pid = int(pid_str)
                pid_map[pid] = name
            except ValueError:
                continue
    return pid_map

def get_active_bindings(netstat_out: Optional[str] = None, tasklist_out: Optional[str] = None) -> List[PortBinding]:
    if netstat_out is None:
        try:
            netstat_out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
        except (subprocess.SubprocessError, FileNotFoundError):
            netstat_out = ""

    if tasklist_out is None:
        try:
            tasklist_out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, errors="replace")
        except (subprocess.SubprocessError, FileNotFoundError):
            tasklist_out = ""

    raw_records = parse_netstat(netstat_out)
    pid_map = parse_tasklist(tasklist_out)

    bindings = []
    for r in raw_records:
        proc_name = pid_map.get(r["pid"], "Unknown")
        bindings.append(PortBinding(
            proto=r["proto"],
            local_address=r["local_address"],
            local_port=r["local_port"],
            foreign_address=r["foreign_address"],
            foreign_port=r["foreign_port"],
            state=r["state"],
            pid=r["pid"],
            process_name=proc_name
        ))
    return bindings

def detect_conflicts(bindings: List[PortBinding]) -> List[Dict]:
    port_map: Dict[Tuple[str, int], List[PortBinding]] = {}
    for b in bindings:
        if b.state in ("LISTENING", "N/A"):
            key = (b.proto, b.local_port)
            port_map.setdefault(key, []).append(b)

    conflicts = []
    for (proto, port), b_list in port_map.items():
        if port == 0:
            continue
        unique_pids = {b.pid for b in b_list}
        if len(unique_pids) > 1:
            conflicts.append({
                "proto": proto,
                "port": port,
                "reason": "Multiple PIDs bound to same port",
                "bindings": [
                    {"pid": b.pid, "process": b.process_name, "address": b.local_address}
                    for b in b_list
                ]
            })
        elif len(b_list) > 1:
            addresses = [b.local_address for b in b_list]
            if "0.0.0.0:" + str(port) in addresses or "[::]:" + str(port) in addresses:
                conflicts.append({
                    "proto": proto,
                    "port": port,
                    "reason": "Wildcard port overlap with specific address",
                    "bindings": [
                        {"pid": b.pid, "process": b.process_name, "address": b.local_address}
                        for b in b_list
                    ]
                })
    return conflicts

def test_connectivity(host: str, port: int, timeout: float = 2.0) -> Dict:
    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "latency_ms": None,
        "error": None
    }
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        elapsed = (time.perf_counter() - start) * 1000
        result["reachable"] = True
        result["latency_ms"] = round(elapsed, 2)
    except Exception as e:
        result["error"] = str(e)
    finally:
        sock.close()
    return result

import argparse
import json
import sys
from win_port_sentinel.inspector import (
    get_active_bindings,
    detect_conflicts,
    test_connectivity,
)

def main():
    parser = argparse.ArgumentParser(
        prog="win-port-sentinel",
        description="Windows Network Port and Process Inspector"
    )
    parser.add_argument(
        "--list", "-l", action="store_true", help="List active listening ports and processes"
    )
    parser.add_argument(
        "--proto", choices=["TCP", "UDP", "ALL"], default="ALL", help="Filter by protocol"
    )
    parser.add_argument(
        "--conflicts", "-c", action="store_true", help="Detect potential port conflicts"
    )
    parser.add_argument(
        "--test", "-t", metavar="HOST:PORT", help="Test TCP connectivity to HOST:PORT"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )

    args = parser.parse_args()

    if not args.list and not args.conflicts and not args.test:
        args.list = True

    if args.test:
        if ":" not in args.test:
            print("Error: --test format must be HOST:PORT (e.g., 127.0.0.1:8080)", file=sys.stderr)
            sys.exit(1)
        host, port_str = args.test.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port number '{port_str}'", file=sys.stderr)
            sys.exit(1)

        res = test_connectivity(host, port)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            status = "REACHABLE" if res["reachable"] else "UNREACHABLE"
            latency = f" ({res['latency_ms']} ms)" if res["latency_ms"] else ""
            err = f" - Error: {res['error']}" if res["error"] else ""
            print(f"[{status}] {host}:{port}{latency}{err}")
        return

    bindings = get_active_bindings()

    if args.proto != "ALL":
        bindings = [b for b in bindings if b.proto == args.proto]

    if args.conflicts:
        conflicts = detect_conflicts(bindings)
        if args.json:
            print(json.dumps(conflicts, indent=2))
        else:
            if not conflicts:
                print("No port conflicts detected.")
            else:
                print(f"Found {len(conflicts)} potential conflict(s):\n")
                for c in conflicts:
                    print(f"[{c['proto']}] Port {c['port']} - {c['reason']}:")
                    for b in c["bindings"]:
                        print(f"  - PID {b['pid']} ({b['process']}) on {b['address']}")
                    print()
        return

    if args.list:
        listening_only = [b for b in bindings if b.state in ("LISTENING", "N/A")]
        if args.json:
            out = [
                {
                    "proto": b.proto,
                    "local_address": b.local_address,
                    "local_port": b.local_port,
                    "state": b.state,
                    "pid": b.pid,
                    "process": b.process_name,
                }
                for b in listening_only
            ]
            print(json.dumps(out, indent=2))
        else:
            fmt = "{:<6} {:<24} {:<12} {:<8} {:<20}"
            print(fmt.format("PROTO", "LOCAL ADDRESS", "STATE", "PID", "PROCESS NAME"))
            print("-" * 72)
            for b in listening_only:
                print(fmt.format(b.proto, b.local_address, b.state, str(b.pid), b.process_name))

if __name__ == "__main__":
    main()

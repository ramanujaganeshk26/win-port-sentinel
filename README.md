# win-port-sentinel

A lightweight, zero-dependency Windows network port and process inspector built with the Python 3 standard library.

## Features

- **Port Inspection**: List active TCP listening ports and UDP bindings mapped directly to process names and PIDs.
- **Conflict Detection**: Identify port collisions where multiple processes attempt to bind or listen on overlapping local ports.
- **Socket Connectivity Test**: Test local or remote TCP socket reachability and response latency.
- **JSON Output**: Output raw data in JSON format for easy scripting and automation integration.

## Usage

### List Active Listening Ports
```bash
python -m win_port_sentinel --list
```

### Detect Port Conflicts
```bash
python -m win_port_sentinel --conflicts
```

### Test TCP Socket Connectivity
```bash
python -m win_port_sentinel --test 127.0.0.1:8080
```

### JSON Output
```bash
python -m win_port_sentinel --list --json
```

## Running Tests

```bash
python -m unittest discover -s tests
```

# StackAtClose Voltage Analyzer

**Version**: 1.0.6

A cross-platform GUI tool for analyzing voltage measurements from stackAtClose diagnostic traces captured in pcap files.

## Features

- Interactive voltage vs. time visualization with pan/zoom
- Fast loading of large pcap files (400MB+ / 5M+ packets)
- Detailed packet inspection with hex dumps
- VLAN deduplication support
- Handles encapsulated packets (Dot1Q, ethertype 0x9102)
- Recent files menu
- Auto-dependency installation

## Quick Start

### Standalone Version (Recommended)

Auto-installs dependencies on first run:

```bash
python3 StackAtCloseAnalyzer.py [pcap_file]
```

### Development Version

```bash
./install.sh && ./run.sh
```

## Usage

### Loading Files

- **File → Load Pcap** (Ctrl+O) to open a pcap file
- **File → Recent Files** for quick access to previously loaded files

### Controls

- **Mouse drag**: Pan the graph
- **Mouse scroll**: Zoom
- **Autoscale buttons**: Reset axes
- **Arrow keys**: Navigate packet list

### Packet List

- Click any packet to view details and hex dump
- Header bytes (0-7) highlighted in yellow

## Packet Format Specification

### Transport

| Parameter | Value |
|-----------|-------|
| Protocol | UDP |
| Multicast Address | 239.255.42.99 |
| Port | 6577 |
| Transmission Rate | Cyclic |

### Packet Structure

```
+------------------+------------------+----------------------------------+
| current_index    | max_values       | Voltage Data                     |
| (4 bytes, LE)    | (4 bytes, LE)    | (N × 4 bytes, LE uint32_t each)  |
+------------------+------------------+----------------------------------+
| Offset 0-3       | Offset 4-7       | Offset 8+                        |
```

### Header Fields

| Field | Offset | Size | Endianness | Description |
|-------|--------|------|------------|-------------|
| `current_index` | 0 | 4 bytes | Little-endian | Index of first voltage sample in this packet |
| `max_values` | 4 | 4 bytes | Little-endian | Total number of samples in trace buffer |

### Payload

- **Content**: Voltage measurements as `uint32_t` array
- **Endianness**: Little-endian
- **Max samples per packet**: ~126 (504 bytes ÷ 4 bytes/sample)
- **Voltage range**: Typically 6000-13000 mV (6V to 13V)

### Fragmentation

Large trace buffers are fragmented across multiple UDP packets:
- Each packet contains up to ~504 bytes of voltage data
- `current_index` indicates where this packet's data belongs in the full trace
- Receiver reassembles by placing data at the correct offset

### Example

```
Packet 1: current_index=0,   max_values=1024, voltages[0..125]
Packet 2: current_index=126, max_values=1024, voltages[126..251]
Packet 3: current_index=252, max_values=1024, voltages[252..377]
...
```

## Requirements

- Python 3.8+
- matplotlib >= 3.7.0
- numpy >= 1.24.0

## Building Standalone Executable

The GitHub Actions workflow automatically builds executables for:
- Linux x64
- Windows x64
- macOS x64

Each release package contains:
- Platform executable
- `StackAtCloseAnalyzer.py` (source for manual running)
- `README.md`

## License

MIT License

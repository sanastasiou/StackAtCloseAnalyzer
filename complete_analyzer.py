#!/usr/bin/env python3
"""
Complete StackAtClose Voltage Analyzer - Standalone GUI
Combines interactive voltage graph with packet inspection and marker analysis.
"""

__version__ = "1.0.6"

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import mmap
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import numpy as np
import os


class ProgressDialog:
    """Reusable progress dialog with multiple steps."""
    def __init__(self, parent, title="Processing"):
        self.parent = parent
        self.win = tk.Toplevel(parent)
        self.win.title(title)
        self.win.geometry("450x150")
        self.win.transient(parent)
        self.win.grab_set()
        self.win.geometry(f"+{parent.winfo_x() + 150}+{parent.winfo_y() + 200}")

        self.step_label = tk.Label(self.win, text="", font=('Arial', 11, 'bold'))
        self.step_label.pack(pady=(15, 5))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.win, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.pack(pady=5, padx=20)

        self.detail_label = tk.Label(self.win, text="", font=('Arial', 9))
        self.detail_label.pack(pady=5)

        self.parent.update()

    def set_step(self, step_name):
        self.step_label.config(text=step_name)
        self.progress_var.set(0)
        self.detail_label.config(text="")
        self.parent.update()

    def update(self, percent, detail=""):
        self.progress_var.set(min(100, percent))
        if detail:
            self.detail_label.config(text=detail)
        self.parent.update()

    def close(self):
        self.win.destroy()


class CompleteAnalyzer:
    def __init__(self, root, pcap_file=None):
        self.root = root
        self.root.title("Complete StackAtClose Analyzer")
        self.root.geometry("1800x1000")

        # Data storage
        self.pcap_file = pcap_file
        self.packets = []
        self.voltage_timeseries = []

        # Graph state
        self.highlight_artist = None  # For fast packet selection updates
        self.graph_needs_full_redraw = True

        # Recent files
        self.recent_files = self.load_recent_files()
        self.recent_menu = None

        # Create UI first
        self.create_widgets()

        # Load initial file if provided
        if pcap_file and os.path.exists(pcap_file):
            self.load_pcap_file(pcap_file)

    def _extract_udp_payload_from_raw(self, raw_bytes):
        """
        Extract UDP payload for port 6577 from raw packet bytes.
        Handles VLAN-tagged packets and other encapsulations by searching
        for the UDP destination port directly in raw bytes.

        Validates the packet structure to avoid false positives.

        Returns (payload, vlan_id) or (None, None) if not found.
        """
        # UDP destination port 6577 in network byte order (big-endian)
        PORT_6577_BE = b'\x19\xb1'

        # Search for all occurrences of the port pattern
        search_start = 0
        while True:
            port_pos = raw_bytes.find(PORT_6577_BE, search_start)
            if port_pos == -1:
                return None, None

            # UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes
            # dst_port is at offset 2, so UDP header starts at port_pos - 2
            udp_start = port_pos - 2
            if udp_start < 20:  # Need at least 20 bytes for IP header before UDP
                search_start = port_pos + 1
                continue

            # Validate: Check for IPv4 header before UDP
            # IPv4 header is typically 20 bytes, starts with 0x45 (version 4, IHL 5)
            # Protocol field at offset 9 should be 17 (UDP)
            # Look backwards for IPv4 header signature
            ip_header_found = False
            for ip_offset in range(udp_start - 20, max(-1, udp_start - 60), -1):
                if ip_offset < 0:
                    break
                # Check for IPv4 version (4) in high nibble
                if (raw_bytes[ip_offset] & 0xF0) == 0x40:
                    ihl = (raw_bytes[ip_offset] & 0x0F) * 4  # Header length in bytes
                    if ihl >= 20 and ip_offset + ihl == udp_start:
                        # Verify protocol field is UDP (17)
                        if raw_bytes[ip_offset + 9] == 17:
                            ip_header_found = True
                            break

            if not ip_header_found:
                search_start = port_pos + 1
                continue

            try:
                udp_len = struct.unpack('>H', raw_bytes[udp_start+4:udp_start+6])[0]
            except struct.error:
                search_start = port_pos + 1
                continue

            if udp_len < 8 or udp_start + udp_len > len(raw_bytes):
                search_start = port_pos + 1
                continue

            payload = raw_bytes[udp_start+8:udp_start+udp_len]

            # Try to extract VLAN ID (802.1Q tag: 0x8100)
            vlan_id = None
            vlan_pos = raw_bytes.find(b'\x81\x00')
            if 0 <= vlan_pos < port_pos:
                try:
                    vlan_id = struct.unpack('>H', raw_bytes[vlan_pos+2:vlan_pos+4])[0] & 0x0FFF
                except struct.error:
                    pass

            return payload, vlan_id

        return None, None

    def load_packets(self, progress=None):
        """Load UDP packets from pcap/pcapng file.

        Properly parses pcap format and extracts UDP port 6577 packets.
        """
        file_size = os.path.getsize(self.pcap_file)

        if progress:
            progress.set_step("Loading pcap file...")

        with open(self.pcap_file, 'rb') as f:
            file_data = f.read()

        # Detect format from magic number
        magic = struct.unpack('<I', file_data[0:4])[0]

        if magic == 0xa1b2c3d4:  # pcap little-endian
            self._parse_pcap(file_data, progress, '<')
        elif magic == 0xd4c3b2a1:  # pcap big-endian
            self._parse_pcap(file_data, progress, '>')
        elif magic == 0x0a0d0d0a:  # pcapng
            self._parse_pcapng(file_data, progress)
        else:
            raise ValueError(f"Unknown file format: magic=0x{magic:08x}")

    def _parse_pcap(self, file_data, progress, endian):
        """Parse classic pcap format."""
        # Global header: 24 bytes
        pos = 24
        file_size = len(file_data)
        seen_payloads = set()
        packet_num = 0
        packets_processed = 0

        while pos + 16 <= file_size:
            # Packet header: ts_sec, ts_usec, incl_len, orig_len
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f'{endian}IIII', file_data[pos:pos+16])
            pos += 16

            if pos + incl_len > file_size:
                break

            pkt_data = file_data[pos:pos+incl_len]
            pos += incl_len
            packets_processed += 1

            if packets_processed % 10000 == 0 and progress:
                pct = (pos / file_size) * 100
                progress.update(pct, f"Processing packet {packets_processed:,}...")

            # Parse packet
            timestamp = ts_sec + ts_usec / 1000000.0
            result = self._extract_udp_6577(pkt_data, timestamp, seen_payloads, packet_num)
            if result:
                self.packets.append(result)
                packet_num += 1

        if progress:
            progress.update(100, f"Loaded {len(self.packets)} packets")
        print(f"Processed {packets_processed:,} packets, found {len(self.packets)} UDP 6577")

    def _parse_pcapng(self, file_data, progress):
        """Parse pcapng format."""
        pos = 0
        file_size = len(file_data)
        seen_payloads = set()
        packet_num = 0
        packets_processed = 0
        if_tsresol = 1000000  # Default microseconds

        while pos + 8 <= file_size:
            block_type = struct.unpack('<I', file_data[pos:pos+4])[0]
            block_len = struct.unpack('<I', file_data[pos+4:pos+8])[0]

            if block_len < 12 or pos + block_len > file_size:
                break

            if block_type == 0x00000006:  # Enhanced Packet Block
                packets_processed += 1
                if packets_processed % 10000 == 0 and progress:
                    pct = (pos / file_size) * 100
                    progress.update(pct, f"Processing packet {packets_processed:,}...")

                # EPB: interface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4)
                if pos + 28 <= file_size:
                    ts_high = struct.unpack('<I', file_data[pos+12:pos+16])[0]
                    ts_low = struct.unpack('<I', file_data[pos+16:pos+20])[0]
                    cap_len = struct.unpack('<I', file_data[pos+20:pos+24])[0]

                    timestamp = ((ts_high << 32) | ts_low) / if_tsresol
                    pkt_start = pos + 28
                    pkt_end = pkt_start + cap_len

                    if pkt_end <= file_size:
                        pkt_data = file_data[pkt_start:pkt_end]
                        result = self._extract_udp_6577(pkt_data, timestamp, seen_payloads, packet_num)
                        if result:
                            self.packets.append(result)
                            packet_num += 1

            pos += block_len

        if progress:
            progress.update(100, f"Loaded {len(self.packets)} packets")
        print(f"Processed {packets_processed:,} packets, found {len(self.packets)} UDP 6577")

    def _extract_udp_6577(self, pkt_data, timestamp, seen_payloads, packet_num):
        """Extract UDP port 6577 payload from packet data."""
        if len(pkt_data) < 42:  # Min: 14 eth + 20 ip + 8 udp
            return None

        # Ethernet header
        ethertype = struct.unpack('>H', pkt_data[12:14])[0]
        ip_start = 14

        # Handle VLAN tags
        vlan_id = None
        if ethertype == 0x8100:  # 802.1Q VLAN
            vlan_id = struct.unpack('>H', pkt_data[14:16])[0] & 0x0FFF
            ethertype = struct.unpack('>H', pkt_data[16:18])[0]
            ip_start = 18
        elif ethertype == 0x9100 or ethertype == 0x9200:  # QinQ
            ethertype = struct.unpack('>H', pkt_data[20:22])[0]
            ip_start = 22

        # Handle proprietary encapsulation (ethertype 0x9102, 0x2090, etc.)
        # Search for IPv4 header within packet for non-standard ethertypes
        if ethertype not in (0x0800,):
            for offset in range(ip_start, min(ip_start + 100, len(pkt_data) - 28)):
                if pkt_data[offset] == 0x45:  # IPv4 version=4, IHL=5
                    if offset + 9 < len(pkt_data) and pkt_data[offset + 9] == 17:  # UDP
                        ip_start = offset
                        ethertype = 0x0800
                        break

        if ethertype != 0x0800:  # Not IPv4
            return None

        if ip_start + 20 > len(pkt_data):
            return None

        # IPv4 header
        ip_header = pkt_data[ip_start:ip_start+20]
        version_ihl = ip_header[0]
        if (version_ihl >> 4) != 4:  # Not IPv4
            return None

        ihl = (version_ihl & 0x0F) * 4
        protocol = ip_header[9]

        if protocol != 17:  # Not UDP
            return None

        udp_start = ip_start + ihl
        if udp_start + 8 > len(pkt_data):
            return None

        # UDP header
        dst_port = struct.unpack('>H', pkt_data[udp_start+2:udp_start+4])[0]
        udp_len = struct.unpack('>H', pkt_data[udp_start+4:udp_start+6])[0]

        if dst_port != 6577:  # Not our port
            return None

        # Extract payload
        payload_start = udp_start + 8
        payload_end = udp_start + udp_len
        if payload_end > len(pkt_data):
            payload_end = len(pkt_data)

        payload = pkt_data[payload_start:payload_end]
        if len(payload) < 12:  # Need at least header + 1 voltage
            return None

        # Deduplicate by payload
        payload_hash = hash(payload)
        if payload_hash in seen_payloads:
            return None
        seen_payloads.add(payload_hash)

        # Parse header
        current_index = struct.unpack('<I', payload[0:4])[0]
        max_values = struct.unpack('<I', payload[4:8])[0]

        # Parse voltage data (0-20V = 0-20000 mV)
        voltages = []
        for i in range(8, len(payload) - 3, 4):
            voltage = struct.unpack('<I', payload[i:i+4])[0]
            if 0 < voltage <= 20000:
                voltages.append(voltage)

        if not voltages:
            return None

        return {
            'num': packet_num,
            'packet': None,
            'payload': payload,
            'timestamp': timestamp,
            'current_index': current_index,
            'max_values': max_values,
            'size': len(payload),
            'voltages': voltages,
            'vlan_id': vlan_id
        }

    def create_timeseries(self):
        """Create voltage timeseries with interpolated timestamps."""
        for i, pkt_data in enumerate(self.packets):
            packet_timestamp = pkt_data['timestamp']
            voltages = pkt_data['voltages']

            if not voltages:
                continue

            if i < len(self.packets) - 1:
                next_packet_timestamp = self.packets[i + 1]['timestamp']
                time_delta = next_packet_timestamp - packet_timestamp
            else:
                if i > 0:
                    time_delta = packet_timestamp - self.packets[i - 1]['timestamp']
                else:
                    time_delta = 0.5

            num_samples = len(voltages)
            time_step = time_delta / num_samples if num_samples > 1 else 0

            for j, voltage in enumerate(voltages):
                sample_timestamp = packet_timestamp + (j * time_step)
                self.voltage_timeseries.append({
                    'timestamp': sample_timestamp,
                    'voltage': voltage,
                    'packet_num': pkt_data['num']
                })

        print(f"Created timeseries with {len(self.voltage_timeseries)} voltage samples")

    def create_widgets(self):
        """Create the complete GUI."""
        # Create menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Pcap...", command=self.load_pcap_dialog, accelerator="Ctrl+O")

        # Recent files submenu
        self.recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=self.recent_menu)
        self.update_recent_files_menu()

        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")

        # Bind keyboard shortcuts
        self.root.bind('<Control-o>', lambda e: self.load_pcap_dialog())
        self.root.bind('<Control-q>', lambda e: self.root.quit())

        # Main container
        main_container = tk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Top section: Voltage graph with controls
        top_frame = tk.Frame(main_container)
        top_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Control panel
        control_frame = tk.Frame(top_frame, bg='lightgray', relief=tk.RAISED, borderwidth=2)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(control_frame, text="Graph Controls:", font=('Arial', 10, 'bold'), bg='lightgray').pack(side=tk.LEFT, padx=5)

        tk.Button(control_frame, text="Autoscale Y", command=self.autoscale_y,
                 bg='lightblue', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)
        tk.Button(control_frame, text="Autoscale X", command=self.autoscale_x,
                 bg='lightblue', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)
        tk.Button(control_frame, text="Autoscale Both", command=self.autoscale_both,
                 bg='lightgreen', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)

        # Graph frame
        graph_frame = tk.Frame(top_frame)
        graph_frame.pack(fill=tk.BOTH, expand=True)

        # Create matplotlib figure
        self.fig = Figure(figsize=(16, 5), dpi=100)
        self.ax = self.fig.add_subplot(111)

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add matplotlib toolbar
        toolbar_frame = tk.Frame(graph_frame)
        toolbar_frame.pack(fill=tk.X)
        toolbar = NavigationToolbar2Tk(self.canvas, toolbar_frame)
        toolbar.update()

        # Bottom section: Packet details
        bottom_paned = tk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        bottom_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left: Packet list
        left_frame = tk.Frame(bottom_paned)
        bottom_paned.add(left_frame, width=700)

        list_label = tk.Label(left_frame, text="UDP Packets (Port 6577)",
                             font=('Arial', 11, 'bold'), bg='lightgray')
        list_label.pack(fill=tk.X)

        list_scroll = tk.Scrollbar(left_frame)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_tree = ttk.Treeview(left_frame,
                                        columns=('num', 'time', 'size', 'index', 'max', 'voltages'),
                                        show='headings',
                                        yscrollcommand=list_scroll.set)

        self.packet_tree.heading('num', text='#')
        self.packet_tree.heading('time', text='Timestamp')
        self.packet_tree.heading('size', text='Size')
        self.packet_tree.heading('index', text='Index')
        self.packet_tree.heading('max', text='Max')
        self.packet_tree.heading('voltages', text='V Count')

        self.packet_tree.column('num', width=40)
        self.packet_tree.column('time', width=150)
        self.packet_tree.column('size', width=60)
        self.packet_tree.column('index', width=80)
        self.packet_tree.column('max', width=80)
        self.packet_tree.column('voltages', width=70)

        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scroll.config(command=self.packet_tree.yview)

        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

        # Right: Packet details
        right_frame = tk.Frame(bottom_paned)
        bottom_paned.add(right_frame)

        self.details_label = tk.Label(right_frame, text="Packet Details",
                                     font=('Arial', 11, 'bold'), bg='lightblue')
        self.details_label.pack(fill=tk.X)

        info_frame = tk.Frame(right_frame, bg='white', relief=tk.SUNKEN, borderwidth=1)
        info_frame.pack(fill=tk.X, padx=5, pady=5)

        self.info_text = tk.Text(info_frame, height=6, bg='white', font=('Courier', 9))
        self.info_text.pack(fill=tk.X, padx=5, pady=5)

        hex_label = tk.Label(right_frame, text="Payload Hex Dump",
                           font=('Arial', 10, 'bold'), bg='lightyellow')
        hex_label.pack(fill=tk.X)

        hex_scroll = tk.Scrollbar(right_frame)
        hex_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.hex_text = tk.Text(right_frame,
                               font=('Courier', 9),
                               yscrollcommand=hex_scroll.set,
                               bg='#f0f0f0')
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        hex_scroll.config(command=self.hex_text.yview)

        # Status bar at bottom
        status_frame = tk.Frame(self.root, relief=tk.SUNKEN, borderwidth=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = tk.Label(status_frame, text="Ready", anchor=tk.W, padx=5)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=5, pady=2)

    def set_status(self, message, progress=False):
        """Update status bar message and optionally show progress."""
        self.status_label.config(text=message)
        if progress:
            self.progress_bar.start(10)
        else:
            self.progress_bar.stop()
        self.root.update_idletasks()

    def populate_packet_list(self):
        """Populate the packet list."""
        for pkt_data in self.packets:
            timestamp_str = datetime.fromtimestamp(pkt_data['timestamp']).strftime('%H:%M:%S.%f')[:-3]

            self.packet_tree.insert('', tk.END, values=(
                pkt_data['num'],
                timestamp_str,
                pkt_data['size'],
                pkt_data['current_index'] if pkt_data['current_index'] is not None else 'N/A',
                pkt_data['max_values'] if pkt_data['max_values'] is not None else 'N/A',
                len(pkt_data['voltages'])
            ))

    def downsample_for_plot(self, timestamps, voltages, packet_nums, max_points=10000):
        """Downsample data intelligently for plotting performance.
        Uses min-max decimation to preserve peaks and valleys.
        """
        n = len(timestamps)
        if n <= max_points:
            return timestamps, voltages, packet_nums

        # Calculate decimation factor
        factor = int(np.ceil(n / (max_points / 2)))

        # Min-max decimation: keep both min and max in each window
        indices = []
        for i in range(0, n, factor):
            window_end = min(i + factor, n)
            window = voltages[i:window_end]

            if len(window) > 0:
                # Find local min and max indices
                local_min_idx = i + np.argmin(window)
                local_max_idx = i + np.argmax(window)

                # Add both (sorted by position)
                if local_min_idx < local_max_idx:
                    indices.extend([local_min_idx, local_max_idx])
                else:
                    indices.extend([local_max_idx, local_min_idx])

        # Remove duplicates while preserving order
        seen = set()
        unique_indices = []
        for idx in indices:
            if idx not in seen:
                seen.add(idx)
                unique_indices.append(idx)

        return timestamps[unique_indices], voltages[unique_indices], packet_nums[unique_indices]

    def update_voltage_graph(self, selected_packet=None, fast_update=False):
        """Update the voltage graph with all features.

        Args:
            selected_packet: Packet number to highlight
            fast_update: If True, only update highlight without full redraw
        """
        # Fast update path - only change highlight
        if fast_update and not self.graph_needs_full_redraw and hasattr(self, 'current_timestamps'):
            self.update_packet_highlight(selected_packet)
            return

        # Full redraw
        self.ax.clear()

        if not self.voltage_timeseries:
            self.ax.text(0.5, 0.5, 'No voltage data available',
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            return

        # Extract data
        timestamps = np.array([v['timestamp'] for v in self.voltage_timeseries])
        voltages = np.array([v['voltage'] for v in self.voltage_timeseries])
        packet_nums = np.array([v['packet_num'] for v in self.voltage_timeseries])

        # Normalize timestamps to start at 0
        self.time_offset = timestamps[0]
        timestamps_normalized = timestamps - self.time_offset

        # Store for later use
        self.current_timestamps = timestamps_normalized
        self.current_voltages = voltages
        self.current_packet_nums = packet_nums

        # Downsample if too many points
        n_samples = len(timestamps_normalized)
        if n_samples > 10000:
            print(f"Downsampling {n_samples} points for performance...")
            timestamps_plot, voltages_plot, packet_nums_plot = self.downsample_for_plot(
                timestamps_normalized, voltages, packet_nums, max_points=10000
            )
            downsample_info = f" (showing {len(timestamps_plot)} of {n_samples} samples)"
        else:
            timestamps_plot = timestamps_normalized
            voltages_plot = voltages
            packet_nums_plot = packet_nums
            downsample_info = ""

        # Store downsampled data for fast updates
        self.plot_timestamps = timestamps_plot
        self.plot_voltages = voltages_plot
        self.plot_packet_nums = packet_nums_plot

        # Plot voltage trace with rasterization for performance
        self.ax.plot(timestamps_plot, voltages_plot, 'b-', linewidth=1.0, alpha=0.8,
                    label='Voltage', zorder=2, rasterized=True)

        # Create placeholder for highlight (will be updated later)
        self.highlight_artist = None

        # Packet boundaries - only show if there aren't too many
        if len(self.packets) <= 50:
            packet_timestamps = [(pkt['timestamp'] - self.time_offset) for pkt in self.packets]
            for pt in packet_timestamps:
                self.ax.axvline(x=pt, color='gray', linestyle='--', alpha=0.2, linewidth=0.8, zorder=1)

        # Threshold lines
        self.ax.axhline(y=12000, color='orange', linestyle=':', alpha=0.6, linewidth=2, label='12V threshold', zorder=1)
        self.ax.axhline(y=6000, color='red', linestyle=':', alpha=0.6, linewidth=2, label='6V threshold', zorder=1)

        # Average line
        avg_voltage = np.mean(voltages)
        self.ax.axhline(y=avg_voltage, color='green', linestyle='--', alpha=0.7, linewidth=2,
                       label=f'Average ({avg_voltage:.0f} mV)', zorder=1)

        # Formatting
        self.ax.set_xlabel('Time (seconds)', fontsize=11, fontweight='bold')
        self.ax.set_ylabel('Voltage (mV)', fontsize=11, fontweight='bold')
        title = f'Voltage Measurements Over Time{downsample_info}'
        self.ax.set_title(title, fontsize=12, fontweight='bold')
        self.ax.grid(True, alpha=0.3, linestyle='--')
        self.ax.legend(loc='best', fontsize=9, framealpha=0.9)

        self.fig.tight_layout()
        self.canvas.draw()
        self.graph_needs_full_redraw = False

    def update_packet_highlight(self, selected_packet):
        """Fast update: only change the highlighted packet markers."""
        # Remove old highlight
        if self.highlight_artist is not None:
            self.highlight_artist.remove()
            self.highlight_artist = None

        # Add new highlight if packet selected
        if selected_packet is not None:
            mask = self.plot_packet_nums == selected_packet
            if np.any(mask):
                # Create new highlight artist
                self.highlight_artist, = self.ax.plot(
                    self.plot_timestamps[mask],
                    self.plot_voltages[mask],
                    'ro', markersize=5, label=f'Packet #{selected_packet}', zorder=5
                )

        # Redraw only the changed elements (much faster)
        self.ax.legend(loc='best', fontsize=9, framealpha=0.9)
        self.canvas.draw_idle()  # Faster than draw()

    def on_packet_select(self, event):
        """Handle packet selection with fast graph update."""
        selection = self.packet_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.packet_tree.item(item, 'values')
        packet_num = int(values[0])

        pkt_data = next((p for p in self.packets if p['num'] == packet_num), None)
        if not pkt_data:
            return

        self.display_packet_details(pkt_data)
        # Use fast update to avoid full redraw
        self.update_voltage_graph(selected_packet=packet_num, fast_update=True)

    def display_packet_details(self, pkt_data):
        """Display detailed packet information."""
        self.details_label.config(text=f"Packet #{pkt_data['num']} Details")

        self.info_text.delete('1.0', tk.END)
        info = f"Packet Number: {pkt_data['num']}\n"
        info += f"Timestamp: {datetime.fromtimestamp(pkt_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')}\n"
        info += f"Payload Size: {pkt_data['size']} bytes\n"
        if pkt_data['current_index'] is not None:
            info += f"Current Index: {pkt_data['current_index']}  |  Max Values: {pkt_data['max_values']}\n"
        info += f"Voltage Samples: {len(pkt_data['voltages'])}\n"
        if pkt_data['voltages']:
            info += f"Voltage Range: {min(pkt_data['voltages'])} - {max(pkt_data['voltages'])} mV\n"
        self.info_text.insert('1.0', info)

        self.hex_text.delete('1.0', tk.END)
        payload = pkt_data['payload']

        hex_dump = self.create_hex_dump(payload)
        self.hex_text.insert('1.0', hex_dump)

        if len(payload) >= 8:
            self.hex_text.tag_add('header', '1.10', '1.33')
            self.hex_text.tag_config('header', background='yellow')

    def create_hex_dump(self, data):
        """Create hex dump."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}  "
            hex_part = ""
            for j in range(16):
                if j < len(chunk):
                    hex_part += f"{chunk[j]:02x} "
                else:
                    hex_part += "   "
                if j == 7:
                    hex_part += " "
            ascii_part = ""
            for byte in chunk:
                if 32 <= byte <= 126:
                    ascii_part += chr(byte)
                else:
                    ascii_part += "."
            lines.append(f"{offset}{hex_part} |{ascii_part}|")
        return "\n".join(lines)

    def autoscale_y(self):
        """Autoscale Y axis."""
        self.ax.autoscale(axis='y')
        self.canvas.draw()

    def autoscale_x(self):
        """Autoscale X axis."""
        self.ax.autoscale(axis='x')
        self.canvas.draw()

    def autoscale_both(self):
        """Autoscale both axes."""
        self.ax.autoscale()
        self.canvas.draw()

    def load_pcap_dialog(self):
        """Show file dialog to load a new pcap file."""
        filename = filedialog.askopenfilename(
            title="Select Pcap File",
            filetypes=[
                ("Pcap files", "*.pcap *.pcapng"),
                ("All files", "*.*")
            ],
            initialdir=os.path.dirname(self.pcap_file) if self.pcap_file else os.getcwd()
        )

        if filename:
            self.load_pcap_file(filename)

    def load_pcap_file(self, filename):
        """Load a pcap file with error handling and progress indication."""
        try:
            # Validate file exists
            if not os.path.exists(filename):
                messagebox.showerror("Error", f"File not found:\n{filename}")
                self.set_status("Error: File not found", progress=False)
                return

            # Clear existing data
            self.packets = []
            self.voltage_timeseries = []
            self.pcap_file = filename
            self.graph_needs_full_redraw = True

            # Create progress dialog
            progress = ProgressDialog(self.root, f"Loading {os.path.basename(filename)}")

            # Load packets with progress
            self.load_packets(progress)

            # Check if we got any packets
            if not self.packets:
                progress.close()
                self.set_status("Error: No packets found", progress=False)
                messagebox.showerror(
                    "No UDP Packets Found",
                    f"No UDP packets found on port 6577 in:\n{os.path.basename(filename)}\n\n"
                    "Please ensure:\n"
                    "- The pcap file contains UDP traffic\n"
                    "- Packets are destined to port 6577\n"
                    "- The file is not corrupted"
                )
                return

            # Create timeseries
            progress.set_step("Creating voltage timeseries...")
            self.create_timeseries()
            progress.update(100, f"{len(self.voltage_timeseries):,} voltage samples")

            # Update UI
            self.root.title(f"Complete StackAtClose Analyzer - {os.path.basename(filename)}")

            # Populate packet list
            progress.set_step("Populating packet list...")
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            self.populate_packet_list()
            progress.update(100)

            # Update graph
            progress.set_step("Rendering voltage graph...")
            self.update_voltage_graph()
            progress.update(100)

            # Close progress and update recent files
            progress.close()
            self.add_recent_file(filename)

            # Success - update status bar
            self.set_status(
                f"Loaded {os.path.basename(filename)}: {len(self.packets)} packets, "
                f"{len(self.voltage_timeseries):,} voltage samples",
                progress=False
            )

        except Exception as e:
            self.set_status(f"Error: {str(e)}", progress=False)
            messagebox.showerror(
                "Error Loading File",
                f"Failed to load file:\n{os.path.basename(filename)}\n\n"
                f"Error: {str(e)}\n\n"
                "Please ensure the file is a valid pcap/pcapng file."
            )
            print(f"Error loading {filename}: {e}")

    def add_recent_file(self, filename):
        """Add file to recent files list."""
        if filename not in self.recent_files:
            self.recent_files.insert(0, filename)
            self.recent_files = self.recent_files[:10]  # Keep max 10
        else:
            # Move to front
            self.recent_files.remove(filename)
            self.recent_files.insert(0, filename)
        self.save_recent_files()
        self.update_recent_files_menu()

    def load_recent_files(self):
        """Load recent files from config."""
        config_file = os.path.join(os.path.expanduser("~"), ".stackatclose_recent")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    files = [line.strip() for line in f.readlines()]
                    # Filter to existing files only
                    return [f for f in files if os.path.exists(f)][:10]
            except:
                pass
        return []

    def save_recent_files(self):
        """Save recent files to config."""
        config_file = os.path.join(os.path.expanduser("~"), ".stackatclose_recent")
        try:
            with open(config_file, 'w') as f:
                for filepath in self.recent_files[:10]:
                    f.write(filepath + '\n')
        except:
            pass

    def update_recent_files_menu(self):
        """Update the recent files submenu."""
        self.recent_menu.delete(0, tk.END)
        for filepath in self.recent_files:
            if os.path.exists(filepath):
                label = os.path.basename(filepath)
                self.recent_menu.add_command(
                    label=label,
                    command=lambda f=filepath: self.load_pcap_file(f)
                )
        if not self.recent_files:
            self.recent_menu.add_command(label="(No recent files)", state=tk.DISABLED)


def main():
    import sys

    # Check for pcap file argument
    pcap_file = None
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    elif os.path.exists('Simulated_Voltage_Data.pcapng'):
        pcap_file = 'Simulated_Voltage_Data.pcapng'

    root = tk.Tk()
    app = CompleteAnalyzer(root, pcap_file)
    root.mainloop()


if __name__ == '__main__':
    main()

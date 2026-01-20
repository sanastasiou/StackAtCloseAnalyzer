#!/usr/bin/env python3
"""
Generate a simulated pcap file with realistic voltage data.
Voltage values vary between 6000mV and 13000mV during stackAtClose diagnosis.
"""

import struct
import random
import math
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from datetime import datetime


def generate_voltage_pattern(num_samples, start_voltage=12000, variation=3500):
    """
    Generate realistic voltage pattern.
    Simulates voltage drop and recovery during diagnosis.

    Args:
        num_samples: Total number of voltage samples to generate
        start_voltage: Starting voltage in mV (default 12V)
        variation: Max variation in mV

    Returns:
        List of voltage values in mV (as uint32_t)
    """
    voltages = []

    for i in range(num_samples):
        # Create a pattern: starts at 12V, drops to ~6-7V, then recovers
        progress = i / num_samples

        # Multi-phase pattern
        if progress < 0.2:
            # Initial stable phase around 12V
            base = start_voltage
            noise = random.randint(-200, 200)
        elif progress < 0.5:
            # Drop phase - voltage decreases
            drop_progress = (progress - 0.2) / 0.3
            base = start_voltage - int(drop_progress * 5000)  # Drop to ~7V
            noise = random.randint(-300, 300)
        elif progress < 0.7:
            # Low voltage phase
            base = 6500 + random.randint(-500, 500)
            noise = random.randint(-400, 400)
        else:
            # Recovery phase
            recovery_progress = (progress - 0.7) / 0.3
            base = 6500 + int(recovery_progress * 5000)  # Recover to ~11.5V
            noise = random.randint(-300, 300)

        # Add some realistic fluctuations
        voltage = base + noise + int(100 * math.sin(i * 0.1))

        # Clamp to realistic range
        voltage = max(6000, min(13000, voltage))

        voltages.append(voltage)

    return voltages


def create_udp_packets(voltages, values_per_packet=126):
    """
    Create UDP packets from voltage data.

    Args:
        voltages: List of voltage values in mV
        values_per_packet: Number of uint32_t values per packet

    Returns:
        List of scapy packet objects
    """
    packets = []
    total_values = len(voltages)

    # Calculate how many packets we need
    num_packets = (total_values + values_per_packet - 1) // values_per_packet

    # Base timestamp
    base_time = datetime.now().timestamp()
    packet_interval = 0.5  # 500ms between packets

    for packet_idx in range(num_packets):
        # Calculate current index and remaining values
        current_index = packet_idx * values_per_packet
        remaining = total_values - current_index
        values_in_this_packet = min(values_per_packet, remaining)

        # Build header: current_index (uint32_t) + max_values (uint32_t)
        header = struct.pack('<I', current_index)  # Current index
        header += struct.pack('<I', total_values)   # Max values (total)

        # Build payload: voltage values as uint32_t
        payload = b''
        for i in range(values_in_this_packet):
            voltage_idx = current_index + i
            voltage_value = voltages[voltage_idx]
            payload += struct.pack('<I', voltage_value)

        # Pad to 512 bytes total if this is not the last packet
        total_size = len(header) + len(payload)
        if values_in_this_packet == values_per_packet and total_size < 512:
            padding = b'\x00' * (512 - total_size)
            payload += padding

        # Create UDP packet
        udp_payload = header + payload

        pkt = Ether() / IP(src='160.48.249.64', dst='239.255.42.99') / \
              UDP(sport=49154, dport=6577) / Raw(load=udp_payload)

        # Set timestamp
        pkt.time = base_time + (packet_idx * packet_interval)

        packets.append(pkt)

    return packets


def main():
    print("Generating simulated voltage data...")

    # Generate realistic voltage pattern
    # Match original: 1024 total values to match original pcap max_values
    num_samples = 1024
    voltages = generate_voltage_pattern(num_samples)

    print(f"Generated {len(voltages)} voltage samples")
    print(f"  Range: {min(voltages)} - {max(voltages)} mV")
    print(f"  Average: {sum(voltages) / len(voltages):.2f} mV")

    # Create UDP packets
    print("\nCreating UDP packets...")
    packets = create_udp_packets(voltages, values_per_packet=126)

    print(f"Created {len(packets)} UDP packets")

    # Write to pcap file
    output_file = 'Simulated_Voltage_Data.pcapng'
    print(f"\nWriting to {output_file}...")
    wrpcap(output_file, packets)

    print(f"✓ Successfully created {output_file}")
    print(f"  Total packets: {len(packets)}")
    print(f"  Total voltage samples: {num_samples}")
    print(f"  Time span: {len(packets) * 0.5:.1f} seconds")


if __name__ == '__main__':
    main()

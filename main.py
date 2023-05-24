import argparse
import sys
from imports import cve_lookup, dos, load, metasploit, nmap, target_info, validation,password_cracker

def main():
    parser = argparse.ArgumentParser(description="Network Security Toolkit")
    parser.add_argument("choice", choices=["1", "2", "3", "4", "5", "6", "7"], help="Select an option (1-7)")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-e", "--exploit", help="Exploit name")
    parser.add_argument("-p", "--packets", type=int, help="Number of packets to send (for DoS attack)")
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Interval between packets in seconds (for DoS attack)")
    parser.add_argument("--port", type=int, default=0, help="Destination port for DoS attack (0 for random)")
    parser.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP for Nmap scan")
    parser.add_argument("--passwords", help="Password file for cracking")
    parser.add_argument("--hashes", help="Hash file for cracking")
    parser.add_argument("--output", help="Output file for cracked passwords")
    args = parser.parse_args()

    if args.choice == "1":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        nmap.scan_with_nmap(args.target, args.udp)
    elif args.choice == "2":
        if not args.target or not args.exploit:
            parser.error("Please provide both the target IP or hostname and the exploit name.")
        metasploit.run_metasploit_exploit(args.target, args.exploit)
    elif args.choice == "3":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        nmap.gather_network_info(args.target)
    elif args.choice == "4":
        if not args.target or not args.packets:
            parser.error("Please provide both the target IP or hostname and the number of packets.")
        dos.perform_dos_attack_threaded(args.target, args.packets, args.interval, args.port, args.udp)
    elif args.choice == "5":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        cve_lookup.get_known_cves_threaded(args.target)
    elif args.choice == "6":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        target_info.display_target_info(args.target)
    elif args.choice == "7":
        if not args.passwords or not args.hashes or not args.output:
            parser.error("Please provide the password file, hash file, and output file.")
        password_cracker.crack_passwords(args.passwords, args.hashes, args.output)
    else:
        print("Invalid choice. Please select a valid option (1-7).")
        sys.exit(1)

if __name__ == "__main__":
    main()

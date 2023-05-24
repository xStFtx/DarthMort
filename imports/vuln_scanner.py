import nessus
import time

def scan_vulnerabilities(target):
    nessus_client = nessus.NessusAPI()

    # Authenticate to the Nessus server
    nessus_client.login("username", "password", "https://nessus_server")

    # Create a new scan
    scan_name = "Vulnerability Scan"
    policy_id = 1  # Replace with the appropriate policy ID
    target_list = [target]
    scan_uuid = nessus_client.scan_create(scan_name, policy_id, target_list)

    # Launch the scan
    nessus_client.scan_launch(scan_uuid)

    # Wait for the scan to complete
    while True:
        scan_status = nessus_client.scan_status(scan_uuid)
        if scan_status['status'] == 'completed':
            break
        elif scan_status['status'] == 'running':
            time.sleep(10)  # Adjust the sleep interval as needed
        else:
            print("Scan failed or terminated.")
            break

    # Get the scan results
    scan_results = nessus_client.scan_export(scan_uuid, nessus.ReportType.V2)
    scan_results_file = f"{scan_name}.nessus"
    with open(scan_results_file, "wb") as f:
        f.write(scan_results)

    print(f"Scan results saved to {scan_results_file}")

    # Logout from the Nessus server
    nessus_client.logout()

def main():
    target = "192.168.1.1"  # Replace with the target IP or hostname
    scan_vulnerabilities(target)

if __name__ == "__main__":
    main()

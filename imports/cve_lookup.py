import requests
import logging
import threading

logger = logging.getLogger(__name__)

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

def get_known_cves_threaded(target):
    cves_thread = threading.Thread(target=get_known_cves, args=(target,))
    cves_thread.start()

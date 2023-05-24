import subprocess
import logging

logger = logging.getLogger(__name__)

def gather_network_info(target):
    info_cmd = f"sudo nmap -A {target}"

    try:
        output = subprocess.check_output(info_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error gathering network information: {e}")



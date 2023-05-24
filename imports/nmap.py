import subprocess
import logging

logger = logging.getLogger(__name__)

def scan_with_nmap(target, use_udp):
    scan_type = "-sU" if use_udp else "-sT"
    nmap_cmd = f"sudo nmap -Pn {scan_type} -sC -sV {target}"

    try:
        output = subprocess.check_output(nmap_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Nmap scan: {e}")

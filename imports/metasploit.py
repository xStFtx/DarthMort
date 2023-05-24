import subprocess
import logging

logger = logging.getLogger(__name__)

def run_metasploit_exploit(target, exploit):
    metasploit_cmd = f"sudo msfconsole -x 'use {exploit}; set RHOST {target}; run;'"

    try:
        output = subprocess.check_output(metasploit_cmd.split())
        logger.info(output.decode())
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing Metasploit exploit: {e}")

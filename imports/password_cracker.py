import subprocess

def crack_passwords(password_file, hash_file, output_file):
    try:
        # Run John the Ripper to crack passwords
        command = f"john --wordlist={password_file} --format=Raw-MD5 --pot={output_file} {hash_file}"
        subprocess.run(command, shell=True, check=True)
        print("Password cracking completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred during password cracking: {e}")

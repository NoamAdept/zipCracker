import zipfile
import itertools
import string
import argparse

def extract_zip(zip_path, password):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            zip_file.extractall(pwd=password.encode())
        print(f"[+] Password found: {password}")
        return True
    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False
    except Exception as e:
        if "invalid distance too far back" in str(e) or "invalid block type" in str(e):
            return False  # Skip decompression errors
        print(f"[-] Error: {e}")
        return False

def bruteforce_zip(zip_path, wordlist_path):
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                password = line.strip()
                print(f"Testing {password}...")
                if extract_zip(zip_path, password):
                    return password
    except FileNotFoundError:
        print("[-] Wordlist file not found.")
        return None
    print("[-] Password not found in wordlist.")
    return None

def generate_bruteforce(zip_path, max_length=4):
    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            password = ''.join(password)
            if extract_zip(zip_path, password):
                return password
    print("[-] Password not found with brute-force.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Brute-force a password-protected ZIP file.")
    parser.add_argument("zipfile", help="Path to the password-protected ZIP file.")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file.")
    parser.add_argument("-m", "--max-length", type=int, default=4, help="Maximum length for brute-force attack.")
    
    args = parser.parse_args()
    
    try:
        if args.wordlist:
            print("[+] Starting dictionary attack...")
            password = bruteforce_zip(args.zipfile, args.wordlist)
        else:
            print("[+] Starting brute-force attack...")
            password = generate_bruteforce(args.zipfile, max_length=args.max_length)
        
        if password:
            print(f"[+] Password cracked: {password}")
        else:
            print("[-] Password not found.")
    except FileNotFoundError:
        print("[-] ZIP file not found.")
    except zipfile.BadZipFile:
        print("[-] Invalid ZIP file format.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    main()


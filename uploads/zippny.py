import os
import re
import shutil
import itertools
import zipfile
import subprocess
import hashlib
import sqlite3
from flask import Flask, render_template, request, jsonify, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
EXTRACT_FOLDER = "extracted"
DICTIONARY_PATH = "cmn_pass.txt"
MODIFIABLE_DICTIONARY_PATH = "modifiable_cmn_pass.txt"
db_path = "seen_files.db"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

# Configure for deployment
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Limit uploads to 100MB
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize database for seen files
def init_db():
    print("Initializing database and checking for previously seen files...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS seen_files (hash TEXT PRIMARY KEY, password TEXT)")
    # Ensure the password column exists
    cursor.execute("PRAGMA table_info(seen_files)")
    columns = [row[1] for row in cursor.fetchall()]
    if "password" not in columns:
        cursor.execute("ALTER TABLE seen_files ADD COLUMN password TEXT")
    conn.commit()
    conn.close()
    print("Database initialization complete.")

def file_seen(file_path):
    file_hash = compute_sha256(file_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM seen_files WHERE hash = ?", (file_hash,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def mark_file_as_seen(file_path, password):
    file_hash = compute_sha256(file_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO seen_files (hash, password) VALUES (?, ?)", (file_hash, password))
    conn.commit()
    conn.close()

def get_all_seen_files():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT hash, password FROM seen_files")
    files = cursor.fetchall()
    conn.close()
    return files

def clear_seen_files():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM seen_files")
    conn.commit()
    conn.close()

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def sanitize_filename(filename):
    return secure_filename(filename)

def fcrackzip_attack(zip_path, dictionary):
    if not os.path.exists(dictionary):
        return "[-] Crack status: Dictionary file not found."

    print("Starting ZIP password cracking using fcrackzip...")
    os.system(f"fcrackzip -v -D -u -p {dictionary} '{zip_path}' > F1.tmp")
    os.system("awk '/pw ==/{print $NF}' F1.tmp > F2.tmp")

    try:
        with open("F2.tmp", "r") as f:
            password = f.readline().strip()
        os.system("rm -f F1.tmp F2.tmp")
        if password:
            print("Password found:", password)
            return password
        else:
            print("Password cracking completed, but dictionary exhausted.")
            return "[-] Crack status: Dictionary exhausted."
    except Exception as e:
        print("Error during password cracking:", e)
        return f"[-] Error: {e}"

def scan_for_malware(zip_path):
    print("Running malware scan on the uploaded ZIP file...")
    try:
        result = subprocess.run(["clamscan", zip_path], capture_output=True, text=True)
        if "Infected files: 0" in result.stdout:
            print("Malware scan completed: No malware detected.")
            return "[+] No malware detected."
        else:
            print("Malware scan warning: Malware detected!")
            return "[!] WARNING: Malware detected in the ZIP file!"
    except FileNotFoundError:
        print("ClamAV not installed. Skipping malware scan.")
        return "[-] ClamAV not installed. Skipping malware scan."

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Inform the user that the process is starting
        status_message = "Uploading file and running malware/database checks..."
        print(status_message)
        
        if 'zipfile' not in request.files:
            error_message = "No file uploaded. Please select a ZIP file to upload."
            print(error_message)
            return render_template("index.html", error=error_message, seen_files=get_all_seen_files())

        zip_file = request.files['zipfile']
        safe_filename = sanitize_filename(zip_file.filename)
        zip_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        zip_file.save(zip_path)
        print(f"File '{safe_filename}' saved to '{UPLOAD_FOLDER}'.")

        # Check if file was already processed
        seen_password = file_seen(zip_path)
        if seen_password:
            message = "File already processed. Displaying stored result."
            print(message)
            return render_template("index.html", message=message, password=seen_password, seen_files=get_all_seen_files())

        # Run password cracking, malware scan, and log the file in the database
        password_result = fcrackzip_attack(zip_path, MODIFIABLE_DICTIONARY_PATH)
        mark_file_as_seen(zip_path, password_result)
        malware_status = scan_for_malware(zip_path)

        info_message = "Completed processing: performed password cracking, malware scanning, and database logging."
        print(info_message)
        return render_template("index.html",
                               message=info_message,
                               password=password_result,
                               malware_status=malware_status,
                               seen_files=get_all_seen_files())

    welcome_message = "Welcome to the Cool ZIP Cracker App! Ready to scan, crack, and check your files."
    print(welcome_message)
    return render_template("index.html", welcome_message=welcome_message, seen_files=get_all_seen_files())

@app.route('/clear_cache', methods=['POST'])
def clear_cache():
    clear_seen_files()
    message = "Seen files cache cleared. You're starting fresh!"
    print(message)
    return render_template("index.html", message=message, seen_files=get_all_seen_files())

if __name__ == "__main__":
    init_db()
    from waitress import serve
    print("Starting the Cool ZIP Cracker App on port 5000...")
    serve(app, host="0.0.0.0", port=5000)


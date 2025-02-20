# ZIP Blaster 🚀

## Overview
ZIP Blaster is a powerful web application that helps you crack password-protected ZIP files using a dictionary-based attack, scan them for malware, and keep track of previously processed files. The app is built with Flask and integrates with `fcrackzip` for password recovery and `ClamAV` for malware scanning.

## Features
- 🔑 **Password Cracking**: Uses `fcrackzip` to brute-force ZIP file passwords with a customizable dictionary.
- 🔍 **Malware Scanning**: Runs `ClamAV` to check uploaded ZIP files for potential threats.
- 📂 **File Tracking**: Stores hashes of previously processed files in an SQLite database to avoid redundant processing.
- 🌐 **Web-Based UI**: Upload ZIP files, view results, and manage processed files through a simple web interface.
- 🗑 **Cache Management**: Clear the database of seen files when needed.

## Requirements
### System Dependencies
Make sure you have the following installed on your system:
- Python 3.x
- `fcrackzip` (for ZIP password cracking)
- `ClamAV` (for malware scanning)
- `sqlite3` (for database management)

### Python Packages
Install required dependencies using:
```sh
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/zip-blaster.git
   cd zip-blaster
   ```
2. Install Python dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Ensure `fcrackzip` and `ClamAV` are installed on your system:
   ```sh
   sudo apt install fcrackzip clamav
   ```
4. Initialize the database:
   ```sh
   python -c 'from app import init_db; init_db()'
   ```
5. Run the application:
   ```sh
   python app.py
   ```
   or use Waitress for production:
   ```sh
   waitress-serve --host=0.0.0.0 --port=5000 app:app
   ```

## Usage
1. Open your browser and go to `http://localhost:5000`.
2. Upload a password-protected ZIP file.
3. The app will attempt to crack the password using the dictionary.
4. It will also scan the ZIP file for malware using ClamAV.
5. Results, including the found password and malware status, will be displayed.
6. Previously processed files are stored to prevent redundant attempts.
7. Use the "Clear Cache" button to remove seen file records.

## File Management
- **Uploads** are stored in the `uploads/` folder.
- **Extracted contents** are placed in the `extracted/` folder.
- **Password dictionary** is located at `cmn_pass.txt` (modifiable dictionary at `modifiable_cmn_pass.txt`).
- **Seen files database** is `seen_files.db`.

## Security Considerations
- **Use responsibly**: Ensure you have permission before attempting to crack a ZIP file.
- **Protect your dictionary**: Customizing your password list can improve cracking efficiency.
- **Run in a secure environment**: ZIP Blaster performs potentially sensitive operations, so use it in a trusted system.

## Future Enhancements
- 🚀 Support for more cracking techniques (e.g., brute-force beyond dictionary attack).
- 🛡️ Integration with more antivirus engines.
- 📊 UI improvements for better user experience.
- 🔄 Background task execution for large-scale cracking attempts.

## License
MIT License. See `LICENSE` file for details.


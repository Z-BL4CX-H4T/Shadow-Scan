# Shadow-Scan

🔧 *Tool Name*: ShadowScan (by Z-SH4DOWSPEECH)

🎯 Main Functions of the Tool
*ShadowScan* is a Python-based domain and web security analysis tool, useful for:

1. Complete Domain Information
Retrieves IP address, headers, DNS records (A, MX, TXT, etc), GeoIP, WHOIS, and reverse DNS.

2. Automatic Subdomain Extraction
Fetches all active subdomains using public data (crt.sh and hackertarget).

3. Full Website URL Extraction
Displays all URLs from the main page & subdomains, including links to social media, scripts, iframes, hidden paths, etc.

4. Redirect & Phishing Detection
Detects suspicious redirect URLs and phishing links based on keywords like “login,” “verify,” “secure,” etc.

✅ Advantages
- No API key required  
- No external tools needed (no subfinder or amass)  
- Lightweight and fast  
- Terminal colors and ASCII art  
- Can be run directly in terminal  

📦 Installation Command
Run this command once before using the tool:
```
pip install requests beautifulsoup4 dnspython colorama
git clone https://github.com/Z-BL4CX-H4T/Shadow-Scan.git
```
🚀 *How to Run*
After dependencies are installed, run the script:
```
python shadowscan.py
```

# By: Z-SH4DOWSPEECH

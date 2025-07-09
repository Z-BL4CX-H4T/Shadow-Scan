import socket
import requests
import json
import re
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(Fore.MAGENTA + r"""
     _            _                             
  __| |_  __ _ __| |_____ __ _____ __ __ _ _ _  
 (_-< ' \/ _` / _` / _ \ V  V (_-</ _/ _` | ' \ 
 /__/_||_\__,_\__,_\___/\_/\_//__/\__\__,_|_||_|
""" + Fore.CYAN + "                   Coded by: " + Fore.GREEN + "Z-SH4DOWSPEECH\n")

def get_info(domain):
    print(Fore.YELLOW + "\n[INFO] Mengambil info lengkap domain...\n")
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP Address: {ip}")

        try:
            response = requests.get("http://" + domain, timeout=5)
            print(Fore.CYAN + "[+] Server Headers:")
            for k, v in response.headers.items():
                print(f"    {k}: {v}")
        except:
            print(Fore.RED + "[-] Tidak dapat mengambil headers.")

        geo = requests.get(f"https://ipinfo.io/{ip}/json").json()
        print(Fore.GREEN + "[+] GeoIP:")
        print(f"    Location: {geo.get('city')}, {geo.get('region')} - {geo.get('country')}")
        print(f"    Org: {geo.get('org')}, ASN: {geo.get('asn', {}).get('asn')}")
        print(f"    ISP: {geo.get('org')}")

        try:
            rev = socket.gethostbyaddr(ip)[0]
            print(Fore.CYAN + f"[+] Reverse DNS: {rev}")
        except:
            print(Fore.RED + "[-] Reverse DNS tidak ditemukan.")

        print(Fore.GREEN + "[+] DNS Records:")
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    print(f"    {record_type}: {rdata.to_text()}")
            except:
                pass

        try:
            rdap = requests.get(f"https://rdap.org/domain/{domain}").json()
            print(Fore.CYAN + "[+] WHOIS Info:")
            print(f"    Registrar: {rdap.get('registrar', {}).get('name')}")
            print(f"    Email: {rdap.get('entities', [{}])[0].get('vcardArray', [''])[1][3][3]}")
            print(f"    Created: {rdap.get('events', [{}])[0].get('eventDate')}")
            print(f"    Expires: {rdap.get('events', [{}])[1].get('eventDate')}")
        except:
            print(Fore.RED + "[-] Gagal mengambil WHOIS RDAP.")

    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def extract_subdomains(domain):
    print(Fore.YELLOW + "\n[INFO] Mencari subdomain...\n")
    found = set()
    try:
        crt = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10).json()
        for entry in crt:
            for sub in entry['name_value'].split('\n'):
                if domain in sub:
                    found.add(sub.strip())
    except:
        print(Fore.RED + "[-] Gagal dari crt.sh")

    try:
        hacker = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}").text
        for line in hacker.strip().splitlines():
            sub = line.split(',')[0]
            if domain in sub:
                found.add(sub.strip())
    except:
        print(Fore.RED + "[-] Gagal dari hackertarget")

    if found:
        print(Fore.GREEN + f"[+] {len(found)} subdomain ditemukan:")
        for sub in sorted(found):
            print(Fore.CYAN + "    - " + sub)
    else:
        print(Fore.RED + "[-] Tidak ada subdomain ditemukan.")

    return sorted(found)

def extract_urls(domain, subdomains):
    print(Fore.YELLOW + "\n[INFO] Mengekstrak semua URL...\n")
    seen = set()
    all_urls = set()
    social_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com', 'instagram.com']

    def crawl(url, base):
        if url in seen or len(seen) > 100:
            return
        seen.add(url)
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')

            for tag in soup.find_all(['a', 'script', 'link', 'iframe', 'img']):
                attr = tag.get('href') or tag.get('src')
                if attr:
                    full_url = urljoin(base, attr)
                    if re.match(r'^https?://', full_url):
                        all_urls.add(full_url)

            scripts = soup.find_all("script")
            for script in scripts:
                if script.string:
                    urls_in_js = re.findall(r'https?://[^\s\'"<>]+', script.string)
                    for js_url in urls_in_js:
                        all_urls.add(js_url)

        except:
            pass

    crawl(f"http://{domain}", f"http://{domain}")
    for sub in subdomains:
        crawl(f"http://{sub}", f"http://{sub}")

    internal = [u for u in all_urls if domain in u]
    external = [u for u in all_urls if domain not in u]
    social = [u for u in all_urls if any(soc in u for soc in social_domains)]

    print(Fore.GREEN + f"[+] Total URL ditemukan: {len(all_urls)}")
    print(Fore.CYAN + f"    Internal: {len(internal)}")
    print(Fore.CYAN + f"    External: {len(external)}")
    print(Fore.CYAN + f"    Sosial Media: {len(social)}\n")

    for url in sorted(all_urls):
        print(Fore.GREEN + "    - " + url)

def detect_phishing_and_redirect(domain, subdomains):
    print(Fore.YELLOW + "\n[INFO] Mendeteksi link redirect dan phishing...\n")
    suspicious = []
    redirect_links = []
    phishing_keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update', 'signin', 'reset']

    checked = set()
    urls = set()

    def gather_links(url):
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            for tag in soup.find_all(['a', 'script', 'iframe', 'link']):
                attr = tag.get('href') or tag.get('src')
                if attr and attr.startswith('http'):
                    urls.add(attr)
        except:
            pass

    gather_links(f"http://{domain}")
    for sub in subdomains:
        gather_links(f"http://{sub}")

    for url in urls:
        if url in checked:
            continue
        checked.add(url)
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            if len(r.history) > 0:
                final = r.url
                if domain not in final:
                    redirect_links.append((url, final))
            for kw in phishing_keywords:
                if kw in url.lower():
                    parsed = urlparse(url)
                    if domain not in parsed.netloc:
                        suspicious.append(url)
        except:
            pass

    print(Fore.GREEN + f"[+] Redirect Terdeteksi: {len(redirect_links)}")
    for src, dst in redirect_links:
        print(Fore.CYAN + f"    {src}  -->  {dst}")

    print(Fore.GREEN + f"\n[+] Potensi Phishing URL: {len(suspicious)}")
    for s in suspicious:
        print(Fore.RED + "    ⚠️ " + s)

def menu():
    banner()
    while True:
        print(Fore.YELLOW + "\n[ MENU ]")
        print(Fore.CYAN + "1. Info Website")
        print(Fore.CYAN + "2. Subdomain Scanner")
        print(Fore.CYAN + "3. URL Extrator")
        print(Fore.CYAN + "4. Deteksi Redirect & Link Phishing")
        print(Fore.RED + "0. Keluar")
        choice = input(Fore.MAGENTA + "\nPilih menu: ").strip()

        if choice == "1":
            target = input(Fore.CYAN + "Masukkan domain target: ").strip()
            get_info(target)
        elif choice == "2":
            target = input(Fore.CYAN + "Masukkan domain target: ").strip()
            extract_subdomains(target)
        elif choice == "3":
            target = input(Fore.CYAN + "Masukkan domain target: ").strip()
            subdomains = extract_subdomains(target)
            extract_urls(target, subdomains)
        elif choice == "4":
            target = input(Fore.CYAN + "Masukkan domain target: ").strip()
            subdomains = extract_subdomains(target)
            detect_phishing_and_redirect(target, subdomains)
        elif choice == "0":
            print(Fore.RED + "Keluar...")
            break
        else:
            print(Fore.RED + "Pilihan tidak valid!")

if __name__ == "__main__":
    menu()

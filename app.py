import socket
import sys
import ssl
import os
import requests
import urllib.request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore
import threading
import time
from bs4 import BeautifulSoup
import configparser
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import pandas as pd
import ipaddress
import whois
import csv

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white
Y = '\033[33m'  # yellow

init()

# Load IP2Location LITE CSV file
ip2location_db_path = 'geolocation_database.CSV'  # Update with your database path
ip2location_data = pd.read_csv(ip2location_db_path, header=None, names=[
    'IP_FROM', 'IP_TO', 'COUNTRY_CODE', 'COUNTRY_NAME', 'REGION_NAME', 'CITY_NAME', 'LATITUDE', 'LONGITUDE'
])

# Convert IP_FROM and IP_TO to integers for easier comparison
ip2location_data['IP_FROM'] = ip2location_data['IP_FROM'].apply(int)
ip2location_data['IP_TO'] = ip2location_data['IP_TO'].apply(int)

def is_using_cloudflare(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        headers = response.headers
        if "server" in headers and "cloudflare" in headers["server"].lower():
            return True
        if "cf-ray" in headers:
            return True
        if "cloudflare" in headers:
            return True
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass

    return False

def detect_web_server(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        server_header = response.headers.get("Server")
        if server_header:
            return server_header.strip()
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass

    return "UNKNOWN"

wordlist_url = "https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt"
default_wordlist = "wordlist.txt"
updated_wordlist = "wordlist.txt"

def download_wordlist(wordlist_path):
    print(f"\n{Fore.GREEN}[+] {C}Downloading an updated wordlist from {Fore.GREEN}SecLists{Fore.RESET}")
    try:
        urllib.request.urlretrieve(wordlist_url, wordlist_path)
        print(f"{Fore.GREEN}[+] {C}Wordlist downloaded successfully as {Fore.GREEN}{wordlist_path}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] {C}Error downloading wordlist: {Fore.RED}{e}{Fore.RESET}")
        print(f"{Fore.GREEN}[+] {C}Using the existing wordlist {Fore.GREEN}{updated_wordlist}{Fore.RESET}")
        return updated_wordlist

def get_ssl_certificate_info(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(True)
                certificate = x509.load_der_x509_certificate(der_cert, default_backend())
                common_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                issuer = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                validity_start = certificate.not_valid_before
                validity_end = certificate.not_valid_after

                return {
                    "Common Name": common_name,
                    "Issuer": issuer,
                    "Validity Start": validity_start,
                    "Validity End": validity_end,
                }
    except Exception as e:
        print(f"{Fore.RED}Error extracting SSL certificate information: {e}{Fore.RESET}")
        return None

def find_subdomains_with_ssl_analysis(domain, wordlist_path=None, timeout=2, max_threads=10, max_subdomains=500):
    subdomains_found = []
    subdomains_lock = threading.Lock()
    stop_search = threading.Event()

    def check_subdomain(subdomain):
        if stop_search.is_set():
            return
        protocols = {
            "http": 80,
            "https": 443,
            "smtp": 25,
            "ftp": 21,
            "pop3": 110,
            "imap": 143,
            "smtps": 465,
            "pop3s": 995,
            "imaps": 993,
            "ldap": 389,
            "ldaps": 636,
            "mysql": 3306,
            "postgresql": 5432,
            "mssql": 1433,
            "mongodb": 27017,
            "redis": 6379,
            "memcached": 11211
        }
        for protocol, port in protocols.items():
            subdomain_url = f"{protocol}://{subdomain}.{domain}"
            try:
                if protocol in ["http", "https"]:
                    response = requests.get(subdomain_url, timeout=timeout)
                    if response.status_code == 200:
                        with subdomains_lock:
                            if len(subdomains_found) >= max_subdomains:
                                stop_search.set()
                                return
                            subdomains_found.append(subdomain_url)
                            print(f"Subdomain Found: {subdomain_url}")
                else:
                    with socket.create_connection((f"{subdomain}.{domain}", port), timeout=timeout) as sock:
                        with subdomains_lock:
                            if len(subdomains_found) >= max_subdomains:
                                stop_search.set()
                                return
                            subdomains_found.append(subdomain_url)
                            print(f"Subdomain Found: {subdomain_url}")
            except (requests.exceptions.RequestException, socket.error):
                pass  # Ignore exceptions and continue

    if wordlist_path is None:
        default_wordlist = "wordlist.txt"
        wordlist_path = input("> Do you have a custom wordlist for subdomain scanning? (yes/no): ").lower()
        if wordlist_path == "yes":
            wordlist_path = input("> Enter the path to your custom wordlist: ")
        else:
            wordlist_path = default_wordlist

    with open(wordlist_path, "r") as file:
        subdomains = [line.strip() for line in file.readlines()]

    print("Starting threads...")
    start_time = time.time()

    # Use ThreadPoolExecutor to limit the number of concurrent threads
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_subdomain, subdomain) for subdomain in subdomains]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Checking subdomains"):
            if stop_search.is_set():
                break
            try:
                future.result()  # Wait for all threads to complete
            except Exception as e:
                print(f"Error in thread: {e}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nTotal Subdomains Scanned: {len(subdomains)}")
    print(f"Total Subdomains Found: {len(subdomains_found)}")
    print(f"Time taken: {elapsed_time:.2f} seconds")

    real_ips = []

    for subdomain in subdomains_found:
        subdomain_parts = subdomain.split('//')
        if len(subdomain_parts) > 1:
            host = subdomain_parts[1]
            real_ip = get_real_ip(host)
            if real_ip:
                org_name, asn = get_org_name_and_asn(real_ip)
                geolocation = get_ip_geolocation(real_ip)
                real_ips.append((host, real_ip, org_name, asn, geolocation))
                print(f"\nReal IP Address of {host}: {real_ip} (Org: {org_name}, ASN: {asn}, Location: {geolocation})")

                ssl_info = get_ssl_certificate_info(host)
                if ssl_info:
                    print("   [+] SSL Certificate Information:")
                    for key, value in ssl_info.items():
                        print(f"      {key}: {value}")

    if not real_ips:
        print("No real IP addresses found for subdomains.")
    else:
        print("\nTask Complete!!\n")

    return real_ips

def get_real_ip(host):
    try:
        real_ip = socket.gethostbyname(host)
        return real_ip
    except socket.gaierror:
        return None

def get_org_name_and_asn(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            org = data.get("org", "Unknown")
            asn = data.get("asn", {}).get("asn", "Unknown")
            return org, asn
        else:
            return "Unknown", "Unknown"
    except requests.RequestException:
        return "Unknown", "Unknown"

def get_ip_geolocation(ip):
    ip_int = int(ipaddress.ip_address(ip))
    row = ip2location_data[(ip2location_data['IP_FROM'] <= ip_int) & (ip2location_data['IP_TO'] >= ip_int)]
    if not row.empty:
        country = row.iloc[0]['COUNTRY_NAME']
        region = row.iloc[0]['REGION_NAME']
        city = row.iloc[0]['CITY_NAME']
        return f"{city}, {region}, {country}"
    return "Unknown"

#Read config file
def read_config():
    config = configparser.ConfigParser()
    #check if config file exists
    if not os.path.exists('config.ini'):
        #create config file
        # Create the [DEFAULT] section and set the securitytrails_api_key option
        config["DEFAULT"] = {
        "securitytrails_api_key": "your_api_key"}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        print(f"\n[!] {Fore.RED}Please add your {C}SecurityTrails{Fore.RED} API Key in config.ini file{Fore.RESET}")
    else:
        config.read('config.ini')
        APIKEY = config['DEFAULT']['securitytrails_api_key']
        return APIKEY

def securitytrails_historical_ip_address(domain):
    historical_ips = []
    if read_config():
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {
        "accept": "application/json",
        "APIKEY": read_config()}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Historical IP Address Info from {C}SecurityTrails{Y} for {Fore.GREEN}{domain}:{W}")
            for record in data['records']:
                ip = record["values"][0]["ip"]
                first_seen = record["first_seen"]
                last_seen = record["last_seen"]
                organizations = record["organizations"][0]
                historical_ips.append((ip, first_seen, last_seen, organizations))
                print(f"\n{R} [+] {C}IP Address: {R}{ip}{W}")
                print(f"{Y}  \u2514\u27A4 {C}First Seen: {G}{first_seen}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Last Seen: {G}{last_seen}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Organizations: {G}{organizations}{W}")
        except:
            print(f"{Fore.RED}Error extracting Historical IP Address information from SecurityTrails{Fore.RESET}")
            None
    else:
        print(f"\n{Fore.RED}Please add your {C}SecurityTrails{Fore.RED} API Key in config.ini file{Fore.RESET}")
        None
    return historical_ips

def get_domain_historical_ip_address(domain):
    historical_ips = []
    try:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",

        }
        response = requests.get(url, headers=headers)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table', {'border': '1'})

        if table:
            rows = table.find_all('tr')[2:]
            print(f"\n{Fore.GREEN}[+] {Fore.YELLOW}Historical IP Address Info from {C}Viewdns{Y} for {Fore.GREEN}{domain}:{W}")
            for row in rows:
                columns = row.find_all('td')
                ip_address = columns[0].text.strip()
                location = columns[1].text.strip()
                owner = columns[2].text.strip()
                last_seen = columns[3].text.strip()
                historical_ips.append((ip_address, location, owner, last_seen))
                print(f"\n{R} [+] {C}IP Address: {R}{ip_address}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Location: {G}{location}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Owner: {G}{owner}{W}")
                print(f"{Y}  \u2514\u27A4 {C}Last Seen: {G}{last_seen}{W}")
        else:
            None
    except:
        None
    return historical_ips

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: x.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    
    # Extract domain if a full URL is provided
    parsed_url = urlparse(domain)
    if (parsed_url.scheme):
        domain = parsed_url.netloc

    filename = "wordlist.txt"
    CloudFlare_IP = get_real_ip(domain)

    print(f"\n{Fore.GREEN}[!] {C}Checking if the website uses Cloudflare{Fore.RESET}\n")

    historical_ips = get_domain_historical_ip_address(domain)
    securitytrails_ips = securitytrails_historical_ip_address(domain)
    subdomain_data = find_subdomains_with_ssl_analysis(domain, max_threads=2000)  # Adjust max_threads as needed

    if is_using_cloudflare(domain):
        print(f"\n{R}Target Website: {W}{domain}")
        print(f"{R}Visible IP Address: {W}{CloudFlare_IP}\n")
    else:
        technology = detect_web_server(domain)
        real_ip = get_real_ip(domain)
        org_name, asn = get_org_name_and_asn(real_ip)
        geolocation = get_ip_geolocation(real_ip)

        # Collect data into a dictionary
        data = {
            "Website": domain,
            "Technology": technology,
            "Real IP": real_ip,
            "Org Name": org_name,
            "ASN": asn,
            "Geolocation": geolocation
        }

        # Write data to a CSV file
        csv_file = "output.csv"
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=data.keys())
            writer.writeheader()
            writer.writerow(data)

        print(f"\n{Fore.GREEN}[+] {C}Website is using: {Fore.GREEN}{technology}{C}, Real IP: {Fore.GREEN}{real_ip}{C}, Org: {Fore.GREEN}{org_name}{C}, ASN: {Fore.GREEN}{asn}{C}, Location: {Fore.GREEN}{geolocation}{Fore.RESET}")

    # Write historical IPs and subdomain data to CSV
    with open("output.csv", mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Historical IPs from ViewDNS"])
        writer.writerow(["IP Address", "Location", "Owner", "Last Seen"])
        for ip in historical_ips:
            writer.writerow(ip)

        writer.writerow(["Historical IPs from SecurityTrails"])
        writer.writerow(["IP Address", "First Seen", "Last Seen", "Organizations"])
        for ip in securitytrails_ips:
            writer.writerow(ip)

        writer.writerow(["Subdomains with SSL Analysis"])
        writer.writerow(["Subdomain", "Real IP", "Org Name", "ASN", "Geolocation", "Common Name", "Issuer", "Validity Start", "Validity End"])
        for subdomain in subdomain_data:
            host, real_ip, org_name, asn, geolocation = subdomain
            ssl_info = get_ssl_certificate_info(host)
            if ssl_info:
                writer.writerow([host, real_ip, org_name, asn, geolocation, ssl_info["Common Name"], ssl_info["Issuer"], ssl_info["Validity Start"], ssl_info["Validity End"]])
            else:
                writer.writerow([host, real_ip, org_name, asn, geolocation, "N/A", "N/A", "N/A", "N/A"])

    print(f"\n{Fore.GREEN}[+] {C}All data has been written to {Fore.GREEN}output.csv{Fore.RESET}")

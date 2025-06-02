# hideFlare

hideFlare is a Python tool designed to uncover the real hosting details of websites that use Cloudflare’s services to mask their infrastructure. Many suspicious websites use Cloudflare, making it difficult to trace the actual hosting provider. hideFlare helps security researchers, investigators, and analysts reveal the true origin behind such domains.

## Features

- Detects if a website is using Cloudflare as a proxy.
- Attempts to discover the real IP address of the target website.
- Uses multiple techniques, including:
  - Subdomain enumeration with SSL analysis.
  - Web server technology detection.
  - ASN and organization lookup for discovered IPs.
  - Geolocation of the real IP address.
  - Historical IP resolution (via SecurityTrails and other methods).
- Outputs results to a CSV file for easy analysis.
- Customizable wordlists for subdomain brute-forcing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/anujjainbatu/hideFlare.git
   cd hideFlare
   ```

2. Install dependencies (Python 3.x required):
   ```bash
   pip install -r requirements.txt
   ```
   *(If `requirements.txt` is missing, please list required packages here.)*

## Usage

```bash
python app.py <domain>
```

Example:
```bash
python app.py example.com
```

- The script will check if the target uses Cloudflare and attempt to discover its real hosting information.
- Results are printed to the console and saved to `output.csv`.

## How it Works

- Checks HTTP response headers to detect Cloudflare.
- Performs subdomain brute force (using `wordlist.txt` or `default_wordlist.txt`).
- Analyzes SSL certificates for potential origin leaks.
- Looks up ASN, organization name, and geolocation for discovered IPs.
- Optionally uses historical IP lookups.

## Files

- `app.py` — Main application logic.
- `wordlist.txt` / `default_wordlist.txt` — Wordlists for subdomain enumeration.

## Limitations

- Results may not always be 100% accurate due to the nature of web infrastructure obfuscation.
- Some websites may have additional layers of protection.

## License
This project is open source and licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

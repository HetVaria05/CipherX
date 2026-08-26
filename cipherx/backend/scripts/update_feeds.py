import urllib.request
import csv
import json
import os
import io
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"

def main():
    logger.info(f"Downloading active threat feed from {URLHAUS_CSV_URL}...")
    try:
        req = urllib.request.Request(URLHAUS_CSV_URL, headers={"User-Agent": "CipherX-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8')
        
        logger.info("Download complete. Parsing CSV data...")
        
        # URLhaus CSV has comments starting with #
        lines = [line for line in content.splitlines() if not line.startswith('#')]
        
        # CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        reader = csv.reader(io.StringIO("\n".join(lines)))
        
        malicious_urls = {}
        for row in reader:
            if len(row) >= 7:
                url = row[2].strip()
                threat = row[5].strip()
                tags = row[6].strip()
                
                malicious_urls[url] = {
                    "threat": threat,
                    "family": tags if tags else "Malware",
                    "source": "URLhaus (local)"
                }
                
                # Also extract domain/hostname for broader matching
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(url).hostname
                    if hostname:
                        malicious_urls[hostname] = {
                            "threat": threat,
                            "family": tags if tags else "Malware",
                            "source": "URLhaus (local)"
                        }
                except Exception:
                    pass

        logger.info(f"Extracted {len(malicious_urls)} unique IOCs (URLs + Hostnames).")
        
        # Save to data/malicious_feed.json
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(current_dir), "data")
        os.makedirs(data_dir, exist_ok=True)
        
        output_file = os.path.join(data_dir, "malicious_feed.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(malicious_urls, f)
            
        logger.info(f"Successfully saved threat dataset to {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to update feeds: {e}")

if __name__ == "__main__":
    main()

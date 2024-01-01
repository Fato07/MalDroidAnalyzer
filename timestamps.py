import requests
import csv
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(filename='update_csv.log', filemode='w', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

api_key = 'e33c206ec5dcf516023aac31c0d2204db68e88c6cffc82d4b6cb26cb06427fd9'  # Replace with your VirusTotal API key

def convert_timestamp(unix_timestamp):
    """Convert Unix timestamp to human-readable date."""
    return datetime.utcfromtimestamp(int(unix_timestamp)).strftime('%Y-%m-%d %H:%M:%S')

def get_first_submission_date_and_family(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        first_submission_date = json_response['data']['attributes']['first_submission_date']
        first_submission_date = convert_timestamp(first_submission_date)
        try:
            family = json_response['data']['attributes']['popular_threat_classification']['suggested_threat_label']
        except KeyError:
            family = 'Unknown'
        return first_submission_date, family
    return None, 'Unknown'

with open('analysis_results_with_dates_and_family.csv', 'r') as infile, open('updated_analysis_results_with_dates_and_family.csv', 'w', newline='') as outfile:
    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames  # Assuming the fields already exist
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        if row['malware_family'] == 'unknown' and row['first_submission_date'] == 'not found':
            hash_value = row['file_hash']
            logging.info(f"Updating record for hash: {hash_value}")
            try:
                first_seen_date, family = get_first_submission_date_and_family(hash_value)
                row['first_submission_date'] = first_seen_date if first_seen_date else 'Not found'
                row['malware_family'] = family
            except Exception as e:
                logging.error(f"Error updating record for hash {hash_value}: {e}")
        writer.writerow(row)
        time.sleep(15)  # Sleep to respect the API rate limit
        logging.info("Successfully updated row in CSV.")

logging.info("Finished updating the CSV with timestamps and malware family.")

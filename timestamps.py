import requests
import csv
import time
from datetime import datetime

api_key = 'e33c206ec5dcf516023aac31c0d2204db68e88c6cffc82d4b6cb26cb06427fd9'  # Replace with your VirusTotal API key

# Function to convert Unix timestamp to human-readable format
def convert_timestamp(unix_timestamp):
    """Convert Unix timestamp to human-readable date."""
    return datetime.utcfromtimestamp(int(unix_timestamp)).strftime('%Y-%m-%d %H:%M:%S')

# Function to get first submission date from VirusTotal
def get_first_submission_date(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        first_submission_date = json_response['data']['attributes']['first_submission_date']
        return convert_timestamp(first_submission_date)
    return None

# Read hashes from CSV, query VirusTotal, and write back to CSV
with open('analysis_results.csv', 'r') as infile, open('analysis_results_with_dates.csv', 'w', newline='') as outfile:
    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames + ['first_submission_date']
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        hash_value = row['file_hash']
        first_seen_date = get_first_submission_date(hash_value)
        if first_seen_date:
            row['first_submission_date'] = first_seen_date
        else:
            row['first_submission_date'] = 'Not found'
        writer.writerow(row)
        time.sleep(15)  # Sleep to respect the API rate limit

print("Finished updating the CSV with timestamps.")

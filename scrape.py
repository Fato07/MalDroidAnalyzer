import os
import requests
from bs4 import BeautifulSoup
import time
import re

def download_apk(download_url, output_folder):
    app_name = os.path.basename(download_url)  # Extracts the file name from the URL
    response = requests.get(download_url)
    if response.status_code == 200:
        with open(os.path.join(output_folder, app_name), 'wb') as file:
            file.write(response.content)
        print(f"Downloaded {app_name}")
    else:
        print(f"Failed to download {app_name}")

def get_app_links(category_url):
    response = requests.get(category_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True) if '/en/packages/' in a['href']]

def get_apk_download_link(app_page_url):
    full_url = f"https://f-droid.org{app_page_url}"
    response = requests.get(full_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Use a regular expression to find the APK download link
    apk_link_pattern = re.compile(r'https://f-droid.org/repo/.+\.apk')
    apk_link = soup.find('a', href=apk_link_pattern)
    if apk_link and 'href' in apk_link.attrs:
        return apk_link['href']
    else:
        return None

def main():
    category_url = 'https://f-droid.org/en/categories/development/4/index.html'
    output_folder = 'downloaded_apks'
    os.makedirs(output_folder, exist_ok=True)

    app_links = get_app_links(category_url)

    for app_link in app_links:
        apk_download_link = get_apk_download_link(app_link)
        if apk_download_link:
            download_apk(apk_download_link, output_folder)
            time.sleep(1)  # Respectful scraping by adding delay

if __name__ == "__main__":
    main()

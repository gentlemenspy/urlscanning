import requests
import time
from requests.exceptions import RequestException

# Function to check internet connectivity
def check_internet_connection():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except RequestException:
        return False

# Function to get input from the user
def get_user_input(prompt):
    return input(prompt)

api_key = 'ad404788720b87bc5a826648b0321313c92c8109e3e527a4ed4b5e92ec13a077'

# Function to scan a URL
def scan_url(api_key, url):
    params = {'apikey': api_key, 'url': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    return response.json()

# Function to retrieve URL scan report and provide detailed results
def get_url_report(api_key, resource):
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    result = response.json()
    # Provide detailed results
    if result.get('positives', 0) > 0:
        reasons = [v['result'] for v in result['scans'].values() if v['detected']]
        return f"The URL is suspicious for the following reasons: {', '.join(reasons)}"
    else:
        return "The URL is safe."

# Function to scan a domain and provide detailed results
def scan_domain(api_key, domain):
    url = f'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey': api_key, 'domain': domain}
    response = requests.get(url, params=params)
    result = response.json()

    detected_reasons = []

    # Check for detected URLs
    if 'detected_urls' in result and result['detected_urls']:
        for url_info in result['detected_urls']:
            detected_reasons.append(f"URL: {url_info['url']} with {url_info['positives']} positives")
    
    # Check for categories
    categories = result.get('categories', {})
    categories_reasons = [f"Category: {category}" for category in categories.values()]

    if detected_reasons:
        reasons_str = "\n".join(detected_reasons)
        return f"The domain is suspicious for the following reasons:\n{reasons_str}"
    elif categories_reasons:
        reasons_str = "\n".join(categories_reasons)
        return f"The domain has the following categorizations:\n{reasons_str}"
    else:
        return "The domain is safe."

# Main function to handle the scanning process
def main():
    # Check internet connection
    if not check_internet_connection():
        print("Please check your internet connection.")
        return

    while True:
        # Get the type of scan from the user
        scan_type = get_user_input("Enter the type of scan (url/file/domain): ").lower()

        if scan_type not in ['url', 'file', 'domain']:
            print("Invalid scan type entered. Please try again.")
            continue

        if scan_type == 'url':
            # Get the URL to scan from the user
            url_to_scan = get_user_input("Enter the URL to scan: ")
            scan_result = scan_url(api_key, url_to_scan)
            report = get_url_report(api_key, scan_result['scan_id'])
            print(report)
        elif scan_type == 'file':
            # Placeholder for file scanning (not implemented)
            print("File scanning is not implemented in this example.")
        elif scan_type == 'domain':
            # Get the domain to scan from the user
            domain_to_scan = get_user_input("Enter the domain to scan: ")
            report = scan_domain(api_key, domain_to_scan)
            print(report)

        # Ask user if they want to perform another scan
        choice = get_user_input("Do you want to perform another scan? (yes/no): ").lower()
        if choice != 'yes':
            break

if __name__ == "__main__":
    main()

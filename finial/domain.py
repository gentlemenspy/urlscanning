import requests
from requests.exceptions import RequestException

def run(api_key, domain):
    base_url = 'https://www.virustotal.com/api/v3/domains/'
    url = f"{base_url}{domain}"
    headers = {'x-apikey': api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()

        if 'data' in result and 'attributes' in result['data']:
            attributes = result['data']['attributes']
            if attributes.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                scans = attributes.get('last_analysis_results', {})
                reasons = [v['result'] for v in scans.values() if v['category'] == 'malicious']
                message = f"The domain is suspicious for the following reasons: {', '.join(reasons)}"
            else:
                message = "The domain is safe."
        else:
            message = "No data available for the provided domain."
    except RequestException as e:
        message = f"An error occurred during the request: {str(e)}"
    except KeyError as e:
        message = f"Unexpected response format: missing key {str(e)}"
    except Exception as e:
        message = f"An error occurred: {str(e)}"

    print(message)

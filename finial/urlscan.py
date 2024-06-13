import requests
import time

def run(api_key, user_url):
    virus_url = 'https://www.virustotal.com/api/v3/urls'
    url_repo = 'https://www.virustotal.com/api/v3/analyses/'

    def url_submit(api_key, url):
        headers = {'x-apikey': api_key}
        data = {'url': url}
        response = requests.post(virus_url, headers=headers, data=data)
        return response.json()
    
    def url_report(api_key, analysis_id):
        headers = {'x-apikey': api_key}
        response = requests.get(f"{url_repo}{analysis_id}", headers=headers)
        result = response.json()
        try:
            if result.get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0) > 0:
                reasons = [v['result'] for v in result['data']['attributes']['results'].values() if v['category'] == 'malicious']
                return f"The URL is suspicious for the following reasons: {', '.join(reasons)}"
            else:
                return "The URL is safe."
        except Exception as e:
            return f"Error checking URL: {str(e)}"

    submission_result = url_submit(api_key, user_url)
    analysis_id = submission_result.get('data', {}).get('id', None)

    if analysis_id:
        time.sleep(30)
        report = url_report(api_key, analysis_id)
        print(report)
    else:
        print("Error submitting URL.")

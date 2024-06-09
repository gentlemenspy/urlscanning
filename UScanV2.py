import requests
import time
import hashlib

class Urlscan():
    def __init__(self) -> None:
       
        self.api = 'ad404788720b87bc5a826648b0321313c92c8109e3e527a4ed4b5e92ec13a077'
        self.user = input("Enter your option: ")
        self.virus_url = 'https://www.virustotal.com/api/v3/urls'
        self.url_repo = 'https://www.virustotal.com/api/v3/analyses/'
        self.virus_domain = 'https://www.virustotal.com/api/v3/domains/'

    def url(self):
        cool = self.user
        params = {'api':self.api, 'url':cool}
        response = requests.post(self.virus_url, data = params)
        return response.json()
    
    def url_report(self, resource):
        params = {'api':self.api, 'resource': resource}
        responce = requests.get(self.url_repo, params=params)
        result = responce.json()
        try:
            if result.get('positive', 0) > 0:
                reasons = [v['result'] for v in result['scans'].values() if v['detected']]
                return f"The URL is suspicious for the following reasons: {', '.join(reasons)}"
            else:
                return "The URL is safe."
        except:
            return "check url connection"
    
    def domain(self, domain):
        params = {'api':self.api, 'domain' : domain}
        response = requests.get(self.virus_domain, params=params)
        result = response.json()
        try:
            if result['data']['attributes']['last_analysis_stats'].get('malicious', 0) > 0:
                scans = result['data']['attributes']['last_analysis_results']
                reasons = [v['result'] for v in scans.values() if v['category'] == 'malicious']
                message = f"The URL is suspicious for the following reasons: {', '.join(reasons)}"
            else:
                message = "The URL is safe."
        except:
            return f"An error occurred: {str(e)}"

    def file(self, file_path):
        md5_hash = hashlib.md5()
        try:
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            return "File not found."
        except Exception as e:
            return f"An error occurred: {str(e)}"
urlscan=Urlscan()
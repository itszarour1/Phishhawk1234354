import requests
import time

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def scan_url(self, link):
        data = {"url": link}
        try:
            scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=self.headers, data=data)
            if scan_response.status_code == 200:
                analysis_id = scan_response.json()["data"]["id"]
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                time.sleep(5)
                analysis_response = requests.get(result_url, headers=self.headers)
                if analysis_response.status_code == 200:
                    stats = analysis_response.json()["data"]["attributes"]["stats"]
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0)
                    }
        except Exception as e:
            print(f"Error in VirusTotal scan: {e}")
        return {"malicious": 0, "suspicious": 0}

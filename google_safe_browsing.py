import requests

class GoogleSafeBrowsingChecker:
    def __init__(self, api_key):
        self.api_key = api_key

    def check(self, link):
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        body = {
            "client": {"clientId": "phishhawk", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": link}]
            }
        }
        try:
            response = requests.post(url, json=body)
            print(f"Response status code: {response.status_code}")  # طباعة رمز الحالة
            print(f"Response text: {response.text}")  # طباعة نص الرد بالكامل
            if response.status_code == 200:
                data = response.json()
                if "matches" in data:
                    return True
                else:
                    return False
            else:
                return None
        except Exception as e:
            print(f"Exception: {e}")  # طباعة الاستثناءات
            return None

import urllib.parse
import tldextract

class LinkAnalyzer:
    phishing_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'confirm', 'signin', 'password']
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'rebrand.ly', 'goo.gl']

    def __init__(self, link, virustotal_result=None, google_safe=True):
        self.link = link
        self.virustotal_result = virustotal_result or {"malicious": 0, "suspicious": 0}
        self.google_safe = google_safe
        self.parsed = urllib.parse.urlparse(link)
        self.domain = self.parsed.netloc
        self.path = self.parsed.path
        self.query = self.parsed.query
        self.ext = tldextract.extract(self.domain)
        self.subdomain = self.ext.subdomain
        self.score = 0
        self.reasons = []

    def analyze(self):
        for word in self.phishing_keywords:
            if word in self.link.lower():
                self.score += 1
                self.reasons.append(f"كلمة مشبوهة: '{word}'")

        for short in self.shorteners:
            if short in self.domain:
                self.score += 2
                self.reasons.append(f"رابط مختصر: '{short}'")

        if len(self.subdomain.split('.')) > 2:
            self.score += 1
            self.reasons.append("دومين فرعي غير معتاد")

        if self.domain.count('-') > 2:
            self.score += 1
            self.reasons.append("عدد كبير من الشرطات (-) في الدومين")

        if self.link.count('.') > 4:
            self.score += 1
            self.reasons.append("عدد كبير من النقاط في الرابط")

        if self.virustotal_result["malicious"] > 0 or self.virustotal_result["suspicious"] > 0:
            self.reasons.append(f"🦠 VirusTotal كشف {self.virustotal_result['malicious']} خبيث و {self.virustotal_result['suspicious']} مشبوه")
            return "❌ Phishing"

        if not self.google_safe:
            self.reasons.append("🚨 Google Safe Browsing: غير آمن")
            return "❌ Phishing"

        if self.score == 0:
            return "✅ Safe"
        elif self.score <= 2:
            return "⚠️ Suspicious"
        else:
            return "❌ Phishing"

    def get_details(self):
        return {
            "domain": self.domain,
            "path": self.path,
            "query": self.query,
            "reasons": self.reasons
        }

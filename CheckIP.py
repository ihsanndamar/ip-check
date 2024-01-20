import requests
import dns.resolver


API_URL = "https://otx.alienvault.com/api/v1"
API_KEY = ""
API_HEADER = {"X-OTX-API-KEY": API_KEY}

IPv4 = "/IPv4/"
IPv6 = "/IPv6/"

class CheckIP:
    def __init__(self, input: str, isDomain = False):
        self.IsMalicious = False
        self.EnumerationResult = []
        self.country = ""
        self.asn = ""
        self.type = ""
        if isDomain==True:
            record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

            # Create a DNS resolver
            resolver = dns.resolver.Resolver()
            for record_type in record_types:
                # Perform DNS lookup for the specified domain and record type
                try:
                    answers = resolver.resolve(input, record_type)
                except dns.resolver.NoAnswer:
                    continue

                for rdata in answers:
                    self.EnumerationResult.append({"record_type": record_type, "rdata": rdata.to_text()})
                    if(record_type == "A"):
                        self.ip = rdata.to_text()
        else:
            self.ip = input

        self.information_from_whois()
        self.check()

    def to_string(self):
        return self.ip

    def information_from_whois(self):
        url = API_URL + "/indicators" + IPv4 + self.ip + "/general"
        try:
            response = requests.get(url, headers=API_HEADER)
            if response.status_code == 200:
                result = response.json()

                self.country = result["country_name"]
                self.asn = result["asn"]
                self.type = result["type"]

                return result.__str__()
            else:
                return "none"
        except:
            return "none"

    def check(self):
        url = API_URL + "/indicators" + IPv4 + self.ip + "/malware"
        try:
            response = requests.get(url, headers=API_HEADER)
            if response.status_code == 200:
                result = response.json()
                if (result["count"] > 0):
                    self.IsMalicious = True
                else:
                    self.IsMalicious = False

                return result.__str__()
            else:
                return "none"
        except:
            return "none"


if __name__ == '__main__':
    print(CheckIP("google.com", True).EnumerationResult)



#import dependencies for project
import re
import requests

def search_threat_indicators(indicators):
    #Add your Threat URLs below
    threat_sources = ["", ""]
    malicious_indicators = set()
    for source in threat_sources:
        for indicator in indicators:
            response = requests.get(f"{source}/search/{indicator}")
            if response.status_code == 200 and response.json().get("malicious"):
                malicious_indicators.add(indicator)

    return malicious_indicators

#define function
def analyze_logs(log_data, ip_suspicious=None):
    #define regular expressions to identify suspicious behavior patterns
    ip_pattern = r"\d{1,3}\. \d{1,3}\. \d{1,3}\. \d{1,3}"
    suspicious_ips = set()

    for line in log_data:
        #Extract IP addresses from log lines
        ips = re.findall(ip_pattern, line)
        for ip in ips:
            #perform additional checks or analysis here
            if ip_suspicious(ip):
                suspicious_ips.add(ip)
        
        return suspicious_ips

log_data = ["Analyze from 192.168.1.1 - unauthorized", "Access from 10.0.0.2 - Authorized"]
suspicious_ips = analyze_logs(log_data)
print(f"Suspicious IPs: {suspicious_ips}")


import shodan
import requests
import json

shodan_api_key = ""
api = shodan.Shodan(shodan_api_key)

threatfox_api_key = ""
threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"

def search_ioc_in_threatfox(ip):
    headers = {"Auth-Key": threatfox_api_key}
    data = {
        "query": "search_ioc",
        "search_term": ip
    }
    response = requests.post(threatfox_url, headers=headers, data=json.dumps(data))
    return response.json()

def submit_ioc_to_threatfox(ip_port):
    headers = {"Auth-Key": threatfox_api_key}
    data = {
        "query": "submit_ioc",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "tags": "CobaltStrike",
        "malware": "win.cobalt_strike",
        "confidence_level": 75,
        "iocs": [ip_port],
        "comment": "Shodan API Pull",
        "anonymous": 0 
    }
    response = requests.post(threatfox_url, headers=headers, data=json.dumps(data))
    return response.json()

try:
    query = 'product:"Cobalt Strike Beacon"'
    results = api.search(query)
    
    if results['total'] > 0:
        for result in results['matches']: 
            ip = result['ip_str']
            port = result['port']
            ip_port = f"{ip}:{port}"

            threatfox_response = search_ioc_in_threatfox(ip_port)
            if threatfox_response.get('query_status') == 'no_result': 
                print(f"No results found for {ip_port}, submitting to ThreatFox.")
                submission_response = submit_ioc_to_threatfox(ip_port)
                print(f"Submission Response: {submission_response}")
            else:
                print(f"Found {ip_port} in ThreatFox, skipping submission.")
    else:
        print("No results from Shodan")

except shodan.APIError as e:
    print(f"Error from Shodan API: {str(e)}")
except Exception as e:
    print(f"General Error: {str(e)}")

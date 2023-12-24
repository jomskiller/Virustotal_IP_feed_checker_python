import requests

def check_ip_reputation_vt(ip_address, api_key):
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key,
    }

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if "data" in result and "attributes" in result["data"]:
                attributes = result["data"]["attributes"]
                if "last_analysis_stats" in attributes:
                    stats = attributes["last_analysis_stats"]
                    malicious_count = stats["malicious"]
                    if malicious_count > 0:
                        return f"The IP address {ip_address} is Malicious."
                    else:
                        return f"The IP address {ip_address} is Clean."
                else:
                    return f"No reputation data available for {ip_address}."
            else:
                return f"Unexpected response format from VirusTotal: {result}"
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error: {e}"

def check_ip_addresses_in_file(file_path, api_key):
    try:
        with open(file_path, "r") as file:
            ip_addresses = [line.strip() for line in file.readlines()]

        results = []
        for ip_address in ip_addresses:
            result = check_ip_reputation_vt(ip_address, api_key)
            print(result)  # Print result for each IP address immediately
            results.append(result)

        return results
    except Exception as e:
        return [f"Error: {e}"]

# Example usage
file_path = "PUT THE FILE PATH OF YOUR IP ADDRESS LIST HERE"  # Replace with the path to your text file
vt_api_key = "PUT YOUR VT API KEY HERE"
results = check_ip_addresses_in_file(file_path, vt_api_key)

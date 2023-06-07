import csv
import virustotal_python
from base64 import urlsafe_b64encode
from api import api_function

with open('dns_data.csv', 'r', newline='') as csvfile:
    data = list(csv.reader(csvfile))

    with open('dns_analysis.csv', 'w', newline='') as savefile:
        fieldnames = ['DNS_Name', 'Harmless', 'Malicious', 'Suspicious', 'Undetected']
        writer = csv.DictWriter(savefile, fieldnames=fieldnames)
        writer.writeheader()

        for lines in data[1:]:
            if lines == "DNS not found":
                pass
            else:
                dns = lines[0]
                print(dns)
                country_S = api_function(dns)
                country_S = country_S[1] if country_S[0] == 'success' else 'NO COUNTRY NAME AVAILABLE'
                flag = 0
                with virustotal_python.Virustotal(
                        "4905a54d2595dd657db8b0ed31a5b043b0f3abfa120cff8ffe806db537b139eb") as vtotal:
                    flag = 0
                    try:
                        flag = 0
                        resp = vtotal.request("urls", data={"url": dns}, method="POST")
                        url_id = urlsafe_b64encode(dns.encode()).decode().strip("=")
                        report = vtotal.request(f"urls/{url_id}")
                        result = report.data['attributes']['last_analysis_stats']
                    except virustotal_python.VirustotalError as err:
                        flag = 1
                        result = f"Failed to send URL:{dns} for analysis and get the report: {err}"

                if flag == 0:
                    row = {
                        'DNS_Name': dns,
                        'Harmless': result['harmless'],
                        'Malicious': result['malicious'],
                        'Suspicious': result['suspicious'],
                        'Undetected': result['undetected']
                        # 'S_Country': country_S
                    }
                    writer.writerow(row)
                else:
                    print(result)

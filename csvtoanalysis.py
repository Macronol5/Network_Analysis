import csv
import virustotal_python
from base64 import urlsafe_b64encode
from api import api_function


with open('Public_IP.csv', 'r', newline='') as csvfile:
    data = list(csv.reader(csvfile))

    with open('csvtoanalysis.csv', 'w', newline='') as savefile:
        fieldnames = ['S_IP','S_Harmless','S_Malicious','S_Suspicious','S_Undetected','S_Country',' ','D_IP', 'D_Harmless','D_Malicious','D_Suspicious','D_Undetected','D_Country']
        writer = csv.DictWriter(savefile, fieldnames=fieldnames)
        writer.writeheader()

        for lines in data[1:]:
            print(lines)
            IP_S = lines[0]
            IP_D = lines[1]
            country_S = api_function(IP_S).split(',')
            country_D = api_function(IP_D).split(',')
            country_S = country_S[1] if country_S[0] == 'success' else 'NO COUNTRY NAME AVAILABLE'
            country_D = country_D[1] if country_D[0] == 'success' else 'NO COUNTRY NAME AVAILABLE'
            flag_S = 0
            with virustotal_python.Virustotal(
                    "4905a54d2595dd657db8b0ed31a5b043b0f3abfa120cff8ffe806db537b139eb") as vtotal:
                flag_S = 0
                try:
                    flag = 0
                    resp = vtotal.request("urls", data={"url": IP_S}, method="POST")
                    url_id = urlsafe_b64encode(IP_S.encode()).decode().strip("=")
                    report = vtotal.request(f"urls/{url_id}")
                    result = report.data['attributes']['last_analysis_stats']
                except virustotal_python.VirustotalError as err:
                    flag = 1
                    result = f"Failed to send URL:{IP_S} for analysis and get the report: {err}"

            flag_D = 0
            with virustotal_python.Virustotal(
                    "4905a54d2595dd657db8b0ed31a5b043b0f3abfa120cff8ffe806db537b139eb") as vtotal:
                flag_D = 0
                try:
                    flag_D = 0
                    resp = vtotal.request("urls", data={"url": IP_D}, method="POST")
                    url_id = urlsafe_b64encode(IP_D.encode()).decode().strip("=")
                    report = vtotal.request(f"urls/{url_id}")
                    result = report.data['attributes']['last_analysis_stats']
                except virustotal_python.VirustotalError as err:
                    flag = 1
                    result = f"Failed to send URL:{IP_D} for analysis and get the report: {err}"

            if flag_S == 0 and flag_D == 0:
                row = {
                    'S_IP': IP_S,
                    'S_Harmless': result['harmless'],
                    'S_Malicious': result['malicious'],
                    'S_Suspicious': result['suspicious'],
                    'S_Undetected': result['undetected'],
                    'S_Country': country_S,
                    'D_IP': IP_D,
                    'D_Harmless': result['harmless'],
                    'D_Malicious': result['malicious'],
                    'D_Suspicious': result['suspicious'],
                    'D_Undetected': result['undetected'],
                    'D_Country': country_D
                }
                writer.writerow(row)
            else:
                print(result)

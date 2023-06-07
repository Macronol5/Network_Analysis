import requests

def api_function(IP):
    api_base_url = f"http://ip-api.com/csv/{IP}"
    response = requests.get(api_base_url)
    return response.text

# print(api_function('52.114.15.109'))



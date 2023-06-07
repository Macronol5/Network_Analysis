# import virustotal_python
# from base64 import urlsafe_b64encode
# IP_S = 'http://23.129.64.134/'
#
# with virustotal_python.Virustotal(
#         "4905a54d2595dd657db8b0ed31a5b043b0f3abfa120cff8ffe806db537b139eb") as vtotal:
#     flag_S = 0
#     try:
#         flag = 0
#         resp = vtotal.request("urls", data={"url": IP_S}, method="POST")
#         url_id = urlsafe_b64encode(IP_S.encode()).decode().strip("=")
#         report = vtotal.request(f"urls/{url_id}")
#         result = report.data['attributes']['last_analysis_stats']
#     except virustotal_python.VirustotalError as err:
#         flag = 1
#         result = f"Failed to send URL:{IP_S} for analysis and get the report: {err}"
# print(result)

# http://23.129.64.134/
# import sys
# import json
# import requests
#
# api_key = "2c90d776bdd1204edf6dce55cef96eb4b2ba02c117b9d2e0d7d49b7df2643ca9"
# if api_key != "":
#     url = "https://malshare.com/api.php?api_key=%s&action=search&query=%s" % (api_key, sys.argv[1])
#     r = requests.get(url)
#     print(json.dumps(r.json(), sort_keys=True, indent=4, separators=(',', ': ')))
# else:
#     print("Please set API key")

import os
import re
import json
import argparse
import requests

BASE_HTTP_PATH = "http://malshare.com/"
API_PATHS = {
    "MD5LIST": "api.php?api_key=%s&action=getlistraw",
    "SOURCES": "api.php?api_key=%s&action=getsourcesraw",

    "DOWNLOAD": "api.php?api_key=%s&action=getfile&hash=%s",
    "DETAILS": "api.php?api_key=%s&action=details&hash=%s",

    "TYPE": "api.php?api_key=%s&action=type&type=%s",
}

api_key = "2c90d776bdd1204edf6dce55cef96eb4b2ba02c117b9d2e0d7d49b7df2643ca9"


def main():
    largs = parse_args()

    if largs['details']:
        uri = API_PATHS['DETAILS'] % (api_key, largs['details'])
        r = api_call(uri)
        if r is not None:
            details = r.json()
            print(json.dumps(details, indent=4, sort_keys=True))


    elif largs['download']:
        uri = API_PATHS['DOWNLOAD'] % (api_key, largs['download'])
        r = api_call(uri)
        if r is not None:
            try:
                with open(str(largs['download']) + ".malshare", 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                print("[X] Problem saving file")
                print("[E] %s" % e)

    elif largs['type']:
        uri = API_PATHS['TYPE'] % (api_key, largs['type'])
        r = api_call(uri)
        if r is not None:
            for rhash in set(r.json()):
                print
                rhash

    elif largs['listmd5']:
        uri = API_PATHS['MD5LIST'] % (api_key)
        r = api_call(uri)
        print(r.text.strip())


    elif largs['listsources']:
        uri = API_PATHS['SOURCES'] % (api_key)
        r = api_call(uri)
        print(r.text.strip())


def api_call(rpath):
    global api_key
    try:
        user_agent = {'User-Agent': 'MalShare API Tool v/0.1 beta'}
        r = requests.get(BASE_HTTP_PATH + rpath, headers=user_agent)

        if r.status_code == 200:
            if standard_error_check(r.content):
                return r
        else:
            if standard_error_check(r.content):
                print
                "[X] API Call Failed"
                return None
            else:
                return None



    except Exception as e:
        print("[X] API Call Failed: %s" % e)
        return None


def standard_error_check(rtext):
    if (rtext == "Sample not found"):
        print("[X] Sample not Found")
        return False

    if (rtext == "ERROR! => Account not activated"):
        print("[X] Bad API Key")
        return False

    if (rtext == "Invalid Hash"):
        print("[X] Invalid Hash")
        return False

    if ("Sample not found by hash" in rtext):
        print("[X] Hash not found")
        return False

    return True


def parse_args():
    global api_key
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--listmd5", help="Pull MD5 List", required=False, action='store_true')
    parser.add_argument("-s", "--listsources", help="Pull MD5 List", required=False, action='store_true')

    parser.add_argument("-d", "--download", help="Download File by Hash", required=False)
    parser.add_argument("-l", "--details", help="List File Details", required=False)
    parser.add_argument("-t", "--type", help="Search For Daily files by Type", required=False)

    parser.add_argument("-a", "--apikey", help="Set API key for session", required=False)

    args = parser.parse_args()
    if stored_api_check() == False:
        if args.apikey:
            api_key = args.apikey

    return vars(args)


# Read ~/.malshare and read the first line.  This file only needs the API string in it.
def stored_api_check():
    global api_key
    try:
        if (os.path.exists(os.path.expanduser('~') + '/.malshare')):
            with open(os.path.expanduser('~') + '/.malshare') as handle_api_file:
                api_key = func_parse_api_key(handle_api_file.readlines())
            return True
        elif (os.path.exists('.malshare')):
            with open('.malshare') as handle_api_file:
                api_key = func_parse_api_key(handle_api_file.readlines())
        return True
    except IOError:
        pass
    return False


# Parse the API key and exit if the API key contains any non [A-Za-z0-9]+
def func_parse_api_key(lst_tmp_key):
    str_tmp_key = "".join(lst_tmp_key).rstrip()
    if re.match("^[A-Za-z0-9]+$", str_tmp_key):
        return str_tmp_key


if __name__ == "__main__":
    main()
import sys
import json
import datetime
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import get_1password_field
from openpyxl import Workbook


Sumo_out_path = "C:/Users/justin.schuessler/Documents/API_Output/Sumo/"


def get_sumo_savepath():
    return Sumo_out_path


def get_all_rules(base_url: str, accessid: str, accesskey: str):
    rules = []
    offset = 0
    limit = 1000
    while True:
        params = {"limit": limit,
                  "offset": offset
                  }
        response = requests.get(f"{base_url}/sec/v1/rules", auth=HTTPBasicAuth(accessid, accesskey), params=params)
        print(response.status_code)
        #print(response.text)
        response.raise_for_status()
        data = response.json()["data"]
        objs = data.get("objects")
        print(len(data.get("objects")), "  ", data.get("hasNextPage"))

        offset += limit
        rules.extend(objs)
        if not data.get("hasNextPage"):
            break

    print(len(rules))
    return rules


def save_to_json(output, filename, path=get_sumo_savepath()):
    original_stdout = sys.stdout
    fullpath = path + filename + ".json"
    f = open(fullpath, "w")
    sys.stdout = f
    output = json.dumps(output, indent=4)
    print(output)
    f.close()
    sys.stdout = original_stdout
    print( filename, "  Saved to  ", path)



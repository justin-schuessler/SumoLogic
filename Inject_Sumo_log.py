import sys
import json
import datetime
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import get_1password_field



if __name__ == "__main__":
    original_stdout = sys.stdout
    test_log_path = "C:/Users/justin.schuessler/Documents/API_Output/Sumo/Test_Json_logs/O365_UserLoggedIn.json"
    endpoint = get_1password_field.get_1password_field("Sedara HTTP Source Endpoint", "URL", "API")

    url = endpoint
    headers = {
        "Content-Type": "application/json"
    }

    with open(test_log_path, 'r') as json_file:
        test_log = json.load(json_file)

    log = test_log

    response = requests.post(url, json=log, headers=headers)

    print(response.status_code)
    print(response.text)
    
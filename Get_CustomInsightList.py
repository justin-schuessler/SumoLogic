import sys
import json
import datetime
import requests
from requests.auth import HTTPBasicAuth


if __name__ == "__main__":
    original_stdout = sys.stdout
    accessID = ""
    accessKey = ""
    BASE_URL = "https://api.us2.sumologic.com"
    LIMIT = 100
    params = {"isCustom": "true", "limit": LIMIT}
    path = "C:/Users/justin.schuessler/Documents/API_Output/Sumo/"

    response = requests.get(f"{BASE_URL}/api/sec/v1/custom-insights", auth=HTTPBasicAuth(accessID, accessKey), params=params, timeout=30)
    response.raise_for_status()
    data = response.json()

    Fullpath = path + "BU_Sumo_Custom_Insights.json"
    f = open(Fullpath, "w")
    sys.stdout = f
    output = json.dumps(data, indent=4, )
    print(output)
    f.close()
    sys.stdout = original_stdout


import sys
import json
import datetime
import time
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import get_1password_field


if __name__ == "__main__":
    original_stdout = sys.stdout
    path = "C:/Users/justin.schuessler/Documents/API_Output/Sumo/"
    access_id = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "Access ID", "API")
    secret_key = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "Access Key", "API")
    BASE_URL = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "url", "API")

    accessID = access_id
    accessKey = secret_key

    FROM_TIME = 1743465600000
    limit = 50
    offset = 0
    q = "created:>2025-04-01T00:00:00+00:00"
    params = {"limit": limit,
              "offset": offset,
              "sort": "CREATED",
              "q": q
              }

    all_insights = []
    total = 51
    while total > offset:
        params = {"limit": limit,
                  "offset": offset,
                  "sort": "CREATED",
                  "q": q
                  }
        response = requests.get(f"{BASE_URL}/sec/v1/insights", auth=HTTPBasicAuth(accessID, accessKey), params=params)
        response.raise_for_status()
        data = response.json()
        insights = data["data"].get("objects")
        ins = []
        for i in insights:
            ins.append(i.get("readableId"))

        print(ins)
        all_insights.extend(insights)
        print(len(all_insights))
        offset += limit
        total = data["data"].get("total")
        print("offset: ", offset, "  of: ", data["data"].get("total"), " Total, Has Next Page: ", str(data["data"].get("hasNextPage")))

    Fullpath = path + "PB_Sumo_Insights_4_1_2025_to_4_13_2026.json"
    f = open(Fullpath, "w")
    sys.stdout = f
    output = json.dumps(all_insights, indent=4)
    print(output)
    f.close()
    sys.stdout = original_stdout



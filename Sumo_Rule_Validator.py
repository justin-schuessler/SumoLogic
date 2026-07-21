import sys
import json
import datetime
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import get_1password_field as onepass
import Useful_Sumo_functions as Use
from openpyxl import Workbook


if __name__ == "__main__":
    args = sys.argv
    customer = "Pathfinder_Bank"
    if len(args) >= 2:
        if args[1].lower() == "all":
            customer = "all"
        else:
            customer = args[1]

    onepass_sumo_dict_list = onepass.get_sumo_1password_items_filtered("API")
    for item in onepass_sumo_dict_list:
        if customer.lower().strip() == item.get("tenant_name").lower() or customer == "all":
            rules = Use.get_all_rules(base_url=item.get("url"), accessid=item.get("Access ID"), accesskey=item.get("Access Key"))
            Use.save_to_json(output=rules, filename=item.get("tenant_name")+"_rules")

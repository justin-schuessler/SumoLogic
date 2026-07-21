import csv
import sys
import os
import json
import re


def out_to_json(dict, filename, original_stdout, saved_location):
    f = open(filename, "w")
    sys.stdout = f
    output = json.dumps(dict, indent=4, )
    print(output)
    f.close()
    sys.stdout = original_stdout
    print(filename, "  | Saved to | " + saved_location + "  | Folder ")


def truth_check(string):
    if len(string) >= 1:
        vt = string.lower()
        v = vt[0]
        if v == "t" or v == "y":
            return True
        else:
            return False
    else:
        return False


# build product dict
def build_customer_product_dict(product_health_status_csv):
    prd_i_l = 'product_issue_reasons_list'
    N_I_R = 'Not Integrated Reason'
    N_L_S_R = 'No Logs Sent Recently Reason'
    N_L_P_R = 'Logs Not Parsing Correctly Reason'
    L_N_S_S = 'Logs Not Sending to SIEM Reason'
    Master_Product_Dict = {}
    with open(product_health_status_csv, encoding='utf-8') as product_hs_file:
        product_health_dict = csv.DictReader(product_hs_file)
        for row in product_health_dict:
            product_dict = {}
            product_name = row.get('Product')
            exists = truth_check(row.get('Product  Exists for Customer'))
            product_dict['Product  Exists for Customer'] = exists
            product_dict['Product is Healthy'] = False
            integrated = truth_check(row.get('Integrated'))
            product_dict['Integrated'] = integrated
            product_dict[prd_i_l] = []
            if not integrated:
                if row.get(N_I_R) != "":
                    product_dict[prd_i_l].append({N_I_R: row.get(N_I_R)})
            log_sending = truth_check(row.get('Logs Sending Recently'))
            product_dict['Logs Sending Recently'] = log_sending
            if not log_sending:
                if row.get(N_L_S_R) != "":
                    product_dict[prd_i_l].append({N_L_S_R: row.get(N_L_S_R)})
            logs_parsing = truth_check(row.get('Logs Parsing Correctly'))
            product_dict['Logs Parsing Correctly'] = logs_parsing
            if not logs_parsing:
                if row.get(N_L_P_R) != "":
                    product_dict[prd_i_l].append({N_L_P_R: row.get(N_L_P_R)})
            sending_to_siem = truth_check(row.get('Sending to SIEM'))
            product_dict['Sending to SIEM'] = sending_to_siem
            if not sending_to_siem:
                if row.get(L_N_S_S) != "":
                    product_dict[prd_i_l].append({L_N_S_S: row.get(L_N_S_S)})
            product_dict['Notes'] = row.get('Notes')

            if exists and integrated and log_sending and logs_parsing and sending_to_siem:
                product_dict['Product is Healthy'] = True

            product_dict['SIEM Rules exist to evaluate against logs'] = False
            product_dict['SIEM Rules that could apply id list'] = []
            product_dict['SIEM Rules currently evaluating against logs'] = False
            product_dict['SIEM Rules currently applied id list'] = []

            Master_Product_Dict[product_name] = product_dict

    return Master_Product_Dict


# add technique information to the Sumo matrix output from the mitre enterprise attack json
def build_sumo_master_with_mitre_tech_names(sumo_technqs, mitre_technqs):
    for mtr_t in mitre_technqs:
        xtr_list = mtr_t.get('external_references')
        for xtr in xtr_list:
            if xtr.get('source_name') == 'mitre-attack':
                mtr_tech_id_to_compare = xtr.get('external_id')
                list_position = 0
                for sum_tech in sumo_technqs:
                    if sum_tech.get('techniqueID') == mtr_tech_id_to_compare:
                        sumo_technqs[list_position]['technique name'] = mtr_t.get('name')
                        sumo_technqs[list_position]['technique description'] = mtr_t.get('description')
                        sumo_technqs[list_position]['technique url'] = xtr.get('url')
                    list_position = list_position + 1
    return sumo_technqs


def build_full_mitre_dict(sumo_master_technqs, mitre_entr_tactics):
    full_mitre_dict = {}
    for tactic_obj in mitre_entr_tactics:
        tactic_dict = {}
        for xtr in tactic_obj.get('external_references'):
            if xtr.get('source_name') == 'mitre-attack':
                tactic = xtr.get('external_id')
                mtr_tactic_url = xtr.get('url')
                mtr_tactic_descrpt = tactic_obj.get('description')
                mtr_tactic_name = tactic_obj.get('name')
                tactic_dict['Tactic Name'] = mtr_tactic_name
                tactic_dict['Tactic Description'] = mtr_tactic_descrpt
                tactic_dict['Tactic url'] = mtr_tactic_url
                tactic_dict['Techniques'] = {}

                for sumo_techq in sumo_master_technqs:
                    if sumo_techq.get('tactic') == get_mitre_dict(tactic) and len(sumo_techq.get('techniqueID')) < 6:
                        techq_dict = {}
                        techq_dict['technique name'] = sumo_techq.get('technique name')
                        techq_dict['technique description'] = sumo_techq.get('technique description')
                        techq_dict['technique url'] = sumo_techq.get('technique url')
                        techq_dict['sub_techniques'] = {}
                        for sumo_sub_techq in sumo_master_technqs:
                            if sumo_sub_techq.get('techniqueID')[:5] == sumo_techq.get('techniqueID') and len(sumo_sub_techq.get('techniqueID')) > 5:
                                sub_techq_dict = {}
                                sub_techq_dict['technique name'] = sumo_techq.get('technique name')
                                sub_techq_dict['technique description'] = sumo_techq.get('technique description')
                                sub_techq_dict['technique url'] = sumo_techq.get('technique url')
                                sub_techq_dict['sub_techniques'] = {}
                                techq_dict['sub_techniques'][sumo_sub_techq.get('techniqueID')] = sub_techq_dict

                        tactic_dict['Techniques'][sumo_techq.get('techniqueID')] = techq_dict
                full_mitre_dict[tactic] = tactic_dict

    return full_mitre_dict


# simple dict to get mitre tactic short name from tactic id input
def get_mitre_dict(mitre_id):
    tactics = {
        'TA0043': 'reconnaissance',
        'TA0042': 'resource-development',
        'TA0001': 'initial-access',
        'TA0002': 'execution',
        'TA0003': 'persistence',
        'TA0004': 'privilege-escalation',
        'TA0005': 'defense-evasion',
        'TA0006': 'credential-access',
        'TA0007': 'discovery',
        'TA0008': 'lateral-movement',
        'TA0009': 'collection',
        'TA0010': 'exfiltration',
        'TA0011': 'command-and-control',
        'TA0040': 'impact'
    }
    return tactics.get(mitre_id)


# take csv of customer products that apply to rules and build master rules dict
def get_sumo_default_rules_to_dict(master_rule_dict, cust_def_csv_file, rules_dir):
    # get severity data
    severity_data = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith('.md'):
            with open(os.path.join(rules_dir, filename), 'r', encoding='utf-8') as file:
                content = file.read()
                match = re.search(r'\|Score/Severity\|\s*(.*?)\s*\|', content)
                if match:
                    severity = match.group(1).strip()
                    f_rule_name = filename.split('.')
                    if severity[0]=='S':
                        severity_number = int(severity[8])
                    if severity[0]=='D':
                        sum = 0
                        sum_c = 0
                        for char in severity:
                            if char.isdigit():
                                sum = sum + int(char)
                                sum_c = sum_c + 1
                        severity_number = round(sum/sum_c)
                    severity_data[f_rule_name[0]] = severity_number

    with open(cust_def_csv_file,  encoding='utf-8') as cust_def_file:
        cust_def_dict = csv.DictReader(cust_def_file)
        for row in cust_def_dict:
            rule_dict = {}
            product = row.get('Product')
            rule_id = row.get('Rule ID')
            rule_name = row.get('Rule Name')

            rule_dict['product list'] = set()
            rule_dict['product list'].add(product)

            rule_dict['Rule Name'] = rule_name
            rule_dict['Severity'] = severity_data.get(rule_id)

            if master_rule_dict.get(rule_id) is not None:
                master_rule_dict[rule_id]['product list'].add(product)

            if master_rule_dict.get(rule_id) is None:
                master_rule_dict[rule_id] = rule_dict

    return master_rule_dict


# adds a technique id to the dictonary of the tactic
def add_tech_to_tactic(tactic, techq_list, sub_techq_dict, rule_id, name, product_list, master_detection_dict, sumo_technqs):
    for techq in techq_list:
        for sumo_techq in sumo_technqs:
            if sumo_techq.get('techniqueID') == techq and sumo_techq.get('tactic') == get_mitre_dict(tactic):
                if master_detection_dict[tactic]['Techniques'].get(techq) is not None:
                    techq_dict = master_detection_dict[tactic]['Techniques'].get(techq)
                if master_detection_dict[tactic]['Techniques'].get(techq) is None:
                    techq_dict = {}
                    techq_dict['Rule id_name Dict'] = {}
                    techq_dict['product list'] = set()
                    techq_dict['sub_techniques'] = {}
                    techq_dict['technique name'] = sumo_techq.get('technique name')
                    techq_dict['technique description'] = sumo_techq.get('technique description')
                    techq_dict['technique url'] = sumo_techq.get('technique url')

                techq_dict['Rule id_name Dict'][rule_id] = name
                for prod in product_list:
                    techq_dict['product list'].add(prod)
                for sub in sub_techq_dict:
                    if sub[:5] == techq:
                        sub_dict = {}
                        sub_dict['sub technique name'] = sumo_techq.get('technique name')
                        sub_dict['sub technique description'] = sumo_techq.get('technique description')
                        sub_dict['sub technique url'] = sumo_techq.get('technique url')

                        techq_dict['sub_techniques'][sub] = sub_dict
                master_detection_dict[tactic]['Techniques'][techq] = techq_dict

    return master_detection_dict


# adds mitre tag information from sumo default csv to customer detection idct and master rule dict
def get_mitre_added_to_dict(master_rule_dict, sumo_def_csv_file, sumo_technqs, mitre_entr_tactics, customer_potential_rule_list):
    customer_detection_dict = {}
    customer_rule_set = set(customer_potential_rule_list)
    with open(sumo_def_csv_file, encoding='utf-8') as sumo_def_file:
        sumo_def_dict = csv.DictReader(sumo_def_file)
        for row1 in sumo_def_dict:
            rule_id = row1.get('rule_id')
            if master_rule_dict.get(rule_id) is not None and rule_id in customer_rule_set:
                r_type = row1.get('type')
                mtr_category = row1.get('category')
                rule_name = row1.get('name')
                mtr_tags = row1.get('tags')
                descpt = row1.get('description')
                tags = mtr_tags.split(',')
                tacitc_list = []
                techq_list = []
                sub_techq_dict = {}
                master_rule_dict[rule_id]['rule type'] = r_type
                master_rule_dict[rule_id]['category'] = mtr_category
                master_rule_dict[rule_id]['mitre tags'] = []
                master_rule_dict[rule_id]['rule description'] = descpt
                master_rule_dict[rule_id]['rule origin'] = "Sumo Built-In"
                product_list = master_rule_dict[rule_id].get('product list')
                for tag in tags:
                    mtr_w_num = tag.split(':')
                    if len(mtr_w_num) > 1:
                        master_rule_dict[rule_id]['mitre tags'].append(mtr_w_num[1])
                        mtr_num = mtr_w_num[1]
                        if mtr_num[1] == 'A':
                            tacitc_list.append(mtr_num)
                        if mtr_num[1] != 'A':
                            if len(mtr_num) < 7:
                                techq_list.append(mtr_num)
                            if len(mtr_num) > 6:
                                sub_techq_dict[mtr_num] = {}

                for tactic in tacitc_list:
                    if customer_detection_dict.get(tactic) is not None:
                        customer_detection_dict[tactic]['Tactic Rules dict'][rule_id] = rule_name
                        customer_detection_dict = add_tech_to_tactic(tactic, techq_list, sub_techq_dict, rule_id, rule_name, product_list, customer_detection_dict, sumo_technqs)

                    if customer_detection_dict.get(tactic) is None:
                        customer_detection_dict[tactic] = {}
                        tactic_dict = {}
                        for tactic_obj in mitre_entr_tactics:
                            for xtr in tactic_obj.get('external_references'):
                                if xtr.get('source_name') == 'mitre-attack':
                                    id_to_compare = xtr.get('external_id')
                                    if id_to_compare == tactic:
                                        mtr_tactic_url = xtr.get('url')
                                        mtr_tactic_descrpt = tactic_obj.get('description')
                                        mtr_tactic_name = tactic_obj.get('name')

                        tactic_dict['Tactic Name'] = mtr_tactic_name
                        tactic_dict['Tactic Description'] = mtr_tactic_descrpt
                        tactic_dict['Tactic url'] = mtr_tactic_url
                        tactic_dict['Tactic Rules dict'] = {}
                        tactic_dict['Techniques'] = {}
                        tactic_dict['Tactic Rules dict'][rule_id] = rule_name

                        customer_detection_dict[tactic] = tactic_dict
                        customer_detection_dict = add_tech_to_tactic(tactic, techq_list, sub_techq_dict, rule_id, rule_name, product_list, customer_detection_dict, sumo_technqs)

    return master_rule_dict, customer_detection_dict


# adds Sedara Rule Modifications to Master Rule dict and customer detection Dict
def get_sedara_rules_added_to_dicts(sedara_rules_file, master_rule_dict, customer_detection_dict, mitre_entr_tactics, sumo_technqs):
    with open(sedara_rules_file,  encoding='utf-8') as sedara_file:
        sedara_rules_dict = csv.DictReader(sedara_file)
        for row in sedara_rules_dict:
            rule_dict = {}
            rule_id = row.get('Rule ID')
            change = row.get('Change Type')
            product_list = []
            if master_rule_dict.get(rule_id) is None:
                rule_name = row.get('Rule Name')
                product_list.append(row.get("Product List"))
                rule_dict['product list'] = product_list
                rule_dict['Rule Name'] = rule_name
                severity = row.get('Severity')
                if severity.isdigit():
                    rule_dict['Severity'] = int(severity)
                if row.get('Modified Built-in Rule ID') is not None:
                    rule_dict['Modified Built-in Rule ID'] = row.get('Modified Built-in Rule ID')
                rule_dict['mitre tags'] = []
                rule_dict['rule description'] = ""
                rule_dict['rule origin'] = row.get('rule origin')
                rule_dict['Change Type'] = change
                tactic_list = []
                techq_list = []
                sub_techq_dict = {}

                mtr_tags = row.get('tags')
                tags = mtr_tags.split(',')
                master_rule_dict[rule_id] = rule_dict
                for tag_d in tags:
                    tag = tag_d.strip()
                    master_rule_dict[rule_id]['mitre tags'].append(tag)
                    if len(tag) > 4:
                        if tag[1] == 'A':
                            tactic_list.append(tag)
                        if tag[1] != 'A':
                            if len(tag) < 7:
                                techq_list.append(tag)
                            if len(tag) > 6:
                                sub_techq_dict[tag] = {}

                for tactic in tactic_list:
                    if customer_detection_dict.get(tactic) is not None:
                        customer_detection_dict[tactic]['Tactic Rules dict'][rule_id] = rule_name
                        customer_detection_dict = add_tech_to_tactic(tactic, techq_list, sub_techq_dict, rule_id, rule_name,
                                                                     product_list, customer_detection_dict, sumo_technqs)

                    if customer_detection_dict.get(tactic) is None:
                        customer_detection_dict[tactic] = {}
                        tactic_dict = {}
                        for tactic_obj in mitre_entr_tactics:
                            for xtr in tactic_obj.get('external_references'):
                                if xtr.get('source_name') == 'mitre-attack':
                                    id_to_compare = xtr.get('external_id')
                                    if id_to_compare == tactic:
                                        mtr_tactic_url = xtr.get('url')
                                        mtr_tactic_descrpt = tactic_obj.get('description')
                                        mtr_tactic_name = tactic_obj.get('name')

                        tactic_dict['Tactic Name'] = mtr_tactic_name
                        tactic_dict['Tactic Description'] = mtr_tactic_descrpt
                        tactic_dict['Tactic url'] = mtr_tactic_url
                        tactic_dict['Tactic Rules dict'] = {}
                        tactic_dict['Techniques'] = {}
                        tactic_dict['Tactic Rules dict'][rule_id] = rule_name

                        customer_detection_dict[tactic] = tactic_dict
                        customer_detection_dict = add_tech_to_tactic(tactic, techq_list, sub_techq_dict, rule_id, rule_name,
                                                                     product_list, customer_detection_dict, sumo_technqs)

            if master_rule_dict.get(rule_id) is not None:
                master_rule_dict[rule_id]['Change Type'] = change

    return master_rule_dict, customer_detection_dict


def get_sedara_insight_added(sedara_added_insights, master_rule_dict, insight_boost):
    with open(sedara_added_insights,  encoding='utf-8') as sedara_file:
        sedara_rules_dict = csv.DictReader(sedara_file)
        for row in sedara_rules_dict:
            insight_dict = {}
            rule_id = row.get('Rule ID')
            insight_dict['Insight Name'] = row.get('Insight Name')
            insight_dict['Insight Description'] = row.get('Insight Description')
            insight_dict['Insight Severity'] = row.get('Insight Severity')
            insight_dict['Rule Change'] = row.get('Rule Change')
            master_rule_dict[rule_id]['Severity'] = master_rule_dict[rule_id].get('Severity') + insight_boost
            master_rule_dict[rule_id]['Insight'] = insight_dict
    return master_rule_dict


# change product sets to list for json output
def get_final_output_master_rule_dict(master_rule_dict):
    for rule in master_rule_dict:
        product_list = list(master_rule_dict[rule].get('product list'))
        master_rule_dict[rule]['product list'] = product_list
    return master_rule_dict


# change product sets to list for json output
def get_final_output_master_detection_dict(master_detection_dict):
    for tactic in master_detection_dict:
        for technique in master_detection_dict[tactic].get('Techniques'):
            product_list = list(master_detection_dict[tactic]['Techniques'][technique].get('product list'))
            master_detection_dict[tactic]['Techniques'][technique]['product list'] = product_list
    return master_detection_dict


# returns product dict with only products customer uses, and adds info about what rules are available for those products
def evaluate_rules_against_products(master_rule_dict, master_product_health_dict):
    keys_to_del = []
    for product in master_product_health_dict:
        if master_product_health_dict[product].get('Product  Exists for Customer'):
            for rule in master_rule_dict.keys():
                rule_prod_list = master_rule_dict[rule].get('product list')
                for rule_prod in rule_prod_list:
                    if rule_prod == product:
                        master_product_health_dict[product]['SIEM Rules exist to evaluate against logs'] = True
                        master_product_health_dict[product]['SIEM Rules that could apply id list'].append(rule)
                        if master_product_health_dict[product].get('Product is Healthy'):
                            master_product_health_dict[product]['SIEM Rules currently evaluating against logs'] = True
                            master_product_health_dict[product]['SIEM Rules currently applied id list'].append(rule)

        if not master_product_health_dict[product].get('Product  Exists for Customer'):
            keys_to_del.append(product)

    for k in keys_to_del:
        del master_product_health_dict[k]

    return master_product_health_dict


# splits product health dict into 2 lists, list of potential rules, list of currently applied rules
def evaluate_product_rules(customer_product_health_dict):
    customer_potential_rule_set = set()
    customer_applied_rule_set = set()
    for product in customer_product_health_dict:
        if customer_product_health_dict[product].get('SIEM Rules exist to evaluate against logs'):
            potential_rule_list = customer_product_health_dict[product].get('SIEM Rules that could apply id list')
            for pot_rule in potential_rule_list:
                customer_potential_rule_set.add(pot_rule)
        if customer_product_health_dict[product].get('SIEM Rules currently evaluating against logs'):
            applied_rule_list = customer_product_health_dict[product].get('SIEM Rules currently applied id list')
            for appl_rule in applied_rule_list:
                customer_applied_rule_set.add(appl_rule)

    customer_potential_rule_list = list(customer_potential_rule_set)
    customer_applied_rule_list = list(customer_applied_rule_set)
    return customer_potential_rule_list, customer_applied_rule_list


# create list of healthy products
def return_healthy_product_list(customer_product_health_dict):
    healthy_products_list = []
    for product in customer_product_health_dict:
        if customer_product_health_dict[product].get('Product is Healthy'):
            healthy_products_list.append(product)
    return healthy_products_list


def return_all_product_list(customer_product_health_dict):
    all_products_list = []
    for product in customer_product_health_dict:
        if customer_product_health_dict[product].get('Product  Exists for Customer'):
            all_products_list.append(product)
    return all_products_list


# return list of all rules sedara has modified
def return_sedara_modified_list(master_rule_dict):
    sed_mod_list = []
    for rule in master_rule_dict:
        if master_rule_dict[rule].get("Change Type") is not None or master_rule_dict[rule].get("Insight") is not None:
            sed_mod_list.append(rule)
    return sed_mod_list


# create detection matrix for given rule list
def evaluate_detection_coverage(rule_list, customer_product_health_dict, master_rule_dict, master_detection_dict):
    detection_coverage = {}
    for tactic in master_detection_dict:
        tactic_dict = {}
        tactic_dict['Tactic Name'] = master_detection_dict[tactic].get('Tactic Name')
        tactic_dict['Tactic Description'] = master_detection_dict[tactic].get('Tactic Description')
        tactic_dict['Tactic url'] = master_detection_dict[tactic].get('Tactic url')
        tactic_dict['Techniques'] = {}
        for technq in master_detection_dict[tactic].get('Techniques'):
            for tech_rule in master_detection_dict[tactic]['Techniques'][technq].get('Rule id_name Dict').keys():
                for rule in rule_list:
                    if tech_rule == rule:
                        if tactic_dict['Techniques'].get(technq) is not None:
                            tactic_dict['Techniques'][technq]['Rule id_name Dict'][tech_rule] = master_detection_dict[tactic]['Techniques'][technq]['Rule id_name Dict'].get(tech_rule)
                        if tactic_dict['Techniques'].get(technq) is None:
                            tactic_dict['Techniques'][technq] = {}
                            tactic_dict['Techniques'][technq]['Rule id_name Dict'] = {}
                            tactic_dict['Techniques'][technq]['Rule id_name Dict'][tech_rule] = master_detection_dict[tactic]['Techniques'][technq]['Rule id_name Dict'].get(tech_rule)
                            tactic_dict['Techniques'][technq]['technique name'] = master_detection_dict[tactic]['Techniques'][technq].get('technique name')
                            tactic_dict['Techniques'][technq]['technique description'] = master_detection_dict[tactic]['Techniques'][technq].get('technique description')
                            tactic_dict['Techniques'][technq]['technique url'] = master_detection_dict[tactic]['Techniques'][technq].get('technique url')

        detection_coverage[tactic] = tactic_dict

    return detection_coverage


# print % of Products that have Rules Evaluating
def output_Siem_Rule_Evaluation_pct(customer_product_health_dict):
    product_count = len(customer_product_health_dict.keys())
    evaluating_count = 0
    for product in customer_product_health_dict:
        if customer_product_health_dict[product].get('SIEM Rules currently evaluating against logs'):
            evaluating_count = evaluating_count + 1
    pct = evaluating_count / product_count
    print("\n")
    print("Percentage of Products with SIEM Rules Currently Evaluating: ", pct)
    print("\n")


# print out detection matrix
def display_coverage(coverage_matrix, coverage_type):
    total_techniques_count = 0
    tactic_covered_list = []
    for tactic in coverage_matrix:
        tac_techniques_list = []
        for technq in coverage_matrix[tactic].get('Techniques'):
            tac_techniques_list.append(technq)
        print(f"{tactic} Has {coverage_type} For   {len(tac_techniques_list):<2}  Techniques")
        if len(tac_techniques_list) > 0:
            tactic_covered_list.append(tactic)
        total_techniques_count = total_techniques_count + len(tac_techniques_list)

    print("\n")
    print(f"{coverage_type} For {len(tactic_covered_list):<2}  Tactics and {total_techniques_count} Total Techniques")
    print("\n")
    return total_techniques_count


def find_missing_rule_ids(customer_potential_rule_list, customer_applied_rule_list):
    customer_missing_rule_list = set(customer_potential_rule_list)
    for P_rule in customer_potential_rule_list:
        for A_rule in customer_applied_rule_list:
            if P_rule == A_rule:
                customer_missing_rule_list.remove(P_rule)

    return list(customer_missing_rule_list)


if __name__ == "__main__":
    args = sys.argv
    original_stdout = sys.stdout
    customer = "BU"
    insight_boost = 12

    input_path = "C:/Users/justin.schuessler/Documents/BetterUp/input files/"
    output_path = "C:/Users/justin.schuessler/Documents/BetterUp/output/"
    Saved_Data_path = "C:/Users/justin.schuessler/Documents/BetterUp/Saved Data/"
    rules_dir = "C:/Users/justin.schuessler/PycharmProjects/test/cloud-siem-content-catalog/rules/"

    Sumo_possible_Rules = input_path + "Sumo_PossibleDefault_Rules.csv"
    sumo_default_all_data = input_path + "Default_SumoLogic_rules_4_21_25.csv"
    sumo_json = input_path + "sumo_mitre_raw.json"
    mitre_enterprise_json = input_path + "enterprise-attack.json"
    product_csv = input_path + "BU_Product_Health_Status_Start_Refresh.csv"
    sedara_added_rules = input_path + "BU_Rule_Modifications.csv"
    sedara_added_insights = input_path + "BU_Insight_Modifications.csv"

    full_rule_out_file_name = Saved_Data_path + "Master_Sumo_Rule_Dict.json"
    full_customer_detection_out_file_name = Saved_Data_path + customer + "_Sumo_Detection_Dict.json"
    full_detection_out_file_name = Saved_Data_path + "Master_Sumo_Detection_Dict.json"
    full_product_out_file_name = Saved_Data_path + customer + "_Product_Health_Status.json"
    full_sumo_techniques_out_file_name = Saved_Data_path + "Sumo_Techniques_With_Mitre_info_added.json"

    value = "N"

    if len(args) > 1:
        value = args[1]

    if len(args) < 2:
        print("Create New Saved Rule, Product, Sumo techniques, And Detection Dicts?: Y/N")
        value = input()

    if truth_check(value):
        with open(sumo_json, 'r') as json_file:
            sumo_data = json.load(json_file)
        sumo_technqs = sumo_data.get('techniques')

        with open(mitre_enterprise_json, 'r') as mtr_json_file:
            mitre_enterprise_data = json.load(mtr_json_file)

        mitre_entr_technqs = []
        mitre_entr_tactics = []
        mitre_objects = mitre_enterprise_data.get('objects')
        for obj in mitre_objects:
            if not obj.get('x_mitre_deprecated'):
                if obj.get('type') == 'attack-pattern':
                    mitre_entr_technqs.append(obj)
                if obj.get('type') == 'x-mitre-tactic':
                    mitre_entr_tactics.append(obj)

        sumo_master_technqs = build_sumo_master_with_mitre_tech_names(sumo_technqs, mitre_entr_technqs)
        all_detection_dict = build_full_mitre_dict(sumo_master_technqs, mitre_entr_tactics)
        master_product_health_dict = build_customer_product_dict(product_csv)
        master_rule_dict = get_sumo_default_rules_to_dict({}, Sumo_possible_Rules, rules_dir)
        customer_product_health_dict = evaluate_rules_against_products(master_rule_dict, master_product_health_dict)
        customer_potential_rule_list, customer_applied_rule_list = evaluate_product_rules(customer_product_health_dict)

        master_rule_dict, customer_detection_dict = get_mitre_added_to_dict(master_rule_dict, sumo_default_all_data, sumo_master_technqs, mitre_entr_tactics, customer_potential_rule_list)
        print("Would You like to add Sedara Rules and Insights: ")
        add_sedara = truth_check(input())
        if add_sedara:
            master_rule_dict, customer_detection_dict = get_sedara_rules_added_to_dicts(sedara_added_rules, master_rule_dict, customer_detection_dict, mitre_entr_tactics, sumo_master_technqs)
            master_rule_dict = get_sedara_insight_added(sedara_added_insights, master_rule_dict, insight_boost)
        customer_product_health_dict = evaluate_rules_against_products(master_rule_dict, master_product_health_dict)

        master_rule_dict = get_final_output_master_rule_dict(master_rule_dict)
        customer_detection_dict = get_final_output_master_detection_dict(customer_detection_dict)

        out_to_json(master_rule_dict, full_rule_out_file_name, original_stdout, "Saved Data")
        out_to_json(customer_detection_dict, full_customer_detection_out_file_name, original_stdout, "Saved Data")
        out_to_json(all_detection_dict, full_detection_out_file_name, original_stdout, "Saved Data")
        out_to_json(customer_product_health_dict, full_product_out_file_name, original_stdout,  "Saved Data")
        out_to_json(sumo_master_technqs, full_sumo_techniques_out_file_name, original_stdout, "Saved Data")


        sys.stdout = original_stdout

    else:
        with open(full_sumo_techniques_out_file_name, 'r') as s_json_file:
            sumo_master_technqs = json.load(s_json_file)
        with open(full_rule_out_file_name, 'r') as r_json_file:
            master_rule_dict = json.load(r_json_file)
        with open(full_customer_detection_out_file_name, 'r') as d_json_file:
            customer_detection_dict = json.load(d_json_file)
        with open(full_detection_out_file_name, 'r') as p_json_file:
            all_detection_dict = json.load(p_json_file)
        with open(full_product_out_file_name, 'r') as o_json_file:
            customer_product_health_dict = json.load(o_json_file)

    customer_potential_rule_list, customer_applied_rule_list = evaluate_product_rules(customer_product_health_dict)
    customer_potential_detection_coverage = evaluate_detection_coverage(customer_potential_rule_list, customer_product_health_dict, master_rule_dict, customer_detection_dict)
    customer_actual_detection_coverage = evaluate_detection_coverage(customer_applied_rule_list, customer_product_health_dict, master_rule_dict, customer_detection_dict)

    print("\n")
    coverage = "Potential_Rules"
    full_potential_coverage_out_file_name = output_path + customer + "_Sumo_" + coverage + "_Coverage_list.json"
    out_to_json(customer_potential_rule_list, full_potential_coverage_out_file_name, original_stdout, output_path)

    coverage = "Applied_Rules"
    full_potential_coverage_out_file_name = output_path + customer + "_Sumo_" + coverage + "_Coverage_list.json"
    out_to_json(customer_applied_rule_list, full_potential_coverage_out_file_name, original_stdout, output_path)

    customer_missing_rule_list = find_missing_rule_ids(customer_potential_rule_list, customer_applied_rule_list)
    coverage = "Missing_Rules"
    full_potential_coverage_out_file_name = output_path + customer + "_Sumo_" + coverage + "_Coverage_list.json"
    out_to_json(customer_applied_rule_list, full_potential_coverage_out_file_name, original_stdout, output_path)

    full_product_filename = output_path + customer + "_Sumo_Healthy_Products_list.json"
    out_to_json(return_healthy_product_list(customer_product_health_dict), full_product_filename, original_stdout, output_path)

    full_all_product_filename = output_path + customer + "_Sumo_All_Products_list.json"
    out_to_json(return_all_product_list(customer_product_health_dict), full_all_product_filename, original_stdout, output_path)

    sedara_changed_rules_list = output_path + customer + "_Sedara_Modified_Rules_List.json"
    out_to_json(return_sedara_modified_list(master_rule_dict), sedara_changed_rules_list, original_stdout, output_path)

    output_Siem_Rule_Evaluation_pct(customer_product_health_dict)

    print("\n")
    print("Number Potential Rules: ", len(customer_potential_rule_list))
    print("Number of Applied Rules: ", len(customer_applied_rule_list))
    print("Number of Missing Rules: ", len(customer_missing_rule_list))
    print("Percentage of Rules Applied: ", len(customer_applied_rule_list) / len(customer_potential_rule_list))
    print("\n")

    potential_technique_count = display_coverage(customer_potential_detection_coverage, "Potential Built-In Detection Coverage")
    applied_technique_count = display_coverage(customer_actual_detection_coverage, "Applied Built-In Detection Coverage")

    print("Percentage of Potential Techniques with Coverage: ", applied_technique_count / potential_technique_count)


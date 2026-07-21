import sys
import json


def out_to_json(dict, filename, original_stdout, saved_location):
    f = open(filename, "w")
    sys.stdout = f
    output = json.dumps(dict, indent=4, )
    print(output)
    f.close()
    sys.stdout = original_stdout
    print(filename, "  | Saved to | " + saved_location + "  | Folder ")


def Layer_builder(base, master_rule_dict, customer_detection_dict, rules_list, healthy_products):
    layer = base.copy()
    all_techniques_list = []
    for tactic in customer_detection_dict:
        tactic_name = customer_detection_dict[tactic].get('Tactic Name')
        for tech in customer_detection_dict[tactic].get('Techniques'):
            tech_dict = {}
            score = 0
            comment = ""
            metadata_list = []
            rule_list = ""
            product_list = set()
            matched = False
            for rule in rules_list:
                if customer_detection_dict[tactic]['Techniques'][tech]['Rule id_name Dict'].get(rule) is not None:
                    matched = True
                    score = score + master_rule_dict[rule].get('Severity')
                    if master_rule_dict[rule].get('Insight') is not None:
                        comment = comment + master_rule_dict[rule]["Insight"].get('Insight Name') + ", "
                    if len(metadata_list) < 1:
                        rule_dict = {"name": "Rule List", "value": ""}
                        prod_dict = {"name": "Product List", "value": ""}
                        metadata_list.append(rule_dict)
                        metadata_list.append(prod_dict)
                    rule_name = master_rule_dict[rule].get('Rule Name') + ", "
                    for product in healthy_products:
                        for rule_prod in master_rule_dict[rule].get('product list'):
                            if product == rule_prod:
                                product_list.add(product)
                    rule_list = rule_list + rule_name

            if matched:
                metadata_list[0]["value"] = rule_list
                metadata_list[1]["value"] = list(product_list)
                tech_dict["techniqueID"] = tech
                tech_dict["tactic"] = tactic_name.lower().replace(" ", "-")
                tech_dict["score"] = score
                tech_dict["color"] = ""
                tech_dict["comment"] = comment
                tech_dict["enabled"] = True
                tech_dict["metadata"] = metadata_list
                tech_dict["links"] = []
                tech_dict["showSubtechniques"] = False
                all_techniques_list.append(tech_dict)
    layer["techniques"] = all_techniques_list
    return layer


if __name__ == "__main__":
    args = sys.argv
    original_stdout = sys.stdout
    customer = "BU"

    Saved_Data_path = "C:/Users/justin.schuessler/Documents/BetterUp/Saved Data/"
    output_path = "C:/Users/justin.schuessler/Documents/BetterUp/output/"

    full_customer_detection_out_file_name = Saved_Data_path + customer + "_Sumo_Detection_Dict.json"
    full_product_out_file_name = Saved_Data_path + customer + "_Product_Health_Status.json"
    full_rule_out_file_name = Saved_Data_path + "Master_Sumo_Rule_Dict.json"
    full_healthy_products_filename = output_path + "BU_Sumo_Healthy_Products_list.json"
    full_all_products_filename = output_path + "BU_Sumo_All_Products_list.json"
    base_f_name = "mitre_layer.json"
    base_full = Saved_Data_path + base_f_name

    coverage = "Potential_Rules"
    full_potential_coverage_out_file_name = output_path + customer + "_Sumo_" + coverage + "_Coverage_list.json"
    with open(full_potential_coverage_out_file_name, 'r') as p_json_file:
        customer_potential_rule_list = json.load(p_json_file)

    coverage = "Applied_Rules"
    full_potential_coverage_out_file_name = output_path + customer + "_Sumo_" + coverage + "_Coverage_list.json"
    with open(full_potential_coverage_out_file_name, 'r') as a_json_file:
        customer_applied_rule_list = json.load(a_json_file)

    full_sedara_modified_list_filename = output_path + customer + "_Sedara_Modified_Rules_List.json"
    with open(full_sedara_modified_list_filename, 'r') as sd_json_file:
        sed_mod_list = json.load(sd_json_file)

    with open(base_full, 'r') as s_json_file:
        base_layer = json.load(s_json_file)
    with open(full_product_out_file_name, 'r') as o_json_file:
        customer_product_health_dict = json.load(o_json_file)
    with open(full_rule_out_file_name, 'r') as r_json_file:
        master_rule_dict = json.load(r_json_file)
    with open(full_customer_detection_out_file_name, 'r') as d_json_file:
        customer_detection_dict = json.load(d_json_file)
    with open(full_healthy_products_filename, 'r') as p_json_file:
        healthy_products = json.load(p_json_file)
    with open(full_all_products_filename, 'r') as a_json_file:
        all_products = json.load(a_json_file)

    potential_layer = Layer_builder(base_layer, master_rule_dict, customer_detection_dict, customer_potential_rule_list, all_products)
    potential_layer["name"] = "Potential Mitre Coverage"

    applied_layer = Layer_builder(base_layer, master_rule_dict, customer_detection_dict, customer_applied_rule_list, healthy_products)
    applied_layer["name"] = "Applied Mitre Coverage"

    sedara_layer = Layer_builder(base_layer, master_rule_dict, customer_detection_dict, sed_mod_list, all_products)
    sedara_layer["name"] = "Sedara Added Mitre Coverage"

    potential_layer_filename = output_path + "Potential_layer.json"
    out_to_json(potential_layer, potential_layer_filename, original_stdout, output_path)

    applied_layer_filename = output_path + "Applied_layer.json"
    out_to_json(applied_layer, applied_layer_filename, original_stdout, output_path)

    sedara_layer_filename = output_path + "sedara_layer.json"
    out_to_json(sedara_layer, sedara_layer_filename, original_stdout, output_path)

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


if __name__ == "__main__":
    args = sys.argv
    original_stdout = sys.stdout
    customer = "BU"
    insight_boost = 12

    input_path = "C:/Users/justin.schuessler/Documents/BetterUp/Layers_other/"
    pre = "Applied_layer_pre_Refresh.json"
    post = "Applied_layer_post_refresh.json"
    Potential = "Potential_layer_w_sedara.json"

    with open(input_path+pre, 'r') as pre_json_file:
        pre_technqs = json.load(pre_json_file)
    with open(input_path+post, 'r') as post_json_file:
        post_technqs = json.load(post_json_file)
    with open(input_path+Potential, 'r') as poten_json_file:
        poten_technqs = json.load(poten_json_file)

    count = 0
    po_pre_id = []
    for po_tech in post_technqs.get('techniques'):
        for pre_tech in pre_technqs.get('techniques'):
            if po_tech.get('techniqueID') == pre_tech.get('techniqueID'):
                if po_tech.get('score') > pre_tech.get('score'):
                    po_pre_id.append(po_tech.get('techniqueID'))
                    count = count +1

    poten_count = 0
    poten_po_id = []
    for poten_tech in poten_technqs.get('techniques'):
        for po_tech in post_technqs.get('techniques'):
            if poten_tech.get('techniqueID') == po_tech.get('techniqueID'):
                if poten_tech.get('score') > po_tech.get('score'):
                    poten_po_id.append(poten_tech.get('techniqueID'))
                    poten_count = poten_count +1

    print("\nNumber of Techniques Increased In Severity Pre to Post Refresh ",count)
    print("Number of potential Techniques Increase In Severity Post Refresh to Potential ", poten_count)
    print("Number of Pre Refresh Techniques Covered ", len(pre_technqs.get('techniques')))
    print("Number of Post Refresh Techniques Covered ", len(post_technqs.get('techniques')))
    print("Number of Potential Techniques Covered Post Refresh ", len(poten_technqs.get('techniques')))
    out_to_json(po_pre_id, input_path+"post_pre_Techniques.json", original_stdout, input_path)
    out_to_json(poten_po_id, input_path+"poten_post_Techniques.json", original_stdout, input_path)
    
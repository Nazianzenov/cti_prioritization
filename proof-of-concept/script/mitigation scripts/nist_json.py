import json

filename = "../../../data/nist_attack.json"
def get_related_ttps(mitigation):
    ttps = set()
    with open(filename,"r") as f:
        mapping_list = json.load(f)["Mappings"]
    for m in mapping_list:
        if m["Control ID"] == mitigation:
            if "." not in m["Technique ID"]:
                ttps.add(m["Technique ID"])
    return list(ttps)

print(get_related_ttps("RA-5"))

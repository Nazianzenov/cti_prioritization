import json
from capec_extractor import get_capecs
from cwe_extractor import extract_weaknesses
from cve_extractor import cve_dict,cpes_list
cve_fn = "cve.json"
cwe_fn = "cwe.xml"
capec_fn = "capec.xml"


def get_asset_from_cwes(cwes):
    assets = set()
    cve_d = cve_dict()
    res, l = extract_weaknesses()
    matching_cves = []
    for k, v in res.items():
        for cwe in cwes:
            if cwe in v:
                matching_cves.append(k)
    for k, v in cve_d.items():
        for cve in matching_cves:
            if cve in v:
                assets.add(k)

    return list(assets)


def capec_json():
    d = {"attack_patterns":[]}

    cwe_capecs,l = get_capecs(cwe_fn)
    for capec_entry in l:
        entry = {"code": capec_entry, "cwes": []}
        for k,v in cwe_capecs.items():
            if capec_entry in v:
                entry["cwes"].append(k)
        entry["asset_refs"] = get_asset_from_cwes(entry["cwes"])
        d["attack_patterns"].append(entry)
    return d
def get_asset_from_cves(cves):
    assets = set()
    cve_d = cve_dict()
    for k,v in cve_d.items():
        for cve in cves:
            if cve in v:
                assets.add(k)
    return list(assets)
def cwe_json():
    d = {"weaknesses": []}
    cve_cwe,l = extract_weaknesses()
    cwe_capecs,_ = get_capecs(cwe_fn)
    for cwe_entry in l:
        entry = {"code": cwe_entry, "vulnerabilities": [],}
        for k,v in cve_cwe.items():
            if cwe_entry in v:
                entry["vulnerabilities"].append(k)
        entry["capecs"] = cwe_capecs[cwe_entry]
        entry["asset_refs"] = get_asset_from_cves(entry["vulnerabilities"])
        d["weaknesses"].append(entry)
    return d
def cve_json():
    d = {"vulnerabilities": []}
    c = cve_dict()
    cve_cwe, l = extract_weaknesses()
    with open("cve.json", "r") as local_catalogue:
        local_catalogue = json.load(local_catalogue)["CVE_Items"]
    for cve in local_catalogue:
        entry = {"id": cve["cve"]["CVE_data_meta"]["ID"], "cpe_ids": [],
                 "name": cve["cve"]["description"]["description_data"][0]["value"], "asset_refs": []}

        cwes = cve_cwe.get(entry["id"], [])
        if len(cwes) > 0:
            entry["weaknesses"] = cwes
        entry["exploitability_score"] = cve["impact"]["baseMetricV3"]["exploitabilityScore"]
        entry["impact_score"] = cve["impact"]["baseMetricV3"]["impactScore"]
        entry["cvssV3"] = cve["impact"]["baseMetricV3"]["cvssV3"]
        cpe_ids = set()
        assets = set()
        for k,v in c.items():

            if entry["id"] in v:
                for x in cpes_list[k]:
                    cpe_ids.add(x)
                assets.add(k)
        entry["cpe_ids"] = list(cpe_ids)
        entry["asset_refs"] = list(assets)
        d["vulnerabilities"].append(entry)
    return d


with open("cves_tra.json", "w") as ct:
    json.dump(cve_json(), ct, indent=4)








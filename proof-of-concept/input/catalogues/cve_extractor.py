import json
filename = "../../../data/nvdcve-1.1-2021.json"

def extract_cves(cpe):
    counter = 0
    with open("cve.json","r") as local_catalogue:
        local_catalogue = json.load(local_catalogue)
    with open(filename,"r") as catalogue:
        catalogue = json.load(catalogue)["CVE_Items"]
    for cve in catalogue:
        if counter >= 35:
            break
        for node in  cve["configurations"]["nodes"]:
            for cpes in node["cpe_match"]:
                if cpe in cpes["cpe23Uri"]:
                    counter += 1
                    local_catalogue["CVE_Items"].append(cve)
    if counter == 0:
        return counter
    with open("cve_ext.json", "w") as cvee:
        json.dump(local_catalogue,cvee,indent=4)
    return counter


cpes_list = {
    "nginx-keycloack-wserver": ["cpe:2.3:a:hypr:keycloak_authenticator:-:*:*:*:*:*:*:*",
                                "cpe:2.3:a:f5:nginx:1.1.1:*:*:*:*:*:*:*"],
    "nodejs_wapp-govspace": ["cpe:2.3:a:openjsf:express:4.3.1:*:*:*:*:node.js:*:*",
                             "cpe:2.3:a:nodejs:node.js:6.2.1:*:*:*:lts:*:*:*"],
    "nodejs_wapp-astra": ["cpe:2.3:a:openjsf:express:4.3.1:*:*:*:*:node.js:*:*",
                          "cpe:2.3:a:nodejs:node.js:6.2.1:*:*:*:lts:*:*:*"],
    "azure-cloud-govspace": ["cpe:2.3:a:microsoft:azure_open_management_infrastructure:-:*:*:*:*:*:*:*"],
    "oracle-sql-astra": ["cpe:2.3:a:oracle:mysql:8.0.18:*:*:*:*:*:*:*"],
}

cpes_list_cut = {
    "nginx-keycloack-wserver": ["cpe:2.3:a:hypr:keycloak_authenticator:",
                                "cpe:2.3:a:f5:nginx:"],
    "nodejs_wapp-govspace": ["cpe:2.3:a:openjsf:express:",
                             "cpe:2.3:a:nodejs:node.js:"],
    "nodejs_wapp-astra": ["cpe:2.3:a:openjsf:express:",
                          "cpe:2.3:a:nodejs:node.js:"],
    "azure-cloud-govspace": ["cpe:2.3:a:microsoft:azure_open_management_infrastructure:"],
    "oracle-sql-astra": ["cpe:2.3:a:oracle:mysql"]
}

def cve_dict():
    d = {}
    for asset, cpes in cpes_list_cut.items():
        d[asset] = []
        for cpe in cpes:
            with open("cve.json", "r") as local_catalogue:
                local_catalogue = json.load(local_catalogue)["CVE_Items"]
            for cve in local_catalogue:
                for node in cve["configurations"]["nodes"]:
                    for cpes in node["cpe_match"]:
                        if cpe in cpes["cpe23Uri"]:
                           d[asset].append(cve["cve"]["CVE_data_meta"]["ID"])
    return d


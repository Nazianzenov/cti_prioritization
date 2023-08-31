import json
import xml.etree.ElementTree as ET

filename = "cve.json"
filename_cwe = "../../../data/1000.xml"

def extract_weaknesses():
    res = {
    }

    with open(filename,"r") as cves:
        cves = json.load(cves)["CVE_Items"]

    for cve in cves:
        cve_info = cve["cve"]
        for data in cve_info["problemtype"]["problemtype_data"]:
            for d in data.get("description",[]):
                value = d.get("value","NOT")
                if len(value) > 4:
                    if value[:3] == "CWE":
                        id = cve_info["CVE_data_meta"]["ID"]
                        if res.get(id,None) is None:
                            res[id] = [value]
                        else:
                            res[id].append(value)
    s = set(list([item for sublist in res.values() for item in sublist]))

    return res,list(s)

print(extract_weaknesses()[1])
def build_cwe_catalogue(fn):
   l,v = extract_weaknesses()
   tree = ET.parse(fn)
   root = tree.getroot()

   # Define the namespace dictionary
   namespaces = {
       'cwe': 'http://cwe.mitre.org/cwe-7'
   }
   # Find the 'Weaknesses' element using the namespace
   weaknesses = root.find('.//cwe:Weaknesses', namespaces=namespaces)
   for element in weaknesses.findall(".//cwe:Weakness", namespaces=namespaces):
       if "CWE-"+element.get("ID") not in v:
           weaknesses.remove(element)

   tree = ET.ElementTree(root)
   tree.write(f"cwe.xml")


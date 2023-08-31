import time
import xml.etree.ElementTree as ET
from cwe_extractor import extract_weaknesses

filename = "cwe.xml"
catalogue = "../../../data/capec_latest.xml"
def get_capecs(fn):
    tree = ET.parse(fn)
    root = tree.getroot()

    res = {}
    for w in extract_weaknesses()[1]:
        res[w] = []
    namespaces = {
        'cwe': 'http://cwe.mitre.org/cwe-7'
    }

    weaknesses = root.find('.//cwe:Weaknesses', namespaces=namespaces)
    for element in weaknesses.findall(".//cwe:Weakness", namespaces=namespaces):
        id = element.get("ID")
        id = f"CWE-{id}"
        capec_elements = element.find('.//cwe:Related_Attack_Patterns', namespaces=namespaces)
        if capec_elements is not None:
            for capec in capec_elements.findall(".//cwe:Related_Attack_Pattern",namespaces=namespaces):
                 res[id].append("CAPEC-" + capec.get("CAPEC_ID"))
    capecs = set(list([item for sublist in res.values() for item in sublist]))
    return res,list(capecs)

def build_capec_catalogue(fn):
    tree = ET.parse(fn)
    root = tree.getroot()
    capecs = get_capecs(filename)[1]

    res = {}
    for c in get_capecs(filename)[1]:
        res[c] = []
    namespaces = {
        'capec': 'http://capec.mitre.org/capec-3'
    }

    capecs_patterns = root.find('.//capec:Attack_Patterns', namespaces=namespaces)
    for element in capecs_patterns.findall(".capec:Attack_Pattern", namespaces=namespaces):
        if "CAPEC-" + element.get("ID") not in capecs:
            capecs_patterns.remove(element)

    tree = ET.ElementTree(root)
    tree.write(f"capec.xml")




            
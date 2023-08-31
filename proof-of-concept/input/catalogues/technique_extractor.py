import xml.etree.ElementTree as ET
from capec_extractor import get_capecs

filename = "capec.xml"
catalogue = "../../../data/capec_latest.xml"


def get_techniques(fn):
    tree = ET.parse(fn)
    root = tree.getroot()

    res = {}
    for c in get_capecs("cwe.xml")[1]:
        res[c] = []
    namespaces = {
        'ns0': 'http://capec.mitre.org/capec-3'
    }

    capecs_patterns = root.find('.//ns0:Attack_Patterns', namespaces=namespaces)
    for element in capecs_patterns.findall(".//ns0:Attack_Pattern", namespaces=namespaces):
            id = element.get("ID")
            id = f"CAPEC-{id}"
            taxonomies = element.find(".//ns0:Taxonomy_Mappings", namespaces=namespaces)
            if taxonomies is not None:
                for tax in taxonomies.findall(".//ns0:Taxonomy_Mapping", namespaces=namespaces):
                    name = tax.get("Taxonomy_Name")

                    [id].append((tax.get("Taxonomy_Name"),tax.get("Entry_ID"),tax.get("Entry_Name")))

    techniques = set(list([item for sublist in res.values() for item in sublist]))
    return res, list(techniques)

print(get_techniques(filename)[1])


import hashlib

from stix2.v21 import (Indicator,Malware,Relationship, Bundle)
from stix2 import MemoryStore
from faker import Faker
faker = Faker()
def generate_indicator_url(n, malware_name, itypes,mw):
    url = faker.bothify(text="http://????.##??#?.com",letters=n.replace(" ",""))
    i = Indicator(
        name= n,
        description = f"This url refers to a {n} indicating the Malware {malware_name}",
        indicator_types= itypes,
        pattern_type="stix",
        pattern=f"[url:value = '{url}']"
    )
    return i, Relationship(i,"indicates",mw)


def generate_indicator_hash(n, malware_name, itypes, mw):
    m = hashlib.sha256()
    m.update(faker.bothify("??????????????",letters=malware_name + n).encode("utf-8"))

    i = Indicator(
        name=n,
        description=f"This hash refers to the checksum of a file of a variant of the Malware {malware_name}",
        indicator_types=itypes,
        pattern_type="stix",
        pattern=f"[file:hashes.'SHA-256' = '{m.hexdigest()}']"
    )
    return i, Relationship(i, "indicates", mw)

def generate_ipv4(n):
    pattern = f"[ipv4-addr:value = '{faker.ipv4()}/32' OR ipv4-addr:value = '{faker.ipv4()}/32']"
    i = Indicator(
        name=n,
        description=f"IP addresses referring to external servers used by APT2312 to exfiltrate data",
        indicator_types="['attribution','malicious-activity']",
        pattern_type="stix",
        pattern=pattern
    )
    return i

def generate_malware(name):
    return Malware(
        name=name,
        malware_types=["back_door", "remote-access-trojan"],
        description="This malware exploits a vulnerability in nginx allowing the attacker to HTTP flood the server with spoofed source IP, with the goal of perform DoS.",
        is_family="true",
        capabilities=["accesses-remote-machines", "compromises-system-availability"]
    )

def gen_ips():
    mem = MemoryStore()
    o = []
    for dom in ["xyz","com","net","ru","pl","lu"]:
        indicator = generate_ipv4(faker.bothify(text=f"http://????.##??#?.{dom}"))
        o.append(indicator)
    bundle = Bundle(objects=o)
    mem.add(bundle)
    mem.save_to_file("bundle.indicators.json")

gen_ips()
def generate_core_dospark():
    mw = generate_malware("DoSpark")
    mem = MemoryStore()
    objs = []
    for i in range(3):
        indicator,rel = generate_indicator_url("website hosting malware downloader","DoSpark", ["malicious-activity"],mw)
        objs.append(indicator)
        objs.append(rel)
    for i in range(3):
        indicator,rel = generate_indicator_hash("DoSpark variant","DoSpark",["malicious-activity"],mw)
        objs.append(indicator)
        objs.append(rel)
    bundle = Bundle(objects=objs)
    mem.add(bundle)
    mem.add(mw)
    mem.save_to_file("bundle.json")



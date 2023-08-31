import json
from difflib import SequenceMatcher as SM
from datetime import datetime, timedelta
from constants import *
filename = "../input/tra.json"

# stix attributes
vulnerability = "vulnerability"
ta = "threat-actor"
mw = "malware"
campaign = "campaign"
intrusion_set = "intrusion-set"
identity = "identity"
location = "location"
attack_pattern = "attack-pattern"
tool = "tool"
infra = "infrastructure"
indicator = "indicator"
ext_refs = "external_references"
ext_id = "external_id"
ID = "id"


# STIX-RELATED METRICS
THREAT_ACTORS = ["threat-actor", "intrusion-set", "campaign"]
SKILL_LEVELS = ["none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"]
SECTORS = """agriculture, aerospace, automotive, communications, construction, defence, education, energy, entertainment,
           financial - services, government - national, government - regional, government - local,
           government - public - services, healthcare, hospitality - leisure, infrastructure, insurance, manufacturing,
           mining, non - profit, pharmaceuticals, retail, technology, telecommunications, transportation, utilities""".split(
    ", ")
TA_TYPES = """activist, competitor, crime - syndicate, criminal, hacker,
              insider - accidental, insider - disgruntled, nation - state,
              sensationalist, spy, terrorist, unknown""".split(", ")

RESOURCE_LVL = ["individual","club","contest","team","organization","government"]
def jaccard(a:set,b:set):
    intersection = len(a.intersection(b))
    union = len(a.union(b))
    jaccard_index = intersection / union if union != 0 else 0 # div by 0
    return jaccard_index

def get_tra():
    with open(filename) as tra:
        tra = json.load(tra)
    return tra

def get_vuln(code):
    tra = get_tra()["vulnerabilities"]
    for v in tra:
        if v[ID] == code:
            return v
    return None

# ============= CPE MATCH =============
def find_cpe_match_from_vuln(bundle_list):
    cpe_matches = {}
    for i in range(len(bundle_list)):
        cpe_matches[i] = []

    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        for k,v in bundle.items():
            if vulnerability in k:
                ext = v.get(ext_refs,None)
                if len(ext) > 0:
                    v_code = ext[0][ext_id]
                    tra_v = get_vuln(v_code)
                    if tra_v is not None:
                        for cpe in tra_v["cpe_ids"]:
                            cpe_matches[i].append(cpe)
    return cpe_matches

def score_cpe_match(bundle_list):
    bundle_scores = {}
    tra = get_tra()["assets"]
    l = sum([1 if a["type"] == "SUPPORT" else 0 for a in tra])
    cpe_matches = find_cpe_match_from_vuln(bundle_list)
    for k,v in cpe_matches.items():
        bundle_scores[k] = round((len(v) / l) * 4) # we map the number of cpes to a score between 0 and 4
    return bundle_scores


# ============= SECTOR MATCH =============

def find_sector_match(bundle_list):
    sector_matches = {}
    for i in range(len(bundle_list)):
        sector_matches[i] = []
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        sector_matches[i] =  get_sectors_from_bundle(bundle)
    return sector_matches

def score_sector(bundle_list):
    sector_scores = {}
    sector_matches = find_sector_match(bundle_list)
    for k,v in sector_matches.items():
        bundle_sectors, tra_sectors = v
        sector_scores[k] = round(jaccard(bundle_sectors,tra_sectors)*4)
    return sector_scores

def get_sectors_from_bundle(bundle):
    tra = set(get_tra()["geo_sectoral"]["sectors"])
    bundle_sectors = set()
    for k,bd in bundle.items():
        if identity in k:
            sectors = bd.get("sectors",[])
            if len(sectors) > 0:
                for s in sectors:
                    bundle_sectors.add(s)
        if any([a in k for a in [ta,mw,intrusion_set,campaign]]):
            desc = bd.get("description","")
            if len(desc) > 0:
                for r in extract_sectors_from_description(desc):
                    bundle_sectors.add(r)
    return bundle_sectors,tra

def extract_sectors_from_description(desc):
    res = set()
    for sec in SECTORS:
        for s in desc:
            if SM(None,sec,s).ratio() > 0.92:
                res.add(sec)
    return list(res)

# ============= GEOGRAPHICAL MATCH =============

def find_geo_match(bundle_list):
    geo_matches = {}
    for i in range(len(bundle_list)):
        geo_matches[i] = []
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        geo_matches[i] = get_geographical_metrics_from_bundle(bundle)
    return geo_matches

def score_geo_match(bundle_list):
    geo_matches= find_geo_match(bundle_list)
    geo_scores = {}
    for k,v in geo_matches.items():
        a,g = v
        geo_scores[k] = 4 if len(a + g) > 2 else 2 if len(a+g) > 0 else 1
    return geo_scores

def get_geographical_metrics_from_bundle(bundle):
    tra = get_tra()
    asset_metrics = [x for a in tra["asset_metrics"] for metric in a["locations"] for x in metric.values()]
    geo_sectoral = tra["geo_sectoral"]["regions"]

    bundle_asset_geo = set()
    bundle_global_geo = set()

    for k,bd in bundle.items():
        if location in k:
            loc = filter(lambda x: x != "", [bd.get("region",""), bd.get("country",""),bd.get("city","")])
            for r in extract_geometrics_from_description(loc, asset_metrics):
                bundle_asset_geo.add(r)
            for r in extract_geometrics_from_description(loc, geo_sectoral):
                bundle_global_geo.add(r)


        if any([a in k for a in [ta, mw, intrusion_set, campaign]]):
            desc = bd.get("description", "")
            if len(desc) > 0:
                for r in extract_geometrics_from_description(desc,asset_metrics):
                    bundle_asset_geo.add(r)
                for r in extract_geometrics_from_description(desc,geo_sectoral):
                    bundle_global_geo.add(r)

    return list(bundle_asset_geo),list(bundle_global_geo)


def extract_geometrics_from_description(desc,tra):
    res = set()
    for metric in tra:
        for s in desc:
            if SM(None, metric, s).ratio() > 0.92:
                res.add(metric)
    return list(res)

# ============= OBJECTIVE MATCH =============

def score_objective_matches(bundle_list):
    obj_scores = {}
    obj_matches = find_objective_matches(bundle_list)
    for k,v in obj_matches.items():
        obj_scores[k] = round(v*4)
    return obj_scores

def find_objective_matches(bundle_list):
    obj_matches = {}
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        obj_matches[i] = get_objective_match_from_bundle(bundle)
    return obj_matches
def get_objective_match_from_bundle(bundle):
    objective_match = 0
    tra = get_tra()["threat_scenarios"]
    for k, bd in bundle.items():
        if campaign in k:
            for scen in tra:
                objective_match = max(SM(None,scen["description"],bd["description"]).ratio(),objective_match)
    return objective_match



# ============= ACTIVITY =============

def activity_scoring(ts: datetime):
    if map_activity_to_score(ts, timedelta(days= 30)):
        return 4
    elif map_activity_to_score(ts, timedelta(days=3 * 30)):
        return 3
    elif map_activity_to_score(ts, timedelta(days=6 * 30)):
        return 2
    elif map_activity_to_score(ts, timedelta(days=12 * 30)):
        return 1
    else:
        return 0
def map_activity_to_score(ts: datetime,delta):
    current_date = datetime.now()
    time_delta = current_date - ts
    return time_delta < delta
def score_activity(bundle_list):
    score_act = {}
    activities = find_activity(bundle_list)
    reference_date = datetime(1970, 1, 1)
    for k,v in activities.items():
        rac, rat, act, att = v

        # computing the mean of timestamps
        if len(act) > 0:
            act = sum([(a - reference_date).total_seconds() for a in act]) / len(act)
            act += (rac - reference_date).total_seconds()
            act = act / 2
            act = reference_date + timedelta(seconds=act)
        else:
            act = reference_date

        if len(att) > 0:
            att = sum([(a - reference_date).total_seconds() for a in att]) / len(att)
            att += (rat - reference_date).total_seconds()
            att = att / 2
            att = reference_date + timedelta(seconds=att)
        else:
            att = reference_date
        score_act[k] = activity_scoring(act),activity_scoring(att)
    return score_act



def get_activity_match_from_bundle(bundle):
    recent_actor = None
    actor_times = []
    recent_attack = None
    attack_times = []
    for k, bd in bundle.items():
        if any([a in k for a in [ta, intrusion_set, campaign]]):
            last = bd.get("last_seen",None)
            if last is not None:
                last = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.%fZ")
                actor_times.append(last)
                if recent_actor is None or last > recent_actor:
                    recent_actor = last
        if any([a in k for a in [mw,vulnerability,attack_pattern,tool,infra,indicator]]):
            last = bd.get("last_seen", None)
            if last is not None:
                last = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.%fZ")
                attack_times.append(last)
                if recent_attack is None or last > recent_attack:
                    recent_attack = last
    return recent_actor,recent_attack,actor_times,attack_times


def find_activity(bundle_list):
    activities = {}
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        activities[i] = get_activity_match_from_bundle(bundle)
    return activities

# ============= SOPHISTICATION =============

def score_sophistication_matches(bundle_list):
    sophs = {}
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        sophs[i] = get_sophistication_map_from_bundle(bundle)
    return sophs
def get_sophistication_map_from_bundle(bundle):
    res = []
    for k ,bd in bundle.items():
        if ta in k:
            sop = bd.get("sophistication","")
            if sop != "":
                res.append(sop)
    res = [get_sophistication_value(x) for x in res]
    if len(res) == 0:
        res = 0
    else:
        res = sum(res) / len(res)
    return map_to_probabilistic(res)


def sophistication_map(x):
    return x * 2 / 3

def get_sophistication_value(x):
    return sophistication_map(SKILL_LEVELS.index(x))

def map_to_probabilistic(num_val):
    bottom = scale_table[int(num_val)]
    up = scale_table[min(int(num_val) + 1, LEN - 1)]
    result = [0 for _ in scale_table]
    if bottom == up:
        result[up] = 1
    else:
        result[bottom] = up - num_val
        result[up] = 1 - result[bottom]
    return [[x] for x in result]

# ============= ATT&CK Coverage =============

def score_attck_coverage(bundle_list):
    att_cov = find_attck_coverage(bundle_list)
    att_score = {}
    tra = get_tra()
    threats = tra["threats"]
    for k,v in att_cov.items():
        v,ttc = v
        score = 0
        if len(v) > 0:
            score = 1 # the score is set to low as long as a matching threat was detected in the CTI
        elif ttc > 0: # if other non-matching threats were found, we can relatively well say the coverage is low
            att_score[k] = score
            continue
        else: # no information on attack coverage, equal probability score
            att_score[k] = [[0.2] for _ in range(5)]
            continue


        max_score = len(tra["threat_scenarios"])*len(tra["attack_patterns"])*len(v)
        weights = 0
        for code,name in v:
            for t in threats:
                  if t["code"] == code:
                      # we use the number of affected threat scenarios and the catalogue mappings to establish a
                      # coverage score
                      weights += len(t["ts_refs"])*len(t["catalogue_mappings"])
        att_score[k] = min(4,round(score + (weights / max_score) * 5 ))
    return att_score

def find_attck_coverage(bundle_list):
    att_cov = {}
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        att_cov[i] = get_attck_coverage(bundle)
    return att_cov
def get_attck_coverage(bundle):
    tra = get_tra()
    threats = set()
    total_threats_count = 0
    for k,bd in bundle.items():
        if attack_pattern in k:
            capec = None
            ext = bd.get(ext_refs,[])
            if len(ext) > 0:
                capec = bd.get(ext_id,"")
                if len(capec) <= 0 or capec[:5].upper() != "CAPEC":
                    capec = None
                else:
                    total_threats_count += 1
            for threat in tra["threats"]:
                    if capec is not None and capec in threat["catalogue_mappings"]: # match the ext id with a CAPEC
                        threats.add((threat["code"],threat["name"]))
                    if SM(None,threat["name"],bd["name"]).ratio() > 0.95: # match the name with a TTP
                        threats.add((threat["code"], threat["name"]))
    return list(threats),total_threats_count




# ============= RESOURCE LEVEL =============

def score_resource_levels(bundle_list):
    r_levels = find_resource_levels(bundle_list)
    r_score = {}
    for k,v in r_levels.items():
        if len(v) == 0:
            r_score[k] = 1
        else:
            r_level = (sum([RESOURCE_LVL.index(r) for r in v]) / len(v)) / len(RESOURCE_LVL) # normalize to 0-1 scale
            r_score[k] = min(4,1 + round(r_level) * 5) # set score to 5-scale
    return r_score

def find_resource_levels(bundle_list):
    resource_lvls = {}
    for i in range(len(bundle_list)):
        bundle = bundle_list[i]
        resource_lvls[i] = get_resource_level(bundle)
    return resource_lvls

def get_resource_level(bundle):
    r_level = set()
    for k, bd in bundle.items():
        if any([a in k for a in [ta, intrusion_set]]):
            rl = bd.get("resource_level", "")
            if len(rl) > 0:
                r_level.add(rl)
            # check if an identity is linked to a threat actor
        if identity in k:
            for k2, bd2 in bundle.items():
                if "relationship" in k2:
                    if ta in bd2["source_ref"] and identity in bd2["target_ref"] and bd["relationship_type"] == "attributed_to":
                       id_class = bd["identity_class"]
                       if id_class == "individual" or id_class == "group" or id_class == "organization":
                           r_level.add(id_class.replace("group","team"))
    return list(r_level)

# ============= EXPLOITABILITY =============
def score_tra_exploitability_metric():
    tra = get_tra()
    exploitability_arr = [v["exploitability_score"] for v in tra["vulnerabilities"]]
    exploitability_mean = sum(exploitability_arr)
    exploitability_mean = (exploitability_mean / len(exploitability_arr)) / 2
    return map_to_probabilistic(exploitability_mean)

# ============ CONTROLS =================

def score_controls_strength(bundle_list):
    cs_score = {}
    for i in range(len(bundle_list)):
        cs_score[i] = get_controls_strength(bundle_list[i])
    return cs_score

def get_controls_strength(bundle):
    # check threats (attack coverage basically)
    # for those, you can easily find the control strength of each
    att_cov,ttc = get_attck_coverage(bundle)
    tra = get_tra()["threats"]
    counter = 0
    cs = 0
    for code,name in att_cov:
        for threat in tra:
            if threat["code"] == code:
                controls = threat.get("controls",[])
                for control in controls:
                    cs += control["strength"]
                    counter+=1
    if counter == 0:
        return 0
    cs = cs / (counter*10) # average and normalize
    return map_to_probabilistic(cs * 5)




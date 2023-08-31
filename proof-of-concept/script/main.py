import sys

from community_detection import detect_stix_community
from analytics import *
from metrics import  *
import json
from FAIR_tree import BFModel,Metric,StateDictionary
from bnn_fair import compute_score
from bayesian_analytics import rank_score
URL = "https://raw.githubusercontent.com/Nazianzenov/cti_prioritization/main/input/cti.json"


def score():
    with open("cluster.json", "r") as cl:
        clustered_bundle = json.load(cl)
        # score each cluster centered around a threat actor
    cpe_match = score_cpe_match(clustered_bundle)
    sector_match = score_sector(clustered_bundle)
    geo_match = score_geo_match(clustered_bundle)
    objective_match = score_objective_matches(clustered_bundle)
    activity = score_activity(clustered_bundle)
    sophistication = score_sophistication_matches(clustered_bundle)
    attack_coverage = score_attck_coverage(clustered_bundle)
    resource_level = score_resource_levels(clustered_bundle)
    exploitability = score_tra_exploitability_metric()
    control_strengths = score_controls_strength(clustered_bundle)

    for i in range(len(clustered_bundle)):
        print("The cluster has the following elements:")
        # state dictionary

        state_d = {
            Metric.IS.value: cpe_match[i],
            Metric.SM.value: sector_match[i],
            Metric.GS.value: geo_match[i],
            Metric.OM.value: objective_match[i],
            Metric.LSC.value: activity[i][0],
            Metric.LSA.value: activity[i][1],
            Metric.SL.value: sophistication[i],
            Metric.R.value: resource_level[i],
            Metric.AC.value: attack_coverage[i],
            Metric.EX.value: exploitability,
            Metric.CES.value: control_strengths[i]
        }

        state_dict = StateDictionary(state_d, True)
        bayesian_fair = BFModel(state_dict)
        bayesian_fair.compute_BN()
        prob_score = bayesian_fair.compute_LEF_inference()
        final_score = compute_score(prob_score)
        print(rank_score(final_score))


def cluster():
    res = detect_stix_community(URL, "cti")
    cb = convert_community_to_objects(res)
    js = cb
    with open("cluster.json", "w") as cl:
        json.dump(js, cl, indent=4)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python program.py <command>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "cluster":
        cluster()
    elif command == "score":
        score()
    else:
        print("Invalid command. Available commands: cluster, score")




from dataclasses import dataclass
from enum import Enum
from constants import *
import numpy as np
import json

# Metrics enumeration
class Metric(Enum):
    V = "Vulnerability"
    TEF = "Threat Event Frequency"
    C = "Contact Frequency"
    PA = "Probability of Action"
    LEF = "Loss Event Frequency"
    IS = "CPE Match"
    GSM = 'Geo sectoral match'
    OM = "Objective Match"
    ACT = "Activity"
    LSC = "Last Campaign"
    LSA = "Last Attack"
    SM = "Sector Match"
    GS = "Geographical Match"
    SL = "Sophistication Level"
    AC = "ATT&CK Coverage"
    R = "Resource Level"
    TC = "Threat Capability"
    TAS ="Skills"
    RB = "Robustness"
    EX = "Exploitability"
    CES = "Controls Strength"

metric_reverse_dict = {m.value.upper(): m for m in Metric}

# FAIR table type
@dataclass
class FAIRTable:
    table: np.ndarray
    x: Metric
    y: Metric


FairTables = dict[Metric,FAIRTable]
def load_fair_tables() -> FairTables:
    try:
        with open(FAIR_DB_NAME, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.decoder.JSONDecodeError) as error:
        print(f"Failed to load the FAIR matrices: {error}")
        return {}
    res = {}
    for metric,table in data.items():
        metric = metric_reverse_dict[metric.upper()]
        x = metric_reverse_dict[table["x"].upper()]
        y = metric_reverse_dict[table["y"].upper()]
        res[metric] = FAIRTable(np.array(table["table"]),x,y)
    return res


TABLES_DICT = load_fair_tables()



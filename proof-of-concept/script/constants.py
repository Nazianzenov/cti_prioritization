"""
Module defining constants for the Proof-of-concept
"""
FAIR_DB_NAME = "tables.json"

# defining metric scales
VL = 0
L = 1
M = 2
H = 3
VH = 4


# Fuzzy base factor
K = 5
scale_table = [VL, L, M, H, VH]
LEN = len(scale_table)

SCALE = len(scale_table)

# dictionary for semantic mapping
state_to_semantic = {VL: "Very Low",
                     L: "Low",
                     M: "Medium",
                     H: "High",
                     VH: "Very High"}

semantic_to_state = {"Very Low": VL,
                     "Low": L,
                     "Medium": M,
                     "High": H,
                     "Very High": VH}

acronym_dict = {"VL": "Very Low",
                "L": "Low",
                "M": "Medium",
                "H": "High",
                "VH": "Very High"}

scale_semantic = [state_to_semantic[s] for s in scale_table]

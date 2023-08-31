from itertools import product
from bnn_fair import *
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import BeliefPropagation
from dataclasses import dataclass
from constants import scale_table,scale_semantic
import warnings

warnings.filterwarnings("ignore",category=RuntimeWarning)


class FAIRTree:
    def __init__(self, metric: Metric, leaf_left: bool, leaf_right: bool, table: FAIRTable, left=None, right=None):
        self.metric = metric
        self.table = table
        self.leaf_left: bool = leaf_left
        self.leaf_right: bool = leaf_right
        self.left = left
        self.right = right
        self.cpt = []
        self.weights = []
        self.judging_vectors = []
        self.score = 0

    def compute_weights(self):
        self.weights = get_weight_vector(self.table.table)
        if not self.leaf_left:
            self.left.compute_weights()
        if not self.leaf_right:
            self.right.compute_weights()

    def compute_judging_vectors(self):
        self.judging_vectors = []
        for m in self.left.metric, self.right.metric:
            r = compute_fuzzy_vector(self.table, m)
            r.reverse()
            self.judging_vectors.append(r)
        if not self.leaf_left:
            self.left.compute_judging_vectors()
        if not self.leaf_right:
            self.right.compute_judging_vectors()

    def compute_cpt(self):
        self.cpt = []
        state_pairs = list(product(scale_table, repeat=2))
        for s in scale_table:
            vector = []
            for pair in state_pairs:
                vector.append(compute_cpt(self.judging_vectors, self.weights, s, pair))
            self.cpt.append(vector)
        if not self.leaf_left:
            self.left.compute_cpt()
        if not self.leaf_right:
            self.right.compute_cpt()

    def compute_score(self):
        self.score = compute_score(self.cpt)

    def compute_tree(self):
        if self.table is None:
            return -1
        t = self.table
        if self.leaf_left:
            vl = self.left.value
            x = vl.index([1])
        else:
            x = self.left.compute_tree()

        if self.leaf_right:
            vr = self.right.value
            y = vr.index([1])
        else:
            y = self.right.compute_tree()

        return get_elem(t.table, x, y)


class FAIRLeaf:
    def __init__(self, value, nb_state, metric: Metric):
        self.value = value
        self.nb_state = nb_state
        self.metric = metric


@dataclass
class StateDictionary:
    dictionary: dict
    is_probabilistic: bool

    def __init__(self, dictionary: dict, is_probabilistic: bool):
        self.dictionary = dictionary
        self.is_probabilistic = is_probabilistic

    def get_dict(self):
        return self.dictionary.copy()

    def set_dict(self, d):
        self.dictionary = d.copy()


    # converts the dictionary to probabilistic vector
    # example:
    # if a value is set to Very High, it will be converted to [0,0,0,0,1],
    # where the 1 corresponds to the index of very high. It means the metric is set to very high with a
    # probability of 1
    def convert_to_probabilistic(self):
        new_d = {}
        for k, v in self.dictionary.items():
            if isinstance(v,int):
                row = [[1] if i == v else [0] for i in range(SCALE)]
                new_d[k] = row
            else:
                new_d[k] = v
        self.dictionary = new_d


def create_lef_tree(state_d):

    # contact frequency tree
    sector_match = FAIRLeaf(state_d[Metric.SM.value],5,Metric.SM)
    geo_match = FAIRLeaf(state_d[Metric.GS.value],5,Metric.GS)
    geosector_match = FAIRTree(Metric.GSM,True,True,TABLES_DICT[Metric.GSM],sector_match,geo_match)

    cpe_match = FAIRLeaf(state_d[Metric.IS.value],5,Metric.IS)
    contact_freq = FAIRTree(Metric.C,True,False,TABLES_DICT[Metric.C],cpe_match,geosector_match)

    # probability of action tree

    last_campaign = FAIRLeaf(state_d[Metric.LSC.value], 5, Metric.LSC)
    last_attack = FAIRLeaf(state_d[Metric.LSA.value], 5, Metric.LSA)
    activity = FAIRTree(Metric.ACT, True, True, TABLES_DICT[Metric.ACT], last_campaign,last_attack)

    objective_match = FAIRLeaf(state_d[Metric.OM.value], 5, Metric.OM)
    probability_of_action = FAIRTree(Metric.PA, True, False, TABLES_DICT[Metric.PA], objective_match,activity)

   # threat event frequency

    tef = FAIRTree(Metric.TEF,False,False,TABLES_DICT[Metric.TEF],contact_freq,probability_of_action)

    # threat capability tree

    sophistication = FAIRLeaf(state_d[Metric.SL.value],5,Metric.SL)
    attack_cov = FAIRLeaf(state_d[Metric.AC.value],5,Metric.AC)
    skills = FAIRTree(Metric.TAS, True, True, TABLES_DICT[Metric.TAS], sophistication,attack_cov)

    resource_level = FAIRLeaf(state_d[Metric.R.value],5,Metric.R)
    threat_cap = FAIRTree(Metric.TC,False,True,TABLES_DICT[Metric.TC],skills,resource_level)

    # system robustness

    exploitability = FAIRLeaf(state_d[Metric.EX.value], 5, Metric.EX)
    controls_efficiency = FAIRLeaf(state_d[Metric.CES.value], 5, Metric.CES)
    system_rob = FAIRTree(Metric.RB, True, True, TABLES_DICT[Metric.RB], exploitability,controls_efficiency)

   # vulnerability

    vul = FAIRTree(Metric.V, False,False, TABLES_DICT[Metric.V], threat_cap,system_rob)

    # lef
    lef = FAIRTree(Metric.LEF, False, False, TABLES_DICT[Metric.LEF], tef,vul)

    return lef

def create_bayesian_network():
    return BayesianNetwork([
        (Metric.SM.value,Metric.GSM.value),
        (Metric.GS.value,Metric.GSM.value),
        (Metric.IS.value,Metric.C.value),
        (Metric.GSM.value,Metric.C.value),
        (Metric.C.value,Metric.TEF.value),
        (Metric.LSA.value,Metric.ACT.value),
        (Metric.LSC.value,Metric.ACT.value),
        (Metric.ACT.value,Metric.PA.value),
        (Metric.OM.value,Metric.PA.value),
        (Metric.PA.value,Metric.TEF.value),
        (Metric.TEF.value,Metric.LEF.value),
        (Metric.SL.value,Metric.TAS.value),
        (Metric.AC.value,Metric.TAS.value),
        (Metric.TAS.value,Metric.TC.value),
        (Metric.R.value,Metric.TC.value),
        (Metric.TC.value,Metric.V.value),
        (Metric.EX.value,Metric.RB.value),
        (Metric.CES.value,Metric.RB.value),
        (Metric.RB.value,Metric.V.value),
        (Metric.V.value,Metric.LEF.value)
    ])

def compute_tabular_cpd(top,left,right,tree):
    return TabularCPD(variable=top, variable_card=5,
               values=tree, evidence=[left,right],
               evidence_card=[5, 5], state_names={
            top: scale_semantic,
            left: scale_semantic,
            right: scale_semantic,
        })

def compute_cpd_leaf(m,state_d):
    values = state_d[m]
    return TabularCPD(variable=m, variable_card=5, values=values, state_names={m: scale_semantic})

class BFModel:
    def __init__(self, state_dict: StateDictionary):
        state_dict_copy = StateDictionary(state_dict.get_dict(), state_dict.is_probabilistic)
        state_dict_copy.convert_to_probabilistic()
        state_d = state_dict_copy.get_dict()

        lef = create_lef_tree(state_d)
        self.tree = lef
        self.BN = None
        self.inference = None
        self.cpds = {}
        self.state_dict = state_dict_copy

        self.tree.compute_weights()
        self.tree.compute_judging_vectors()
        self.tree.compute_cpt()

    def compute_BN(self):
        self.BN = create_bayesian_network()
        self.cpds[Metric.LEF.value] = compute_tabular_cpd(Metric.LEF.value,Metric.V.value,Metric.TEF.value,self.tree.cpt)
        self.cpds[Metric.TEF.value] = compute_tabular_cpd(Metric.TEF.value,Metric.C.value,Metric.PA.value,self.tree.left.cpt)
        self.cpds[Metric.V.value] = compute_tabular_cpd(Metric.V.value,Metric.TC.value,Metric.RB.value,self.tree.right.cpt)

        self.cpds[Metric.C.value] = compute_tabular_cpd(Metric.C.value,Metric.IS.value,Metric.GSM.value,self.tree.left.left.cpt)
        self.cpds[Metric.PA.value] = compute_tabular_cpd(Metric.PA.value, Metric.OM.value, Metric.ACT.value,
                                                   self.tree.left.right.cpt)
        self.cpds[Metric.GSM.value] = compute_tabular_cpd(Metric.GSM.value, Metric.SM.value, Metric.GS.value,
                                                    self.tree.left.left.right.cpt)
        self.cpds[Metric.ACT.value] = compute_tabular_cpd(Metric.ACT.value, Metric.LSC.value, Metric.LSA.value,
                                                    self.tree.left.right.right.cpt)

        self.cpds[Metric.TC.value] = compute_tabular_cpd(Metric.TC.value, Metric.TAS.value, Metric.R.value,
                                                         self.tree.right.left.cpt)
        self.cpds[Metric.RB.value] = compute_tabular_cpd(Metric.RB.value, Metric.EX.value, Metric.CES.value,
                                                         self.tree.right.right.cpt)
        self.cpds[Metric.TAS.value] = compute_tabular_cpd(Metric.TAS.value, Metric.SL.value, Metric.AC.value,
                                                          self.tree.right.left.left.cpt)

        self.cpds[Metric.IS.value] = compute_cpd_leaf(Metric.IS.value,self.state_dict.get_dict())
        self.cpds[Metric.SM.value] = compute_cpd_leaf(Metric.SM.value, self.state_dict.get_dict())
        self.cpds[Metric.OM.value] = compute_cpd_leaf(Metric.OM.value,self.state_dict.get_dict())
        self.cpds[Metric.GS.value] = compute_cpd_leaf(Metric.GS.value, self.state_dict.get_dict())
        self.cpds[Metric.LSC.value] = compute_cpd_leaf(Metric.LSC.value, self.state_dict.get_dict())
        self.cpds[Metric.LSA.value] = compute_cpd_leaf(Metric.LSA.value, self.state_dict.get_dict())
        self.cpds[Metric.SL.value] = compute_cpd_leaf(Metric.SL.value, self.state_dict.get_dict())
        self.cpds[Metric.AC.value] = compute_cpd_leaf(Metric.AC.value, self.state_dict.get_dict())
        self.cpds[Metric.R.value] = compute_cpd_leaf(Metric.R.value, self.state_dict.get_dict())
        self.cpds[Metric.EX.value] = compute_cpd_leaf(Metric.EX.value, self.state_dict.get_dict())
        self.cpds[Metric.CES.value] = compute_cpd_leaf(Metric.CES.value, self.state_dict.get_dict())
        for k,v in self.cpds.items():
            self.BN.add_cpds(v)

    def compute_LEF_inference(self):
        scales = scale_semantic
        evidence = self.state_dict.get_dict()
        for k, v in evidence.items():
            evidence[k] = TabularCPD(variable=k, variable_card=5, values=v, state_names={k: scales})
        self.inference = BeliefPropagation(self.BN)
        q = self.inference.query(variables=[Metric.LEF.value], virtual_evidence=evidence.values())
        return q.values

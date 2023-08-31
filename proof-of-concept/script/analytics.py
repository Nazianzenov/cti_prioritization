import json
from constants import *

filepath = "../input/cti.json"



def get_bundle(url):
    with open(url,"r") as file:
        return json.load(file)["objects"]

class Bundle:
    def __init__(self,URL):
        self.bundle = get_bundle(URL)
    def find(self,stix_id):
        for o in self.bundle:
            if o["id"] == stix_id:
                return o
        return None
    def get_community_objects(self, community):
        comm = {}
        for id in community["sids"]:
            obj = self.find(id)
            if obj is not None:
                comm[id] = obj
        return comm

def convert_community_to_objects(communities):
    b = Bundle(filepath)
    comm_objects = []
    for com in communities:
        comm_objects.append(b.get_community_objects(com))

    return comm_objects

def post_process_community(community):
    # TODO
    return 1
from neo4j import GraphDatabase,exceptions
uri = "bolt://localhost:7687"
username = "neo4j"
password ="xxxxxxxx"

stix_script_filename = "../cypher/template_stix_setup.cypher"
def get_driver():
    try:
      with GraphDatabase.driver(uri, auth=(username, password)) as driver:
        return driver
    except Exception as e:
        print(f"Error in the session opening: {e}")

def execute(driver,query,params=None):
    with driver.session() as session:
        if query != "":
            if params is not None:
                result = session.run(query,params)
            else:
                result = session.run(query)
            return result.data()
        return None

def load_stix_bundle(driver, params=None):
    with open(stix_script_filename,"r") as script:
        cypher_query = script.read()
    queries = cypher_query.split(";\n")
    results = []
    for query in queries:
        r = execute(driver, query, params)
        if r is not None:
            results.append(r)
    return results



def create_GDS_ta(driver, graph_name):
    query = f"""
           CALL gds.graph.project(
            '{graph_name}',
            ["Campaign","Identity", "ThreatActor","IntrusionSet"],
            "ATTRIBUTED-TO"
            );"""
    return execute(driver, query)

def delete_GDS(driver,graph_name):
    query = f"""
            CALL gds.graph.drop(\"{graph_name}\")"""

    try:
      r = execute(driver,query)
    except exceptions.ClientError:
        return None
    return r
def threat_partition(driver, graph_name):
    query = f"""
        CALL gds.wcc.stream(\"{graph_name}\",""" + """ {}) YIELD nodeId, componentId
WITH componentId, collect(gds.util.asNode(nodeId).id) AS stix_ids
RETURN componentId AS cluster_id, stix_ids;
        """
    result = execute(driver,query)
    return result

def louvain(driver,graph_name):
    query = f"""
            CALL gds.louvain.stream(\'{graph_name}\'""" +""",{relationshipWeightProperty: 'weight'})
                YIELD nodeId, communityId, intermediateCommunityIds
                WITH gds.util.asNode(nodeId).id AS stix_id, communityId
                ORDER BY communityId ASC
                WITH communityId, COLLECT(stix_id) AS sids
                RETURN communityId, sids, SIZE(sids) AS NbIds;
            """
    result = execute(driver, query)
    return result

def detect_stix_community(stix_url,graph_name):
    driver = get_driver()
    delete_GDS(driver, graph_name)
    load_stix_bundle(driver, params={
        "url": stix_url,
        "graph_name": graph_name})
    res = louvain(driver, graph_name)
    delete_GDS(driver, graph_name)

    return res



// delete all nodes
MATCH (n)
DETACH DELETE n;

//attack_pattern
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'attack-pattern'
MERGE (attackPattern:AttackPattern:NODE {
  type:         object.type,
  spec_version: object.spec_version,
  id:           object.id,
  created:      datetime(object.created),
  modified:     datetime(object.modified),
  name:         object.name,
  description:  object.description
})

FOREACH (reference IN object.external_references |
  MERGE (externalReference:ExternalReference:NODE {
    source_name: reference.source_name,
    description: reference.description,
    external_id: reference.external_id
  })
  MERGE (attackPattern)-[:HAS_EXTERNAL_REFERENCE{weight:1}]->(externalReference)
)
FOREACH (killChainPhase IN object.kill_chain_phases |
  MERGE (phase:KillChainPhase:NODE {
    kill_chain_name: killChainPhase.kill_chain_name,
    phase_name:      killChainPhase.phase_name
  })
  MERGE (attackPattern)-[:HAS_KILL_CHAIN_PHASE {weight:1}]->(phase)
);
//campaign
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'campaign'
CREATE (campaign:Campaign:NODE {
  id:           object.id,
  spec_version: object.spec_version,
  name:         object.name,
  description:  object.description,
  created:      object.created,
  modified:     object.modified,
  first_seen:   object.first_seen
});

//course-of-action
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object

// Create CourseOfAction nodes
WITH object
  WHERE object.type = 'course-of-action'
CREATE (coa:CourseOfAction:NODE)
SET coa.id = object.id,
coa.spec_version = object.spec_version,
coa.name = object.name,
coa.description = object.description,
coa.created = object.created,
coa.modified = object.modified,
coa.created_ref = object.created_by_ref

FOREACH (reference IN object.external_references |
  MERGE (externalReference:ExternalReference:NODE {
    source_name: reference.source_name,
    description: reference.description,
    url:         reference.url
  })
  MERGE (coa)-[:HAS_EXTERNAL_REFERENCE{weight:1}]->(externalReference)
)

RETURN coa;

// grouping
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'grouping'
CREATE (g:Grouping:NODE)
SET g = properties(object)
RETURN g;

//identity
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'identity'
CREATE (idt:Identity:NODE)
SET idt = properties(object)
RETURN idt;

//indicator
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'indicator'
CREATE (i:Indicator:NODE)
SET i = apoc.map.removeKey(properties(object), 'kill_chain_phases')
FOREACH (killChainPhase IN object.kill_chain_phases |
  MERGE (phase:KillChainPhase:NODE {
    kill_chain_name: killChainPhase.kill_chain_name,
    phase_name:      killChainPhase.phase_name
  })
  MERGE (i)-[:HAS_KILL_CHAIN_PHASE{weight:1}]->(phase)
)

RETURN i;

// infrastructure

WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'infrastructure'
CREATE (ifs:Infrastructure:NODE)
SET ifs = properties(object)
RETURN ifs;

// intrusion-set
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'intrusion-set'
CREATE (IS:IntrusionSet:NODE)
SET IS = properties(object)
RETURN IS;

// location
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'location'
CREATE (l:Location:NODE)
SET l = properties(object)
RETURN l;

//malware
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'malware'
CREATE (m:Malware:NODE)

SET m = apoc.map.removeKey(properties(object), 'kill_chain_phases')

FOREACH (killChainPhase IN object.kill_chain_phases |
  MERGE (phase:KillChainPhase:NODE {
    kill_chain_name: killChainPhase.kill_chain_name,
    phase_name:      killChainPhase.phase_name
  })
  MERGE (m)-[:HAS_KILL_CHAIN_PHASE {weight:1}]->(phase)
)

RETURN m;

// malware-analysis
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'malware-analysis'
CREATE (ma:MalwareAnalysis:NODE)
SET ma = properties(object)
RETURN ma;

// observed-data
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'observed-data'
CREATE (od:ObservedData:NODE)
SET od = properties(object)
RETURN od;


//report
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'report'
CREATE (r:Report:NODE)
SET r = properties(object)
RETURN r;

// sighting
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'sighting'
CREATE (s:Sighting:NODE)
SET s = properties(object)
RETURN s;
// threat-actor
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'threat-actor'
CREATE (ta:ThreatActor:NODE)
SET ta = properties(object)
RETURN ta;

// tool
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'tool'
CREATE (v:Tool:NODE)
SET v.id = object.id,
v.spec_version = object.spec_version,
v.name = object.name,
v.description = object.description,
v.created = object.created,
v.modified = object.modified,
v.tool_types = object.tool_types

FOREACH (killChainPhase IN object.kill_chain_phases |
  MERGE (phase:KillChainPhase:NODE {
    kill_chain_name: killChainPhase.kill_chain_name,
    phase_name:      killChainPhase.phase_name
  })
  MERGE (v)-[:HAS_KILL_CHAIN_PHASE{weight:1}]->(phase)
)

RETURN v;

//vulnerability
WITH $url
     AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'vulnerability'
CREATE (v:Vulnerability:NODE)
SET v.id = object.id,
v.spec_version = object.spec_version,
v.name = object.name,
v.description = object.description,
v.created = object.created,
v.modified = object.modified,
v.valid_from = object.valid_from

SET v.external_ids = [entry IN object.external_references | entry.external_id]

RETURN v;

//relationship
// graph naive
WITH $url AS url
CALL apoc.load.json(url) YIELD value AS data
UNWIND data.objects AS object
WITH object
  WHERE object.type = 'relationship'
WITH
  object.source_ref AS sourceRef, object.target_ref AS targetRef, toUpper(object.relationship_type) AS relationshipType
WITH sourceRef,targetRef,relationshipType,
CASE relationshipType
  WHEN 'INDICATES' THEN 10
  ELSE 100
END AS w
MATCH (source:NODE {id: sourceRef})
MATCH (target:NODE {id: targetRef})
CALL apoc.create.relationship(source, relationshipType, {weight: w}, target) YIELD rel AS r
RETURN r;

CALL db.relationshipTypes() YIELD relationshipType AS r
WITH r
WHERE NOT r = 'HAS_EXTERNAL_REFERENCE' AND NOT r = 'HAS_KILL_CHAIN_PHASE'
WITH collect(r) AS allRels
// collect all nodes, project the graph using those relationships
CALL gds.graph.project(
$graph_name,
'NODE',
{ALL: {orientation: 'UNDIRECTED', type: '*'}},
{relationshipProperties: ['weight']}
)
YIELD graphName
RETURN graphName;

// display
MATCH (n)
RETURN n;

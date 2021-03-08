import redis
import time
from redisgraph import Node, Edge, Graph, Path
from pymisp import PyMISP
from pymisp import MISPEvent
from keys import misp_url, misp_key

# TODO make these var config file settings
r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)

def getBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               RETURN b.ip, b.lastseen, b.hostname, b.user, b.architecture, b.fingerprint"""
    return redis_graph.query(query)

def getInfectedBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               WITH collect(DISTINCT b) as bb
               UNWIND bb as bot
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen"""
    return redis_graph.query(query)

def getBots():
    query = """MATCH (b:Bot)
               RETURN b.ip, b.lastseen"""
    return redis_graph.query(query)

def getBinaryCC(sha256):
    print(sha256)
    query = """MATCH (bin:Binary {{sha256: "{}"}})<-[h1:host]-(c1:CC)
               RETURN c1, bin""".format(sha256)
    return redis_graph.query(query)

def getBinarySiblings(sha256, depth):
    print(sha256)
    query = """MATCH (b1:Binary {{sha256: "{}"}})<-[:host]-(cc1:CC)-[:host]->(b2:Binary)
               WHERE b2.sha256 <> ""
               WITH b1, b2, collect(DISTINCT cc1) as commonCCs
               WHERE size(commonCCs) >= {} 
               RETURN b2, commonCCs""".format(sha256, depth)
    return redis_graph.query(query)

def getBinariesCCs():
    query = """MATCH (bin:Binary)<-[h1:host]-(c1:CC)
               RETURN c1, bin"""
    return redis_graph.query(query)

def misp_init(url, key):
        return PyMISP(url, key, False, 'json')


def create_misp_event_json():
        eventJson = {"Event": {"info": "Testouille Event",
                               "timestamp": "1",
                               "attribute_count": 0,
                               "analysis": "0",
                               "date": time.strftime("%Y-%m-%d"),
                               "org": "",
                               "distribution": "0",
                               "Attribute": [],
                               "proposal_email_lock": False,
                               "threat_level_id": "4",
                               }}

        return eventJson

def push_event_to_misp(jsonEvent):
        global misp
        _ = misp.add_event(jsonEvent)
        return

# Print resultset
# getBinaryCC("fc888339e8cf0ad37a20f56acc247e374cbe960aeafb541fc374776c68a467f1").pretty_print()
# getBinarySiblings("8dec3f18d8652bc68fbfcf516cb0bcabf259aaf61c65044d917bce9640be2db4", 10).pretty_print()

        # try connection
try:
    misp = misp_init(misp_url, misp_key)
except:
    print("/!\ Connection fail, bad url ({0}) or API key : {1}".format(misp_url, misp_key))

jsonEvent = create_misp_event_json()
push_event_to_misp(jsonEvent)

getInfectedBots().pretty_print()
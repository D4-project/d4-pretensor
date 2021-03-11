import redis
import os
import time
from datetime import datetime
from redisgraph import Node, Edge, Graph, Path
from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp import MISPObject
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import make_binary_objects
from keys import misp_url, misp_key, infected_path, infected_bash_path
import pdb

# TODO make these var config file settings
r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)

def setCCuuid(redisid, uuid):
    query = """MATCH (c:CC)
               WHERE id(c) = {}
               SET c.uuid = "{}" """.format(redisid, uuid)
    return redis_graph.query(query)

def setBotuuid(redisid, uuid):
    query = """MATCH (b:Bot)
               WHERE id(b) = {}
               SET b.uuid = "{}" """.format(redisid, uuid)
    return redis_graph.query(query)

def setBinaryuuid(redisid, uuid):
    query = """MATCH (b:Binary)
               WHERE id(b) = {}
               SET b.uuid = "{}" """.format(redisid, uuid)
    return redis_graph.query(query)

def getBots():
    query = """MATCH (bot:Bot)
               WHERE NOT EXISTS(bot.uuid) 
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen, bot.arch, ID(bot)"""
    return redis_graph.query(query)

def getCCs():
    query = """MATCH (c:CC)
               WHERE NOT EXISTS(c.uuid) 
               RETURN c.host, ID(c)"""
    return redis_graph.query(query)

def getBinaries():
    query = """MATCH (b:Binary)
               WHERE NOT EXISTS(b.uuid) 
               RETURN b.sha256, b.binname, b.size, ID(b)"""
    return redis_graph.query(query)

def getExcutingBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               RETURN b.ip, b.lastseen, b.hostname, b.user, b.architecture, b.fingerprint"""
    return redis_graph.query(query)

def getCCBots(hostuuid):
    query = """MATCH (bot:Bot)-[:reach]-(c:CC {{uuid:"{}"}})
               RETURN bot.uuid""".format(hostuuid)
    return redis_graph.query(query)

def getCCBinaries(host):
    query = """MATCH (b:Binary)-[:host]-(c:CC {{host:"{}"}})
               RETURN b.sha256, b.binname, b.size""".format(host)
    return redis_graph.query(query)

def getCCDLBots(host):
    query = """MATCH (b:Bot)-[:download]->(:Binary)<-[:host]-(c:CC {{host: "{}"}})
               WITH collect(DISTINCT b) as bb
               UNWIND bb as bot
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen""".format(host)
    return redis_graph.query(query)

def getCCInfectedBots(host):
    query = """MATCH (b:Bot)-[:execute]->(:Command)<-[:launch]-(c:CC {{host: "{}"}})
               WITH collect(DISTINCT b) as bb
               UNWIND bb as bot
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen""".format(host)
    return redis_graph.query(query)

def getBinaryCC(sha256):
    query = """MATCH (bin:Binary {{sha256: "{}"}})<-[h1:host]-(c1:CC)
               RETURN c1, bin""".format(sha256)
    return redis_graph.query(query)

def getBinarySiblings(sha256, depth):
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


def create_misp_event():
    event = MISPEvent()
    event.info = "Correct way of doing this testouille event"
    event.analysis = 0
    event.date = time.strftime("%Y-%m-%d")

    return event

def push_event_to_misp(event):
        global misp
        _ = misp.add_event(event)
        return

# Print resultset
# getBinaryCC("fc888339e8cf0ad37a20f56acc247e374cbe960aeafb541fc374776c68a467f1").pretty_print()
# getBinarySiblings("8dec3f18d8652bc68fbfcf516cb0bcabf259aaf61c65044d917bce9640be2db4", 10).pretty_print()

try:
    misp = misp_init(misp_url, misp_key)
except:
    print("/!\ Connection fail, bad url ({0}) or API key : {1}".format(misp_url, misp_key))

# event = create_misp_event()
event = misp.get_event("cae82159-5607-4cc1-b917-39d22698ac39", pythonify=True)

# Add CCs
ccs = getCCs()
for record in ccs.result_set:
    torhs_object = MISPObject('tor-hiddenservice', standalone=False)
    torhs_object.add_attribute('address', value=record[0])
    mycc = event.add_object(torhs_object, break_on_duplicate=True)
    print(mycc.uuid)
    setCCuuid(record[1], mycc.uuid)

# Add binaries
bins = getBinaries()
for bin in bins.result_set:
    if len(bin[0]) > 0:
        # it's a binary
        if os.path.exists(os.path.join(infected_path, bin[0])):
            file_obj, bin_obj, sections = make_binary_objects(os.path.join(infected_path, bin[0]), standalone=False)
            mybin = event.add_object(file_obj, break_on_duplicate=True)
            setBinaryuuid(bin[3], mybin.uuid)
            if bin_obj:
                event.add_object(bin_obj, break_on_duplicate=True)
                for s in sections:
                    event.add_object(s, break_on_duplicate=True)
        # it's a bash file
        elif os.path.exists(os.path.join(infected_bash_path, bin[0])):
            shellcmd_object = MISPObject('shell-commands', standalone=False)
            shellcmd_object.add_attribute('language', value="Bash")
            with open(os.path.join(infected_bash_path, bin[0]), 'r') as reader:
                shellcmd_object.add_attribute('script', value=reader.read())
            mybash = event.add_object(shellcmd_object, break_on_duplicate=True)
            setBinaryuuid(bin[3], mybash.uuid)

# Add Bots
bots = getBots()
for bot in bots.result_set:
    record_datetime = datetime.strptime(bot[3], '%d/%b/%Y:%H:%M:%S %z')
    attributeAsDict = [{'node-ip': {'value': bot[0], 'type': 'ip-dst'}},
                       {'node-user': {'value': bot[1], 'type': 'text'}},
                       {'node-hostname': {'value': bot[2], 'type': 'text'}},
                       {'first-seen': {'value': record_datetime, 'type': 'datetime'}},
                       {'node-arch': {'value': bot[4], 'type': 'text'}}]
    misp_object = GenericObjectGenerator('botnet-node')
    misp_object.generate_attributes(attributeAsDict)
    mybot = event.add_object(misp_object, break_on_duplicate=True)
    setBotuuid(bot[5], mybot.uuid)

# Create Relationships
for obj in event.objects:
    if obj.name == 'tor-hiddenservice':
        ccbots = getCCBots(obj.uuid)
        for bot in ccbots.result_set:
            mispbot = event.get_object_by_uuid(bot[0])
            mispbot.add_reference(obj.uuid, "reach")
            misp.update_object(mispbot)

# push_event_to_misp(event)
_ = misp.update_event(event)
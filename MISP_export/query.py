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

def getBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               RETURN b.ip, b.lastseen, b.hostname, b.user, b.architecture, b.fingerprint"""
    return redis_graph.query(query)

def getCCs():
    query = """MATCH (c:CC)
               RETURN c.host"""
    return redis_graph.query(query)

def getCCBots(host):
    query = """MATCH (bot:Bot)-[:reach]-(c:CC {{host:"{}"}})
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen, bot.arch""".format(host)
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

event = create_misp_event()
# getBots().pretty_print()

ccs = getCCs()
for record in ccs.result_set:
    torhs_object = MISPObject('tor-hiddenservice', standalone=False)
    torhs_object.add_attribute('address', value=record[0])
    event.add_object(torhs_object)
    record_bin = getCCBinaries(record[0])
    # Add binaries
    for bin in record_bin.result_set:
        # it's a binary
        if os.path.exists(os.path.join(infected_path, bin[0])):
            file_obj, bin_obj, sections = make_binary_objects(os.path.join(infected_path, bin[0]), standalone=False)
            event.add_object(file_obj)
            if bin_obj:
                event.add_object(bin_obj)
                for s in sections:
                    event.add_object(s)
            # Create reference
            torhs_object.add_reference(file_obj.uuid, "host")
        # it's a bash file
        elif os.path.exists(os.path.join(infected_bash_path, bin[0])):
            shellcmd_object = MISPObject('shell-commands', standalone=False)
            shellcmd_object.add_attribute('language', value="Bash")
            with open(os.path.join(infected_bash_path, bin[0]), 'r') as reader:
                shellcmd_object.add_attribute('script', value=reader.read())
            event.add_object(shellcmd_object)
            # Create reference
            torhs_object.add_reference(shellcmd_object.uuid, "host")
    # Add Bots
    record_bots = getCCBots(record[0])
    for bot in record_bots.result_set:
        record_datetime = datetime.strptime(bot[3], '%d/%b/%Y:%H:%M:%S %z')
        attributeAsDict = [{'node-ip': {'value': bot[0], 'type': 'ip-dst'}},
                           {'node-user': {'value': bot[1], 'type': 'text'}},
                           {'node-hostname': {'value': bot[2], 'type': 'text'}},
                           {'first-seen': {'value': record_datetime, 'type': 'datetime'}},
                           {'node-arch': {'value': bot[4], 'type': 'text'}}]
        misp_object = GenericObjectGenerator('botnet-node')
        misp_object.generate_attributes(attributeAsDict)
        misp_object.add_reference(torhs_object.uuid, "reach")
        event.add_object(misp_object)

push_event_to_misp(event)
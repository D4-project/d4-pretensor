import redis
import os
import time
from datetime import datetime, timedelta, date
from redisgraph import Node, Edge, Graph, Path
from redisearch import Client
from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp import MISPObject
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import make_binary_objects
from keys import misp_url, misp_key, infected_path, infected_bash_path, misp_event_uuid
import pdb

# TODO make these var config file settings
r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)

# Setter for MISP uuid in redisgraph
def setCCuuid(redisid, uuid, muuid):
    query = """MATCH (c:CC)
               WHERE id(c) = {}
               SET c.uuid = "{}"
               SET c.misp_uuid = "{}" """.format(redisid, uuid, muuid)
    return redis_graph.query(query)

def setBotuuid(redisid, uuid, muuid):
    query = """MATCH (b:Bot)
               WHERE id(b) = {}
               SET b.uuid = "{}" 
               SET b.misp_uuid = "{}" """.format(redisid, uuid, muuid)
    return redis_graph.query(query)

def setBinaryuuid(redisid, uuid):
    query = """MATCH (b:Binary)
               WHERE id(b) = {}
               SET b.uuid = "{}" """.format(redisid, uuid)
    return redis_graph.query(query)

# Getter for populating the MISP event with new nodes
def getBots():
    query = """MATCH (bot:Bot)
               WHERE NOT EXISTS(bot.uuid) 
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen, bot.arch, ID(bot)"""
    return redis_graph.query(query)


# Getter for populating the MISP event with new nodes
def getBotsForDate(date):
    query = """CALL db.idx.fulltext.queryNodes('Bot', '"{}"') YIELD node as bot
               WHERE NOT EXISTS(bot.uuid) 
               RETURN bot.ip, bot.user, bot.hostname, bot.firstseen, bot.lastseen, bot.arch, ID(bot)""".format(date)
    print(query)
    return redis_graph.query(query)

def getCCs():
    query = """MATCH (c:CC)
               WHERE NOT EXISTS(c.uuid) 
               RETURN c.host, c.firstseen, c.lastseen, ID(c)"""
    return redis_graph.query(query)

def getCCsForDate(date):
    query = """CALL db.idx.fulltext.queryNodes('CC', '"{}"') YIELD node as cc
               WHERE NOT EXISTS(cc.uuid) 
               RETURN cc.host, cc.firstseen, cc.lastseen, ID(cc)""".format(date)
    return redis_graph.query(query)

def getBinaries():
    query = """MATCH (b:Binary)
               WHERE NOT EXISTS(b.uuid) 
               RETURN b.sha256, b.binname, b.size, ID(b)"""
    return redis_graph.query(query)

# Getter for building relationships
def getCCBots(hostuuid):
    query = """MATCH (bot:Bot)-[:reach]-(c:CC {{uuid:"{}"}})
               RETURN bot.uuid, bot.misp_uuid""".format(hostuuid)
    return redis_graph.query(query)

def getBotCCs(rid):
    query = """MATCH (bot:Bot)-[:reach]->(c:CC)
               WHERE id(bot) = {}
               RETURN c.uuid""".format(rid)
    print(query)
    return redis_graph.query(query)

def getBinaryCC(uuid):
    query = """MATCH (bin:Binary {{uuid: "{}"}})<-[h1:host]-(c1:CC)
               RETURN c1.uuid""".format(uuid)
    return redis_graph.query(query)

def getBinaryBots(uuid):
    query = """MATCH (bin:Binary {{uuid: "{}"}})<-[h1:downloas]-(b:Bot)
               RETURN b.uuid""".format(uuid)
    return redis_graph.query(query)

# Parking of queries to build MISP reports
def getExcutingBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               RETURN b.ip, b.lastseen, b.hostname, b.user, b.architecture, b.fingerprint"""
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

def getBinarySiblings(sha256, depth):
    query = """MATCH (b1:Binary {{sha256: "{}"}})<-[:host]-(cc1:CC)-[:host]->(b2:Binary)
               WHERE b2.sha256 <> ""
               WITH b1, b2, collect(DISTINCT cc1) as commonCCs
               WHERE size(commonCCs) >= {} 
               RETURN b2, commonCCs""".format(sha256, depth)
    return redis_graph.query(query)

def misp_init(url, key):
        return PyMISP(url, key, ssl=False, debug=False)

def create_misp_event(date):
    event = MISPEvent()
    event.info = "PGMiner event update"
    event.tag = "tlp:green"
    event.tag = "D4-onion-peeling"
    event.analysis = 0
    event.date = date

    return event

try:
    misp = misp_init(misp_url, misp_key)
except:
    print("/!\ Connection fail, bad url ({0}) or API key : {1}".format(misp_url, misp_key))

supportEvent = misp.get_event(misp_event_uuid, extended=True, pythonify=True)

# C2 and binary are located in the support event to add references to

# Add CCs
ccs = getCCs()
for record in ccs.result_set:
    torhs_object = MISPObject('tor-hiddenservice', standalone=False)
    torhs_object.add_attribute('address', value=record[0])
    torhs_object.add_attribute('first-seen', value=datetime.strptime(record[1], "%d/%b/%Y:%H:%M:%S %z"))
    torhs_object.add_attribute('last-seen', value=datetime.strptime(record[2], "%d/%b/%Y:%H:%M:%S %z"))
    mycc = supportEvent.add_object(torhs_object, break_on_duplicate=True)
    setCCuuid(record[3], mycc.uuid, supportEvent.uuid)

# Add binaries
bins = getBinaries()
for bin in bins.result_set:
    if len(bin[0]) > 0:
        # it's a binary
        if os.path.exists(os.path.join(infected_path, bin[0])):
            file_obj, bin_obj, sections = make_binary_objects(os.path.join(infected_path, bin[0]), standalone=False, filename=bin[1])
            mybin = supportEvent.add_object(file_obj, break_on_duplicate=True)
            setBinaryuuid(bin[3], mybin.uuid)
            if bin_obj:
                supportEvent.add_object(bin_obj, break_on_duplicate=True)
                for s in sections:
                    supportEvent.add_object(s, break_on_duplicate=True)
        # it's a bash file
        elif os.path.exists(os.path.join(infected_bash_path, bin[0])):
            shellcmd_object = MISPObject('shell-commands', standalone=False)
            shellcmd_object.add_attribute('language', value="Bash")
            print(bin[0])
            try:
                with open(os.path.join(infected_bash_path, bin[0]), 'r') as reader:
                    shellcmd_object.add_attribute('script', value=reader.read())
                    mybash = supportEvent.add_object(shellcmd_object, break_on_duplicate=True)
                    setBinaryuuid(bin[3], mybash.uuid)
                    # sonovabitch is actually a binary
            except UnicodeDecodeError:
                file_obj, bin_obj, sections = make_binary_objects(os.path.join(infected_bash_path, bin[0]), standalone=False,
                                                                  filename=bin[1])
                mybin = supportEvent.add_object(file_obj, break_on_duplicate=True)
                setBinaryuuid(bin[3], mybin.uuid)
                if bin_obj:
                    supportEvent.add_object(bin_obj, break_on_duplicate=True)
                    for s in sections:
                        supportEvent.add_object(s, break_on_duplicate=True)

# Create relationships in the support event
# for obj in supportEvent.objects:
#     if (obj.name == 'shell-commands') or (obj.name == 'file'):
#         bincc = getBinaryCC(obj.uuid)
#         for cc in bincc.result_set:
#             obj.add_reference(cc[0], "is_hosted_by")

# Update the support event
supportEvent = misp.update_event(supportEvent, pythonify=True)

# Create extended daily events for bots
sdate = date(2020, 10, 20)   # start date
# edate = date(2021, 4, 6)   # end date
edate = date(2020, 10, 21)   # end date
delta = edate - sdate       # as timedelta

for i in range(delta.days + 1):
    day = sdate + timedelta(days=i)
    strdate = datetime.strftime(day, format="%d/%b/%Y")

    # Extends Support Event
    event = create_misp_event(day)
    event = misp.add_event(event, pythonify=True)
    event = misp.update_event({'extends_uuid': misp_event_uuid}, event_id=event.uuid, pythonify=True)

    # Add Bots
    bots = getBotsForDate(strdate)
    print("Date: {}, Nb Bots: {}".format(strdate, len(bots.result_set)))
    for bot in bots.result_set:
        print(bot)
        record_datetimefs = datetime.strptime(bot[3], '%d/%b/%Y:%H:%M:%S %z')
        record_datetimels = datetime.strptime(bot[4], '%d/%b/%Y:%H:%M:%S %z')
        attributeAsDict = [{'node-ip': {'value': bot[0], 'type': 'ip-dst'}},
                           {'node-user': {'value': bot[1], 'type': 'text', 'to_ids': False, 'disable_correlation': True}},
                           {'node-hostname': {'value': bot[2], 'type': 'text', 'disable_correlation': True}},
                           {'first-seen': {'value': record_datetimefs, 'type': 'datetime', 'to_ids': False, 'disable_correlation': True}},
                           {'last-seen': {'value': record_datetimels, 'type': 'datetime', 'to_ids': False, 'disable_correlation': True}},
                           {'node-arch': {'value': bot[5], 'type': 'text', 'to_ids': False, 'disable_correlation': True}}]
        misp_object = GenericObjectGenerator('botnet-node')
        misp_object.generate_attributes(attributeAsDict)
        # Check which CC the bot reached
        # botcc = getBotCCs(bot[6])
        # for cc in botcc.result_set:
        #     c2 = supportEvent.get_object_by_uuid(cc[0])
        #     test = misp_object.add_reference(c2, "reaches")
        mybot = event.add_object(misp_object, break_on_duplicate=True)
        setBotuuid(bot[6], mybot.uuid, event.uuid)

    _ = misp.update_event(event, pythonify=True)

# Create relationships to the daily event
for obj in supportEvent.objects:
    if obj.name == 'tor-hiddenservice':
        ccbots = getCCBots(obj.uuid)
        for bot in ccbots.result_set:
            obj.add_reference(bot[0], "is_reached_by")
supportEvent = misp.update_event(supportEvent, pythonify=True)


    # Create relationship in the daily event from the support event
    # for obj in supportEvent.objects:
    #     if obj.name == 'tor-hiddenservice':
    #         ccbots = getCCBots(obj.uuid)
    #         for bot in ccbots.result_set:
    #             mispbot = event.get_object_by_uuid(bot[0])
    #             mispbot.add_reference(obj.uuid, "reach")
    #             misp.update_object(mispbot)
    #             dailyEvent = misp.update_event(bot[1], pythonify=True)

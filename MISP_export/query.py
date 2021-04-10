import redis
import os
import time
from datetime import datetime, timedelta, date
from redisgraph import Node, Edge, Graph, Path
from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp import MISPObject
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import make_binary_objects
from lib import setCCuuid, getCCs, getBinaries, setBinaryuuid, setBotuuid, getBotsForDate, getCCBots, getBinaryCC, getBotCCs, getBots
from keys import misp_url, misp_key, infected_path, infected_bash_path, misp_event_uuid, event_name

r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)

def misp_init(url, key):
        return PyMISP(url, key, ssl=False, debug=False)

def create_misp_event(date):
    event = MISPEvent()
    event.info = event_name
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

# C2 and binary are located in the support event
# Add CCs
ccs = redis_graph.query(getCCs())
for record in ccs.result_set:
    torhs_object = MISPObject('tor-hiddenservice', standalone=False)
    torhs_object.add_attribute('address', value=record[0])
    torhs_object.add_attribute('first-seen', value=datetime.strptime(record[1], "%d/%b/%Y:%H:%M:%S %z"))
    torhs_object.add_attribute('last-seen', value=datetime.strptime(record[2], "%d/%b/%Y:%H:%M:%S %z"))
    mycc = supportEvent.add_object(torhs_object, break_on_duplicate=True)
    setCCuuid(record[3], mycc.uuid, supportEvent.uuid)

# Add binaries
bins = redis_graph.query(getBinaries())
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
for obj in supportEvent.objects:
    if (obj.name == 'shell-commands') or (obj.name == 'file'):
        bincc = redis_graph.query(getBinaryCC(obj.uuid))
        for cc in bincc.result_set:
            obj.add_reference(cc[0], "is_hosted_by")

# Update the support event
supportEvent = misp.update_event(supportEvent, pythonify=True)

# Extends Support Event
event = create_misp_event(time.strftime("%Y-%m-%d"))
event = misp.add_event(event, pythonify=True)
event = misp.update_event({'extends_uuid': misp_event_uuid}, event_id=event.uuid, pythonify=True)

# Add Bots
bots = redis_graph.query(getBots())
for bot in bots.result_set:
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
    # Adds relationshipt to the CC which the bot reached
    botcc = redis_graph.query(getBotCCs(bot[6]))
    for cc in botcc.result_set:
        misp_object.add_reference(cc[0], "reaches")
    mybot = event.add_object(misp_object, break_on_duplicate=True)
    setBotuuid(bot[6], mybot.uuid, event.uuid)

_ = misp.update_event(event, pythonify=True)
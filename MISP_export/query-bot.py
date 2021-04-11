import redis
from datetime import datetime, timedelta, date
from redisgraph import Graph
from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp.tools import GenericObjectGenerator
from lib import setBotuuid, getBotsForDate, getBotCCs
from keys import misp_url, misp_key, misp_event_uuid, event_name

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

# Extends Support Event
yesterday = date.today() - timedelta(days=1)
event = create_misp_event(yesterday.strftime("%Y-%m-%d"))
event = misp.add_event(event, pythonify=True)
event = misp.update_event({'extends_uuid': misp_event_uuid}, event_id=event.uuid, pythonify=True)

# Add Bots
bots = redis_graph.query(getBotsForDate(yesterday.strftime(format="%d/%b/%Y")))
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
    redis_graph.query(setBotuuid(bot[6], mybot.uuid, event.uuid))

_ = misp.update_event(event, pythonify=True)
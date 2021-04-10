# Setter for MISP uuid in redisgraph
def setCCuuid(redisid, uuid, muuid):
    query = """MATCH (c:CC)
               WHERE id(c) = {}
               SET c.uuid = "{}"
               SET c.misp_uuid = "{}" """.format(redisid, uuid, muuid)
    return query

def setBotuuid(redisid, uuid, muuid):
    query = """MATCH (b:Bot)
               WHERE id(b) = {}
               SET b.uuid = "{}" 
               SET b.misp_uuid = "{}" """.format(redisid, uuid, muuid)
    return query

def setBinaryuuid(redisid, uuid):
    query = """MATCH (b:Binary)
               WHERE id(b) = {}
               SET b.uuid = "{}" """.format(redisid, uuid)
    return query

# Getter for populating the MISP event with new nodes
def getBots():
    query = """MATCH (bot:Bot)
               WHERE NOT EXISTS(bot.uuid) 
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen, bot.arch, ID(bot)"""
    return query


# Getter for populating the MISP event with new nodes
def getBotsForDate(date):
    query = """CALL db.idx.fulltext.queryNodes('Bot', '"{}"') YIELD node as bot
               WHERE NOT EXISTS(bot.uuid) 
               RETURN bot.ip, bot.user, bot.hostname, bot.firstseen, bot.lastseen, bot.arch, ID(bot)""".format(date)
    return query

def getCCs():
    query = """MATCH (c:CC)
               WHERE NOT EXISTS(c.uuid) 
               RETURN c.host, c.firstseen, c.lastseen, ID(c)"""
    return query

def getCCsForDate(date):
    query = """CALL db.idx.fulltext.queryNodes('CC', '"{}"') YIELD node as cc
               WHERE NOT EXISTS(cc.uuid) 
               RETURN cc.host, cc.firstseen, cc.lastseen, ID(cc)""".format(date)
    return query

def getBinaries():
    query = """MATCH (b:Binary)
               WHERE NOT EXISTS(b.uuid) 
               RETURN b.sha256, b.binname, b.size, ID(b)"""
    return query

# Getter for building relationships
def getCCBots(hostuuid):
    query = """MATCH (bot:Bot)-[:reach]-(c:CC {{uuid:"{}"}})
               RETURN bot.uuid, bot.misp_uuid""".format(hostuuid)
    return query

def getBotCCs(rid):
    query = """MATCH (bot:Bot)-[:reach]->(c:CC)
               WHERE id(bot) = {}
               RETURN c.uuid""".format(rid)
    return query

def getBinaryCC(uuid):
    query = """MATCH (bin:Binary {{uuid: "{}"}})<-[h1:host]-(c1:CC)
               RETURN c1.uuid""".format(uuid)
    return query

def getBinaryBots(uuid):
    query = """MATCH (bin:Binary {{uuid: "{}"}})<-[h1:downloas]-(b:Bot)
               RETURN b.uuid""".format(uuid)
    return query

# Parking of queries to build MISP reports
def getExcutingBots():
    query = """MATCH (b:Bot)-[:execute]->(:Command)
               RETURN b.ip, b.lastseen, b.hostname, b.user, b.architecture, b.fingerprint"""
    return query

def getCCDLBots(host):
    query = """MATCH (b:Bot)-[:download]->(:Binary)<-[:host]-(c:CC {{host: "{}"}})
               WITH collect(DISTINCT b) as bb
               UNWIND bb as bot
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen""".format(host)
    return query

def getCCInfectedBots(host):
    query = """MATCH (b:Bot)-[:execute]->(:Command)<-[:launch]-(c:CC {{host: "{}"}})
               WITH collect(DISTINCT b) as bb
               UNWIND bb as bot
               RETURN bot.ip, bot.user, bot.hostname, bot.lastseen""".format(host)
    return query

def getBinarySiblings(sha256, depth):
    query = """MATCH (b1:Binary {{sha256: "{}"}})<-[:host]-(cc1:CC)-[:host]->(b2:Binary)
               WHERE b2.sha256 <> ""
               WITH b1, b2, collect(DISTINCT cc1) as commonCCs
               WHERE size(commonCCs) >= {} 
               RETURN b2, commonCCs""".format(sha256, depth)
    return query
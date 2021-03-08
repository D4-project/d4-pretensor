import redis
from redisgraph import Node, Edge, Graph, Path

# TODO make these var config file settings
r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)



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

# Print resultset
# getBinaryCC("fc888339e8cf0ad37a20f56acc247e374cbe960aeafb541fc374776c68a467f1").pretty_print()
getBinarySiblings("8dec3f18d8652bc68fbfcf516cb0bcabf259aaf61c65044d917bce9640be2db4", 10).pretty_print()
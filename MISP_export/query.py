import redis
from redisgraph import Node, Edge, Graph, Path

# TODO make these var config file settings
r = redis.Redis(host='localhost', port=6502)
redis_graph = Graph('pretensor', r)



def getBinaryCC(sha256):
    print(sha256)
    query = """MATCH (bin:Binary {{sha256: "{}"}})<-[h1:host]-(c1:CC)
               RETURN c1""".format(sha256)
    return redis_graph.query(query)

# Print resultset
getBinaryCC("7e9002d8a7bc8364f291e8774c3bfd794ba496cdf0e2823513247d87d582382a").pretty_print()
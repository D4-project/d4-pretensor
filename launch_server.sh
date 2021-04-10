#!/bin/bash
#screen -X -S pewpew quit

go fmt
go build

rm pretensor.log

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#CONF="conf.sample"

screen -dmS "pretensor"
sleep 0.1

screen -S "pretensor" -X screen -t "pew-redis" bash -c "(${DIR}/redis/src/redis-server ${DIR}/redis.conf); read x;"
#screen -S "pretensor" -X screen -t "redis-insight" bash -c "(${DIR}/redisinsight-linux64-1.10.0); read x;"

sleep 0.5

redis-cli -h localhost -p 6502 -n 0 GRAPH.QUERY pretensor "CALL db.idx.fulltext.createNodeIndex('Bot', 'firstseen')"
redis-cli -h localhost -p 6502 -n 0 GRAPH.QUERY pretensor "CALL db.idx.fulltext.createNodeIndex('Bot', 'hostname')"
redis-cli -h localhost -p 6502 -n 0 GRAPH.QUERY pretensor "CALL db.idx.fulltext.createNodeIndex('CC', 'firstseen')"

exit 0

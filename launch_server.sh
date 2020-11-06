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

sleep 0.5

exit 0

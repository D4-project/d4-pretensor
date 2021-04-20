# d4-pretensor
`d4-pretensor` is a tool used support the monitor of http <> tor gateways. 
Here are its main current features:

- analyze logs modsecurity log files from a folder, or straight from D4
- re-download binary files downloaded by clients
- build a property graph in redisgraph
- export bots / binaries and C2 to MISP.

# Installation
- launch `install_server.sh`
- create a symlink in project's root to your redisgraph.so file
`ln -s  /home/jlouis/Git/RedisGraph/src/redisgraph.so redisgraph.so`

- create a symlink in project's root to your redisearch.so file
`ln -s  /home/jlouis/Git/RedisGraph/src/redisearch.so redisearch.so`

# Setup
Create the following files in a foder of your choice:
- redis-pretensor: a text file containing the address of the redis server (by default 127.0.0.1:6502/pretensor)
- logs: text file containing the name of the folder to monitor
- mitm: text file containing a list (\n separated) of domain used for the collection. For instance .foobar if your collecting domain is onion.foobar
- tomonitor: text file containing a list of (\n separated) requests to analyze (for instance /miner)
- redis_d4: text file containing D4's redis address if used (for instance localhost:6380/2)
- redis_d4_queue: text file containing the D4 redis queue to lpop (for instance nalyzer:filewatcher:d9b632f9-d671-43a5-9846-6772aeb6445a)


# Launch
- `launch_server.sh` to launch the redis server
- ./d4-pretensor -c conf.sample

```
./d4-pretensor -h
d4 - d4-pretensor
Parses Mod Security logs into Redis Graph 
from a folder first to bootstrap a redis graph, 
and then from d4 to update it. 

Usage: d4-pretensor -c config_directory

Configuration

The configuration settings are stored in files in the configuration directory
specified with the -c command line switch.

Files in the configuration directory:

redis_pretensor - host:port/graphname
redis_d4 - host:port/db
redis_d4_queue - d4 queue to pop
folder - folder containing mod security logs
tomonitor - list of requests to monitor (botnet activity)
mitm - list of mitm proxy to remove

  -D	Delete previous graph
  -c string
    	configuration directory (default "conf.sample")
  -d	debug output
  -log_folder string
    	folder containing mod security logs (default "logs")
  -r	Connect to redis - d4 to get new files
  -rl duration
    	Rate limiter: time in human format before retry after EOF (default 5s)
  -v	additional debug output
``` 

# TODO
- Drop modsecurity for something smarter (suricata)

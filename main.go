package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/D4-project/d4-pretensor/pretensorhit"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	config "github.com/D4-project/d4-golang-utils/config"
	"github.com/gomodule/redigo/redis"
	rg "github.com/redislabs/redisgraph-go"
	gj "github.com/tidwall/gjson"
)

type (
	// Input is a grok - NIFI or Logstash
	redisconfD4 struct {
		redisHost  string
		redisPort  string
		redisGraph string
	}
)

// Setting up Flags and other Vars
var (
	confdir        = flag.String("c", "conf.sample", "configuration directory")
	folder         = flag.String("log_folder", "logs", "folder containing mod security logs")
	buf            bytes.Buffer
	logger         = log.New(&buf, "INFO: ", log.Lshortfile)
	redisConn      redis.Conn
	redisInputPool *redis.Pool
	tomonitor      [][]byte
	mitm           [][]byte
)

func main() {
	// Setting up log file
	f, err := os.OpenFile("pretensor.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}

	defer f.Close()
	logger.SetOutput(f)
	logger.SetFlags(log.LstdFlags | log.Lshortfile)
	logger.Println("Init")

	// Setting up Graceful killing
	sortie := make(chan os.Signal, 1)
	signal.Notify(sortie, os.Interrupt, os.Kill)
	// Signal goroutine
	go func() {
		<-sortie
		logger.Println("Exiting")
		os.Exit(0)
	}()

	// Usage
	flag.Usage = func() {
		fmt.Printf("d4 - d4-pretensor\n")
		fmt.Printf("Parses Mod Security logs into Redis Graph \n")
		fmt.Printf("\n")
		fmt.Printf("Usage: d4-pretensor -c config_directory\n")
		fmt.Printf("\n")
		fmt.Printf("Configuration\n\n")
		fmt.Printf("The configuration settings are stored in files in the configuration directory\n")
		fmt.Printf("specified with the -c command line switch.\n\n")
		fmt.Printf("Files in the configuration directory\n")
		fmt.Printf("\n")
		fmt.Printf("redis_server - host:port/graphname\n")
		fmt.Printf("folder - folder containing mod security logs\n")
		fmt.Printf("tomonitor - list of requests to monitor (botnet activity)\n")
		fmt.Printf("mitm - list of mitm proxy to remove\n")
		fmt.Printf("\n")
		flag.PrintDefaults()
	}

	// Parse Flags
	flag.Parse()
	if flag.NFlag() == 0 || *confdir == "" {
		flag.Usage()
		sortie <- os.Kill
	} else {
		*confdir = strings.TrimSuffix(*confdir, "/")
		*confdir = strings.TrimSuffix(*confdir, "\\")
	}

	rd4 := redisconfD4{}
	// Parse Input Redis Config
	tmp := config.ReadConfigFile(*confdir, "redis_server")
	ss := strings.Split(string(tmp), "/")
	if len(ss) <= 1 {
		log.Fatal("Missing Database in Redis input config: should be host:port/database_name")
	}
	rd4.redisGraph = ss[1]
	var ret bool
	ret, ss[0] = config.IsNet(ss[0])
	if ret {
		sss := strings.Split(string(ss[0]), ":")
		rd4.redisHost = sss[0]
		rd4.redisPort = sss[1]
	} else {
		logger.Fatal("Redis config error.")
	}

	// Checking that the log folder exists
	log_folder := string(config.ReadConfigFile(*confdir, "folder"))
	_, err = ioutil.ReadDir(log_folder)
	if err != nil {
		logger.Fatal(err)
	}

	// Loading Requests to monitor
	tomonitor = config.ReadConfigFileLines(*confdir, "tomonitor")
	// Loading proxy list to remove from Hosts
	mitm = config.ReadConfigFileLines(*confdir, "mitm")

	// Create a new redis connection pool
	redisInputPool = newPool(rd4.redisHost+":"+rd4.redisPort, 16)
	redisConn, err = redisInputPool.Dial()
	if err != nil {
		logger.Fatal("Could not connect to d4 Redis")
	}

	// Init redis graph
	graph := rg.GraphNew("pretensor", redisConn)
	graph.Delete()

	// Walking folder
	err = filepath.Walk(log_folder,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			logger.Println(info.Name(), info.Size())
			if !info.IsDir() {
				content, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				// Load JSON
				contents := string(content)
				if !gj.Valid(contents) {
					return errors.New("Invalid json: " + path)
				}
				// For each request to monitor
				for _, v := range tomonitor {
					request := gj.Get(contents, "request.request_line")
					if strings.Contains(request.String(), string(v)) {
						// We are in a file of interest
						tmp := new(pretensorhit.PHit)
						tmp.SetTimestamp(gj.Get(contents, "transaction.time"))
						tmp.SetIp(gj.Get(contents, "transaction.remote_address"))
						tmp.SetLine(gj.Get(contents, "request.request_line"))
						tmp.SetUseragent(gj.Get(contents, "request.headers.User-Agent"))
						tmp.SetStatus(gj.Get(contents, "response.status"))
						tmp.SetBody(gj.Get(contents, "response.body"))
						tmp.SetContenttype(gj.Get(contents, "response.headers.Content-Type"))
						tmp.SetLength(gj.Get(contents, "response.headers.Content-Length"))
						tmp.SetHost(removeMitm(gj.Get(contents, "request.headers.Host")))

						// Complete the graph
						// Create bot if not exist
						query := `MATCH (b:Bot {ip:"` + tmp.GetIp() + `"}) RETURN b.ip`
						result, err := graph.Query(query)
						if err != nil {
							fmt.Println(err)
						}
						if result.Empty() {
							graph.AddNode(tmp.GetBotNode())
							_, err := graph.Flush()
							if err != nil {
								fmt.Println(err)
							}
						}

						// Create CC if not exist
						query = `MATCH (c:CC {host:"` + tmp.GetHost() + `"}) RETURN c.host`
						result, err = graph.Query(query)
						if err != nil {
							fmt.Println(err)
						}
						if result.Empty() {
							graph.AddNode(tmp.GetCCNode())
							_, err := graph.Flush()
							if err != nil {
								fmt.Println(err)
							}
						}

						// Use Merge to create the relationship between the bot and the CC
						query = `MATCH (b:Bot {ip:"` + tmp.GetIp() + `"})
								MATCH (c:CC {host:"` + tmp.GetHost() + `"})
								MERGE (b)-[r:reach {name: "reach"}]->(c)`
						result, err = graph.Query(query)
						if err != nil {
							fmt.Println(err)
						}

						// If the bot downloaded a binary
						if tmp.GetContenttype() == "application/octet-stream" && tmp.GetStatus() == "200" {
							// Create binary if not exist
							query := `MATCH (bin:Binary` + tmp.GetBinaryMatchQuerySelector() + `) RETURN bin`
							result, err := graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}
							if result.Empty() {
								//fmt.Println("Add binary: "+tmp.GetBinaryMatchQuerySelector())
								fmt.Println(tmp.Curl())
								graph.AddNode(tmp.GetBinaryNode())
								_ , err := graph.Flush()
								if err != nil {
									fmt.Println(err)
								}
							}

							// Use Merge to create the relationship bot, binaries and CC
							query = `MATCH (b:Bot {ip:"` + tmp.GetIp() + `"})
								MATCH (c:CC {host:"` + tmp.GetHost() + `"})
								MATCH (bin:Binary ` + tmp.GetBinaryMatchQuerySelector() + `)
								MERGE (b)-[d:download {name: "download"}]->(bin)
								MERGE (c)-[h:host {name: "host"}]->(bin)`
							result, err = graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}
						}

						// We treated the request
						break
					}
				}
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	logger.Println("Exiting")
}

func removeMitm(s gj.Result) gj.Result {
	str := s.String()
	for _, v := range mitm {
		str = strings.Replace(str, string(v), "", -1)
	}
	s = gj.Result{Str: str, Type: gj.String}
	return s
}

func newPool(addr string, maxconn int) *redis.Pool {
	return &redis.Pool{
		MaxActive:   maxconn,
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		Dial: func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}

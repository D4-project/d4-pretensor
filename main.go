package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"github.com/D4-project/d4-pretensor/pretensorhit"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/D4-project/d4-golang-utils/config"
	"github.com/gomodule/redigo/redis"
	rg "github.com/redislabs/redisgraph-go"
	gj "github.com/tidwall/gjson"
)

type (
	redisconf struct {
		redisHost    string
		redisPort    string
		databasename string
	}

	binurl struct {
		url  string
		phit *pretensorhit.PHit
	}

	filedesc struct {
		path string
		info os.FileInfo
	}
)

// Setting up Flags and other Vars
var (
	confdir            = flag.String("c", "conf.sample", "configuration directory")
	folder             = flag.String("log_folder", "logs", "folder containing mod security logs")
	debug              = flag.Bool("d", false, "debug output")
	buf                bytes.Buffer
	logger             = log.New(&buf, "INFO: ", log.Lshortfile)
	redisConn          redis.Conn
	redisConnPretensor          redis.Conn
	redisGR            redis.Conn
	redisPretensorPool *redis.Pool
	redisd4Pool        *redis.Pool
	redisd4Queue       string
	tomonitor          [][]byte
	mitm               [][]byte
	curls              map[string]string
	// Keeps a map of url/hash to keep track of what we downloaded already
	binurls     map[string]*pretensorhit.PHit
	bashs       map[string]*pretensorhit.PHit
	wg          sync.WaitGroup
	walk_folder = true
	binchan     chan binurl
	filechan    chan filedesc
	bashchan    chan string
)

func main() {
	// Setting up log file
	f, err := os.OpenFile("pretensor.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}

	// Create infected folder if not exist
	if _, err := os.Stat("infected"); os.IsNotExist(err) {
		os.Mkdir("infected", 0750)
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
		fmt.Printf("from a folder first to bootstrap a redis graph, \n")
		fmt.Printf("and then from d4 to update it. \n")
		fmt.Printf("\n")
		fmt.Printf("Usage: d4-pretensor -c config_directory\n")
		fmt.Printf("\n")
		fmt.Printf("Configuration\n\n")
		fmt.Printf("The configuration settings are stored in files in the configuration directory\n")
		fmt.Printf("specified with the -c command line switch.\n\n")
		fmt.Printf("Files in the configuration directory\n")
		fmt.Printf("\n")
		fmt.Printf("redis_pretensor - host:port/graphname\n")
		fmt.Printf("redis_d4 - host:port/db\n")
		fmt.Printf("redis_d4_queue - d4 queue to pop\n")
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

	// Check redis-pretensor configuration
	rrg := redisconf{}
	// Parse Input Redis Config
	tmp := config.ReadConfigFile(*confdir, "redis_pretensor")
	ss := strings.Split(string(tmp), "/")
	if len(ss) <= 1 {
		log.Fatal("Missing Database in redis_pretensor input config: should be host:port/database_name")
	}
	rrg.databasename = ss[1]
	var ret bool
	ret, ss[0] = config.IsNet(ss[0])
	if ret {
		sss := strings.Split(string(ss[0]), ":")
		rrg.redisHost = sss[0]
		rrg.redisPort = sss[1]
	} else {
		logger.Fatal("Redis-pretensor config error.")
	}

	// Create a new redis-pretensor connection pool
	redisPretensorPool = newPool(rrg.redisHost+":"+rrg.redisPort, 400)
	redisConnPretensor, err = redisPretensorPool.Dial()
	if err != nil {
		logger.Fatal("Could not connect to redis-pretensor Redis")
	}

	// Check redis-d4 configuration
	rd4 := redisconf{}
	// Parse Input Redis Config
	tmp = config.ReadConfigFile(*confdir, "redis_d4")
	ss = strings.Split(string(tmp), "/")
	if len(ss) <= 1 {
		log.Fatal("Missing Database in redis_d4 input config: should be host:port/database_name")
	}
	rd4.databasename = ss[1]
	ret, ss[0] = config.IsNet(ss[0])
	if ret {
		sss := strings.Split(string(ss[0]), ":")
		rrg.redisHost = sss[0]
		rrg.redisPort = sss[1]
	} else {
		logger.Fatal("Redis-d4 config error.")
	}

	// Create a new redis-graph connection pool
	redisd4Pool = newPool(rrg.redisHost+":"+rrg.redisPort, 400)
	redisConn, err = redisd4Pool.Dial()
	if err != nil {
		logger.Fatal("Could not connect to d4 Redis")
	}

	// Get that the redis_d4_queue file
	redisd4Queue = string(config.ReadConfigFile(*confdir, "redis_d4_queue"))

	// Checking that the log folder exists
	log_folder := string(config.ReadConfigFile(*confdir, "folder"))
	_, err = ioutil.ReadDir(log_folder)
	if err != nil {
		logger.Println(err)
		walk_folder = false
	}

	// Loading Requests to monitor
	tomonitor = config.ReadConfigFileLines(*confdir, "tomonitor")
	// Loading proxy list to remove from Hosts
	mitm = config.ReadConfigFileLines(*confdir, "mitm")

	// Init maps
	curls = make(map[string]string)
	bashs = make(map[string]*pretensorhit.PHit)
	binurls = make(map[string]*pretensorhit.PHit)

	// Init redis graph
	graph := rg.GraphNew("pretensor", redisConnPretensor)
	graph.Delete()

	// Create processing channels
	binchan = make(chan binurl, 200)
	filechan = make(chan filedesc, 100000)
	bashchan = make(chan string, 200)

	// Launch the download routine
	//go downloadBin(binchan, sortie)
	// Launch the Pretensor routine
	wg.Add(1)
	go pretensorParse(filechan, sortie, &graph)

	// Walking folder
	err = filepath.Walk(log_folder,
		func(path string, info os.FileInfo, err error) error {
			filechan <- filedesc{path: path, info: info}
			if err != nil {
				return err
			}
			logger.Println(info.Name(), info.Size())
			return nil
		})
	//
	//// Write non-ELF to files and had hashed to the graph
	//for k, v := range bashs {
	//	// Set Sha 256 hash to the object
	//	v.SetSha256(k)
	//	// Add binary's hash to the graph
	//	query := `MATCH (b:Bot {ip:"` + v.GetIp() + `"})
	//			  MATCH (c:CC {host:"` + v.GetHost() + `"})
	//			  MERGE (bin:Binary ` + v.GetBinaryMergeSelector() + `)
	//			  MERGE (b)-[d:download {name: "download"}]->(bin)
	//			  MERGE (c)-[h:host {name: "host"}]->(bin)`
	//
	//	fmt.Println(query)
	//	result, err := graph.Query(query)
	//	if err != nil {
	//		logger.Println(err)
	//	}
	//	fmt.Println(result)
	//	err = ioutil.WriteFile("./infected/"+k, []byte(v.GetBody()), 0644)
	//	if err != nil {
	//		logger.Println(err)
	//	}
	//}
	//
	//// Write curl commands to a file
	//for _, v := range curls {
	//	f, err := os.OpenFile("./infected/curl.sh", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	//	if err != nil {
	//		logger.Println(err)
	//	}
	//	if _, err := f.Write([]byte(fmt.Sprintf("%v\n", v))); err != nil {
	//		f.Close()
	//		logger.Println(err)
	//	}
	//	if err := f.Close(); err != nil {
	//		logger.Println(err)
	//	}
	//}

	// Waiting for the binary fetching routines
	wg.Wait()

	logger.Println("Exiting")
}

// Parsing whatever is thrown into filechan
func pretensorParse(filechan chan filedesc, sortie chan os.Signal, graph *rg.Graph) error {
	logger.Println("Entering pretensorparse")
	defer wg.Done()
	for {
		select {
		case file := <-filechan:
			logger.Println(file.path)
			info := file.info
			path := file.path
			if !info.IsDir() {
				content, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				if len(content) == 0 {
					return filepath.SkipDir
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
						tmp.SetReferer(gj.Get(contents, "request.headers.Referer"))
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
							fmt.Println(result)
						}
						if result.Empty() {
							fmt.Println(tmp.GetBotNode())
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
							// Logging all bash scripts and curl commands to download binaries
							if strings.Contains(fmt.Sprintf("%v", tmp.GetBody()), "ELF") {
								tmpsha256 := sha256.Sum256([]byte(tmp.Curl()))
								curls[fmt.Sprintf("%x", tmpsha256)] = tmp.Curl()
								tmpsha256b := sha256.Sum256([]byte(tmp.GetBinurl()))
								binchan <- binurl{url: fmt.Sprintf("%x", tmpsha256b),
									phit: tmp}
							} else {
								tmpsha256 := sha256.Sum256([]byte(tmp.GetBody()))
								bashs[fmt.Sprintf("%x", tmpsha256)] = tmp
							}
							// Create binary if not exist
							query := `MATCH (bin` + tmp.GetBinaryMatchQuerySelector() + `) RETURN bin`
							// The following is causing a panic -- it looks like a redigo issue
							//query := `MATCH (bin:Binary` + tmp.GetBinaryMatchQuerySelector() + `) RETURN bin`
							qres, err := graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}
							if qres.Empty() {
								//fmt.Println("Add binary: "+tmp.GetBinaryMatchQuerySelector())
								graph.AddNode(tmp.GetBinaryNode())
								_, err := graph.Flush()
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

						// Bot set a referer command
						if tmp.GetCmdRawCommand() != "" {
							// First we update what we know about this bot
							query = `MATCH (b:Bot {ip:"` + tmp.GetIp() + `"})
								MATCH (c:CC {host:"` + tmp.GetHost() + `"})
								SET b.user="` + tmp.GetCmdUser() + `"
								SET b.hostname="` + tmp.GetCmdHostname() + `"
								SET b.fingerprint="` + tmp.GetCmdFingerprint() + `"
								SET b.architecture="` + tmp.GetCmdArchitecture() + `"`
							result, err = graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}

							// Then we create a command node for this command
							query = `MATCH (c:Command {rawcontent:"` + tmp.GetCmdRawCommand() + `"}) RETURN c.content`
							result, err = graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}
							if result.Empty() {
								graph.AddNode(tmp.GetCommandNode())
								_, err := graph.Flush()
								if err != nil {
									fmt.Println(err)
								}
							}

							// Finally we tie the Bot and the issued Command
							query = `MATCH (b:Bot {ip:"` + tmp.GetIp() + `"})
								MATCH (c:CC {host:"` + tmp.GetHost() + `"})
								MATCH (co:Command {rawcontent:"` + tmp.GetCmdRawCommand() + `"})
								MERGE (b)-[e:execute {name: "execute"}]->(co)
								MERGE (c)-[l:launch {name: "launch"}]->(co)`
							result, err = graph.Query(query)
							if err != nil {
								fmt.Println(err)
							}
						}

						if *debug {
							fmt.Println(tmp)
						}
						// We treated the request
						break
					}
				}
			}
		case <-sortie:
			return nil
		}
	}
}

// Gathering Binaries ourselves
func downloadBin(phitchan chan binurl, sortie chan os.Signal) error {
	wg.Add(1)
	defer wg.Done()
downloading:
	for {
		select {
		case vi := <-phitchan:
			fmt.Println("Received a new binary to download")
			// Check whether we already touched it
			tmpsha256b := sha256.Sum256([]byte(vi.phit.GetBinurl()))
			if _, ok := binurls[fmt.Sprintf("%x", tmpsha256b)]; !ok {
				//do something here
				var err error
				redisGR, err = redisPretensorPool.Dial()
				if err != nil {
					logger.Fatal("Could not connect routine to d4 Redis")
				}
				graphGR := rg.GraphNew("pretensor", redisGR)
				logger.Println("Fetching " + vi.phit.GetBinurl())
				defer wg.Done()
				// create a socks5 dialer
				dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
				if err != nil {
					fmt.Fprintln(os.Stderr, "can't connect to the proxy:", err)
					os.Exit(1)
				}
				// setup a http client
				httpTransport := &http.Transport{}
				httpClient := &http.Client{Transport: httpTransport}
				// set our socks5 as the dialer
				httpTransport.Dial = dialer.Dial
				// create a request
				req, err := http.NewRequest("GET", vi.phit.GetBinurl(), nil)
				req.Header.Set("User-Agent", "-")
				if err != nil {
					logger.Println(os.Stderr, "can't create request:", err)
				}
				// use the http client to fetch the page
				resp, err := httpClient.Do(req)
				if err != nil {
					logger.Println(os.Stderr, "can't GET page:", err)
					break downloading
				}
				defer resp.Body.Close()
				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					logger.Println(os.Stderr, "error reading body:", err)
				}
				tmpb := sha256.Sum256(b)
				err = ioutil.WriteFile("./infected/"+fmt.Sprintf("%x", tmpb), b, 0644)
				if err != nil {
					logger.Println(err)
				}

				// Update the Go object with this sha
				vi.phit.SetSha256(fmt.Sprintf("%x", tmpb))

				fmt.Printf("Not empty, we Create a new relationship for: %v ", vi.phit.GetSha256())
				query := `MATCH (b:Bot {ip:"` + vi.phit.GetIp() + `"})
								MATCH (c:CC {host:"` + vi.phit.GetHost() + `"})
								MERGE (bin:Binary ` + vi.phit.GetBinaryMergeSelector() + `)
								MERGE (b)-[d:download {name: "download"}]->(bin)
								MERGE (c)-[h:host {name: "host"}]->(bin)`
				fmt.Println(query)
				logger.Println(query)
				result, err := graphGR.Query(query)
				logger.Println(result)
				fmt.Println(result)
				if err != nil {
					fmt.Println(err)
				}

				// update the binurls map
				binurls[fmt.Sprintf("%x", tmpsha256b)] = vi.phit
			}
		case <-sortie:
			return nil
		}
	}
	return nil
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

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

	config "github.com/D4-project/d4-golang-utils/config"
	"github.com/gomodule/redigo/redis"
	rg "github.com/redislabs/redisgraph-go"
	gj "github.com/tidwall/gjson"
)

type (
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
	curls          map[string]string
	binurls        map[string]*pretensorhit.PHit
	bashs          map[string]*pretensorhit.PHit
	wg             sync.WaitGroup
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
	redisInputPool = newPool(rd4.redisHost+":"+rd4.redisPort, 200)
	redisConn, err = redisInputPool.Dial()
	if err != nil {
		logger.Fatal("Could not connect to d4 Redis")
	}

	// Init maps
	curls = make(map[string]string)
	bashs = make(map[string]*pretensorhit.PHit)
	binurls = make(map[string]*pretensorhit.PHit)

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
							// Logging all bash scripts and curl commands to downlaod binaries
							if strings.Contains(fmt.Sprintf("%v", tmp.GetBody()), "ELF") {
								tmpsha256 := sha256.Sum256([]byte(tmp.Curl()))
								curls[fmt.Sprintf("%x", tmpsha256)] = tmp.Curl()
								tmpsha256b := sha256.Sum256([]byte(tmp.GetBinurl()))
								binurls[fmt.Sprintf("%x", tmpsha256b)] = tmp

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

						fmt.Println(tmp)
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

	os.Exit(0)

	// Gathering Binaries ourselves
	for _, v := range binurls {
		wg.Add(1)
		// Go fetch the binary
		go func(vi *pretensorhit.PHit) {
			logger.Println("Fetching " + vi.GetBinurl())
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
			req, err := http.NewRequest("GET", vi.GetBinurl(), nil)
			req.Header.Set("User-Agent", "-")
			if err != nil {
				logger.Println(os.Stderr, "can't create request:", err)
			}
			// use the http client to fetch the page
			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Println(os.Stderr, "can't GET page:", err)
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

			// Add binary's hash to the graph
			query := `MATCH (b:Bot {ip:"` + vi.GetIp() + `"})
					MATCH (c:CC {host:"` + vi.GetHost() + `"})
					MATCH (bin:Binary ` + vi.GetBinaryMatchQuerySelector() + `)
					SET bin.sha256="` + fmt.Sprintf("%x", tmpb) + `"`
			fmt.Println(query)
			_, err = graph.Query(query)
			if err != nil {
				logger.Println(err)
			}
		}(v)
	}

	// Write non-ELF to files and had hashed to the graph
	for k, v := range bashs {
		// Add binary's hash to the graph
		query := `MATCH (b:Bot {ip:"` + v.GetIp() + `"})
					MATCH (c:CC {host:"` + v.GetHost() + `"})
					MATCH (bin:Binary ` + v.GetBinaryMatchQuerySelector() + `)
					SET bin.sha256="` + k + `"`
		fmt.Println(query)
		_, err = graph.Query(query)
		if err != nil {
			logger.Println(err)
		}
		err := ioutil.WriteFile("./infected/"+k, []byte(v.GetBody()), 0644)
		if err != nil {
			logger.Println(err)
		}
	}

	// Write curl commands to a file
	for _, v := range curls {
		f, err := os.OpenFile("./infected/curl.sh", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Println(err)
		}
		if _, err := f.Write([]byte(fmt.Sprintf("%v\n", v))); err != nil {
			f.Close()
			logger.Println(err)
		}
		if err := f.Close(); err != nil {
			logger.Println(err)
		}
	}

	// Waiting for the binary fetchin routines
	wg.Wait()

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

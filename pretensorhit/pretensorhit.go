package pretensorhit

import (
	"bytes"
	"fmt"
	rg "github.com/redislabs/redisgraph-go"
	gj "github.com/tidwall/gjson"
	"regexp"
	"strings"
	"time"
)

type (
	PHit struct {
		req request
		res response
		g graph
	}

	request struct {
		timestamp string
		ip        string
		useragent string
		line      string
		host      string
	}

	response struct {
		status       string
		body         string
		contenttype string
		length       string
	}

	graph struct{
		bot rg.Node
		bin rg.Node
		cc rg.Node
		rel rg.Edge
	}
)

func (p *PHit) SetTimestamp(in gj.Result) {
	p.req.timestamp = in.String()
	return
}

func (p *PHit) SetIp(in gj.Result) {
	p.req.ip = in.String()
	return
}

func(p *PHit) GetIp() string{
	return p.req.ip
}

func (p *PHit) SetUseragent(in gj.Result) {
	p.req.useragent = in.String()
	return
}

func (p *PHit) SetLine(in gj.Result) {
	p.req.line = in.String()
	return
}

func (p *PHit) GetLine(in gj.Result) string {
	return p.req.line
}

func (p *PHit) SetHost(in gj.Result) {
	p.req.host = in.String()
	return
}

func(p *PHit) GetHost() string{
	return p.req.host
}

func (p *PHit) SetStatus(in gj.Result) {
	p.res.status = in.String()
	return
}

func (p *PHit) GetStatus() string{
	return p.res.status
}

func (p *PHit) SetBody(in gj.Result) {
	p.res.body = in.String()
	return
}

func (p *PHit) GetBody() string {
	return p.res.body
}

func (p *PHit) SetContenttype(in gj.Result) {
	p.res.contenttype = in.String()
	return
}

func (p *PHit) GetContenttype() string {
	return p.res.contenttype
}

func (p *PHit) SetLength(in gj.Result) {
	p.res.length = in.String()
	return
}

func (p *PHit) GetLength() string {
	return p.res.length
}

func (p *PHit) getMethod() string {
	re, _ := regexp.Compile(`(?P<verb>GET|POST|HEAD|DELETE|PUT|UPDATE)\s(?P<command>\/\S*)\s(?P<version>\S*)`)
	indexes := re.FindStringSubmatch(p.req.line)
	return indexes[1]
}

func (p *PHit) getBinName() string {
	re, _ := regexp.Compile(`(?P<verb>GET|POST|HEAD|DELETE|PUT|UPDATE)\s(?P<command>\/\S*)\s(?P<version>\S*)`)
	indexes := re.FindStringSubmatch(p.req.line)
	return indexes[2]
}

func(p *PHit) getBinurl() string{
	re, _ := regexp.Compile(`(?P<verb>GET|POST|HEAD|DELETE|PUT|UPDATE)\s(?P<command>\/\S*)\s(?P<version>\S*)`)
	indexes := re.FindStringSubmatch(p.req.line)
	str := "http://"+p.req.host+indexes[2]
	return str
}

func(p *PHit) getTimeStamp() time.Time {
	// "05/Nov/2020:16:30:10 +0100"
	// Mon Jan 2 15:04:05 -0700 MST 2006
	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700"  ,p.req.timestamp)
	return ts
}

func(p *PHit) GetBotNode() *rg.Node{
	p.g.bot = rg.Node{
		Label: "Bot",
		Properties: map[string]interface{}{
			"ip": p.req.ip,
			"lastseen": p.req.timestamp,
		},
	}
	return &p.g.bot
}

func(p *PHit) GetCCNode() *rg.Node{
	p.g.cc = rg.Node{
		Label: "CC",
		Properties: map[string]interface{}{
			"host"	: p.req.host,
		},
	}
	return & p.g.cc
}

func(p *PHit) GetBinaryMatchQuerySelector() string{
	return "{size:\""+p.res.length+"\", binname:\""+p.getBinName()+"\"}"
}

func(p *PHit) GetBinaryNode() *rg.Node{
	p.g.bin = rg.Node{
		Label: "Binary",
		Properties: map[string]interface{}{
			"size": p.res.length,
			"lastseen": p.req.timestamp,
			"binname": p.getBinName(),
			"method": p.getMethod(),
		},
	}
	return &p.g.bin
}

func (p *PHit) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("---------------HIT START-------------------\n"))
	buf.WriteString(fmt.Sprintf("Timestmap: %v\n", p.req.timestamp))
	buf.WriteString(fmt.Sprintf("Remote IP: %v\n", p.req.ip))
	buf.WriteString(fmt.Sprintf("User-Agent: %v\n", p.req.useragent))
	buf.WriteString(fmt.Sprintf("Request: %v\n", p.req.line))
	buf.WriteString(fmt.Sprintf("Host: %v\n", p.req.host))
	buf.WriteString(fmt.Sprintf("Response status: %v\n", p.res.status))
	buf.WriteString(fmt.Sprintf("Response content-type: %v\n", p.res.contenttype))
	buf.WriteString(fmt.Sprintf("Response length: %v\n", p.res.length))
	buf.WriteString(fmt.Sprintf("Response body: %v\n", p.res.body))
	buf.WriteString(fmt.Sprintf("---------------HIT END--------------------\n"))
	return buf.String()
}

func(p *PHit) Curl() string{
	str := "curl -A \"-\" "
	str += p.getBinurl()+" -X "+p.getMethod()+" -o "+strings.TrimPrefix(p.getBinName(), "/")+" --create-dirs"
	return str
}


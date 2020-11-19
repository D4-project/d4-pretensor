package pretensorhit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	rg "github.com/redislabs/redisgraph-go"
	gj "github.com/tidwall/gjson"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	PHit struct {
		req request
		res response
		cmd command
		g   graph
	}

	request struct {
		timestamp string
		ip        string
		useragent string
		line      string
		host      string
		referer   string
	}

	response struct {
		status      string
		body        string
		contenttype string
		length      string
		sha256      string
	}

	command struct {
		ip          string
		user        string
		arch        string
		hostname    string
		fingerprint string
		command     string
		rawcommand  string
	}

	graph struct {
		bot rg.Node
		bin rg.Node
		cmd rg.Node
		cc  rg.Node
		rel rg.Edge
	}
)

func (p *PHit) SetReferer(in gj.Result) {
	if in.String() != "" {
		p.req.referer = in.String()
		p.extractRefererFields()
	}
	return
}

func (p *PHit) GetReferer() string {
	return p.req.referer
}

func (p *PHit) GetSha256() string {
	return p.res.sha256
}

func (p *PHit) SetSha256(in string) {
	p.res.sha256 = in
	return
}

func (p *PHit) GetCmdRawCommand() string {
	return p.cmd.rawcommand
}

func (p *PHit) GetCmdDecodedCommand() string {
	return p.cmd.command
}

func (p *PHit) GetCmdUser() string {
	return p.cmd.user
}

func (p *PHit) GetCmdHostname() string {
	return p.cmd.hostname
}

func (p *PHit) GetCmdFingerprint() string {
	return p.cmd.fingerprint
}

func (p *PHit) GetCmdArchitecture() string {
	return p.cmd.arch
}

func (p *PHit) SetTimestamp(in gj.Result) {
	p.req.timestamp = in.String()
	return
}

func (p *PHit) SetIp(in gj.Result) {
	p.req.ip = in.String()
	return
}

func (p *PHit) GetIp() string {
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

func (p *PHit) GetHost() string {
	return p.req.host
}

func (p *PHit) SetStatus(in gj.Result) {
	p.res.status = in.String()
	return
}

func (p *PHit) GetStatus() string {
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

func (p *PHit) GetBinurl() string {
	re, _ := regexp.Compile(`(?P<verb>GET|POST|HEAD|DELETE|PUT|UPDATE)\s(?P<command>\/\S*)\s(?P<version>\S*)`)
	indexes := re.FindStringSubmatch(p.req.line)
	str := "http://" + p.req.host + indexes[2]
	return str
}

func (p *PHit) getTimeStamp() time.Time {
	// "05/Nov/2020:16:30:10 +0100"
	// Mon Jan 2 15:04:05 -0700 MST 2006
	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", p.req.timestamp)
	return ts
}

func (p *PHit) GetBotNode() *rg.Node {
	p.g.bot = rg.Node{
		Label: "Bot",
		Properties: map[string]interface{}{
			"ip":       p.req.ip,
			"lastseen": p.req.timestamp,
		},
	}
	return &p.g.bot
}

func (p *PHit) GetCCNode() *rg.Node {
	p.g.cc = rg.Node{
		Label: "CC",
		Properties: map[string]interface{}{
			"host": p.req.host,
		},
	}
	return &p.g.cc
}

func (p *PHit) GetBinaryMatchQuerySelector() string {
	return "{size:\"" + p.res.length + "\", binname:\"" + p.getBinName() + "\"}"
}

func (p *PHit) GetBinaryMatchSha256Selector() string {
	return "{sha256:\"" + p.res.sha256 + "\"}"
}

func (p *PHit) GetBinaryMergeSelector() string {
	return "{sha256:\"" + p.res.sha256 + "\", size:\"" + p.res.length + "\", binname:\"" + p.getBinName() + "\"}"
}

func (p *PHit) GetBinaryNode() *rg.Node {
	p.g.bin = rg.Node{
		Label: "Binary",
		Properties: map[string]interface{}{
			"size":    p.res.length,
			"binname": p.getBinName(),
			"sha256":  p.GetSha256(),
		},
	}
	return &p.g.bin
}

func (p *PHit) GetCommandNode() *rg.Node {
	p.g.cmd = rg.Node{
		Label: "Command",
		Properties: map[string]interface{}{
			"content":    strconv.Quote(p.GetCmdDecodedCommand()),
			"rawcontent": p.GetCmdRawCommand(),
		},
	}
	return &p.g.cmd
}

func (p *PHit) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("---------------HIT START-------------------\n"))
	buf.WriteString(fmt.Sprintf("Timestmap: %v\n", p.req.timestamp))
	buf.WriteString(fmt.Sprintf("Remote IP: %v\n", p.req.ip))
	buf.WriteString(fmt.Sprintf("User-Agent: %v\n", p.req.useragent))
	buf.WriteString(fmt.Sprintf("Referer: %v\n", p.req.referer))
	buf.WriteString(fmt.Sprintf("Request: %v\n", p.req.line))
	buf.WriteString(fmt.Sprintf("Host: %v\n", p.req.host))
	buf.WriteString(fmt.Sprintf("Response status: %v\n", p.res.status))
	buf.WriteString(fmt.Sprintf("Response content-type: %v\n", p.res.contenttype))
	buf.WriteString(fmt.Sprintf("Response length: %v\n", p.res.length))
	buf.WriteString(fmt.Sprintf("Response body: %v\n", p.res.body))

	// We avoid outputing REDIS rdb files
	storecommand := p.cmd.rawcommand
	if len(p.cmd.command) > 4 {
		fmt.Println([]byte(p.cmd.command)[:4])
		if res := bytes.Compare([]byte(p.cmd.command)[:5], []byte{'R', 'E', 'D', 'I', 'S'}); res != 0 {
			storecommand = p.cmd.command
		}
	}

	if (p.cmd.ip == p.req.ip) || (p.cmd.hostname != "") || (p.cmd.fingerprint != "") || (p.cmd.hostname != "") || (p.cmd.user != "") || (len(p.cmd.command) > 0) {
		buf.WriteString(fmt.Sprintf("Bot user: %v\n", p.cmd.user))
		buf.WriteString(fmt.Sprintf("Bot arch: %v\n", p.cmd.arch))
		buf.WriteString(fmt.Sprintf("Bot hostname: %v\n", p.cmd.hostname))
		buf.WriteString(fmt.Sprintf("Bot fingerprint: %v\n", p.cmd.fingerprint))
		buf.WriteString(fmt.Sprintf("Bot command: %v\n", storecommand))
	}
	buf.WriteString(fmt.Sprintf("---------------HIT END--------------------\n"))
	return buf.String()
}

func (p *PHit) Curl() string {
	str := "curl -A \"-\" "
	str += p.GetBinurl() + " -X " + p.getMethod() + " -o " + strings.TrimPrefix(p.getBinName(), "/") + " --create-dirs"
	return str
}

func (p *PHit) extractRefererFields() {
	re, _ := regexp.Compile(`(?P<ip>.*)_(?P<user>.*)_(?P<arch>x86_64|i386|i686|ia64|alpha|amd64|arm|armeb|armel|hppa|m32r|m68k|mips|mipsel |powerpc|ppc64|s390|s390x|sh3|sh3eb|sh4|sh4eb|sparc)_(?P<hostname>.*)_(?P<fingerprint>.*)_(?P<command>.*)`)
	indexes := re.FindStringSubmatch(p.req.referer)
	if indexes != nil {
		p.cmd.ip = indexes[1]
		p.cmd.user = indexes[2]
		p.cmd.arch = indexes[3]
		p.cmd.hostname = indexes[4]
		p.cmd.fingerprint = indexes[5]
		data, _ := base64.StdEncoding.DecodeString(indexes[6])
		p.cmd.command = string(data)
		p.cmd.rawcommand = indexes[6]
	}
}

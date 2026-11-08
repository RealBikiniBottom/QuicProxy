// Command doh_go_client queries a DNS-over-HTTPS server with miekg/dns messages
// over Go's net/http stack and prints one answer record per line.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	url := flag.String("url", "", "DoH endpoint")
	name := flag.String("name", "", "query name")
	qtype := flag.String("type", "A", "query type")
	method := flag.String("method", "POST", "GET or POST")
	http1 := flag.Bool("http1", false, "force HTTP/1.1")
	subnet := flag.String("ecs", "", "EDNS client subnet to send, e.g. 198.51.100.0/24")
	flag.Parse()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(*name), dns.StringToType[strings.ToUpper(*qtype)])
	msg.Id = 0
	if *subnet != "" {
		_, network, err := net.ParseCIDR(*subnet)
		must(err)
		ones, _ := network.Mask.Size()
		option := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(ones), Address: network.IP}
		if network.IP.To4() != nil {
			option.Family = 1
		} else {
			option.Family = 2
		}
		msg.SetEdns0(1232, false)
		opt := msg.IsEdns0()
		opt.Option = append(opt.Option, option)
	}
	wire, err := msg.Pack()
	must(err)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: !*http1,
	}
	if *http1 {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: transport}

	var req *http.Request
	if strings.EqualFold(*method, "GET") {
		req, err = http.NewRequest(http.MethodGet, *url+"?dns="+base64.RawURLEncoding.EncodeToString(wire), nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, *url, bytes.NewReader(wire))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	must(err)
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	must(err)
	if resp.StatusCode != http.StatusOK {
		fail("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		fail("content-type %q", ct)
	}

	reply := new(dns.Msg)
	must(reply.Unpack(body))
	if reply.Id != msg.Id {
		fail("id mismatch %d != %d", reply.Id, msg.Id)
	}
	fmt.Printf("PROTO %s\n", resp.Proto)
	fmt.Printf("RCODE %s\n", dns.RcodeToString[reply.Rcode])
	if opt := reply.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				fmt.Printf("ECS %s/%d/%d\n", s.Address, s.SourceNetmask, s.SourceScope)
			}
		}
	}
	for _, rr := range reply.Answer {
		switch v := rr.(type) {
		case *dns.A:
			fmt.Printf("A %s\n", v.A)
		case *dns.AAAA:
			fmt.Printf("AAAA %s\n", v.AAAA)
		case *dns.TXT:
			fmt.Printf("TXT %s\n", strings.Join(v.Txt, ""))
		}
	}
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

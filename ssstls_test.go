package ssstls

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/Sssilencee/ssstls/ssstransport"
)

const (
	ja3      = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24-25,0"
	ua       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
	proxyUrl = "http://5k1M9M:gw5ePc@193.32.54.135:8000"

	ja3ZoneUrl  = "https://check.ja3.zone/"
	scrapflyUrl = "https://tools.scrapfly.io/api/fp/ja3?extended=1"
	myIpUrl     = "https://api.myip.com"
)

type ja3ZoneRes struct {
	Fingerprint string `json:"fingerprint"`
}

func TestJa3HTTP1(t *testing.T) {
	transport := ssstransport.NewTransport(ja3, ua)
	client := http.Client{Transport: &transport}

	data, err := makeReq[ja3ZoneRes](&client, ja3ZoneUrl)
	if err != nil {
		t.Fatalf("make request: %v", err)
	}

	t.Log(data.Fingerprint)

	if data.Fingerprint != ja3 {
		t.Fatalf("ja3's differ")
	}
}

type scrapflyRes struct {
	Ja3 string `json:"ja3"`
}

func TestJa3ProxyHTTP2(t *testing.T) {
	url, err := url.Parse(proxyUrl)
	if err != nil {
		t.Fatalf("proxy parse: %v", err)
	}

	transport, err := ssstransport.NewTransportProxy(ja3, ua, *url)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}

	client := http.Client{Transport: &transport}

	data, err := makeReq[scrapflyRes](&client, scrapflyUrl)
	if err != nil {
		t.Fatalf("make request: %v", err)
	}

	t.Logf("Ja3: %s", data.Ja3)

	// Site shows not accurate TLS version (and extensions sometime)
	if data.Ja3[5:] != ja3[5:] {
		t.Fatalf("ja3's differ")
	}
}

type myIpRes struct {
	IP string `json:"ip"`
}

func TestIPProxyHTTP2(t *testing.T) {
	url, err := url.Parse(proxyUrl)
	if err != nil {
		t.Fatalf("proxy parse: %v", err)
	}

	var local string
	{
		client := http.Client{}

		data, err := makeReq[myIpRes](&client, myIpUrl)
		if err != nil {
			t.Fatalf("make request: %v", err)
		}
		local = data.IP
	}

	transport, err := ssstransport.NewTransportProxy(ja3, ua, *url)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}

	client := http.Client{Transport: &transport}

	data, err := makeReq[myIpRes](&client, myIpUrl)
	if err != nil {
		t.Fatalf("make request: %v", err)
	}

	t.Logf("Proxy IP: %s", data.IP)
	t.Logf("Local IP: %s", local)

	if data.IP == local {
		t.Fatalf("ip's not differ")
	}
}

func makeReq[T ja3ZoneRes | scrapflyRes | myIpRes](client *http.Client, url string) (T, error) {
	var data T

	res, err := client.Get(url)
	if err != nil {
		return data, fmt.Errorf("client get: %v", err)
	}

	b, err := io.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		return data, fmt.Errorf("io readall: %v", err)
	}

	err = json.Unmarshal(b, &data)
	if err != nil {
		return data, fmt.Errorf("body unmarshal: %v", err)
	}

	return data, nil
}

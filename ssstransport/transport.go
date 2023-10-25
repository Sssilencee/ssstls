package ssstransport

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	utls "github.com/Danny-Dasilva/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

type (
	connVersion int
	t1          struct{ http.Transport }
	t2          struct{ http2.Transport }
)

const (
	h1 connVersion = iota
	h2
)

type Transport struct {
	ja3      string
	ua       string
	proxyURL url.URL
	dialer   proxy.Dialer

	t1 *t1
	t2 *t2

	conns *connectionPool
}

func NewTransport(ja3, ua string) Transport {
	connPool := newConnectionPool()
	transport := Transport{
		ja3:    ja3,
		ua:     ua,
		dialer: &net.Dialer{},
		conns:  &connPool,
	}
	transport.applyTransports()
	return transport
}

func NewTransportProxy(ja3, ua string, proxy url.URL) (Transport, error) {
	header := http.Header{}
	parsedProxy, err := parseProxyURL(proxy)
	if err != nil {
		return Transport{}, fmt.Errorf("parse proxy: %v", err)
	}
	header.Add("Proxy-Authorization", parsedProxy.auth)

	connPool := newConnectionPool()
	dialer := dialer{
		proxyURL:      parsedProxy.url,
		defaultHeader: header,
	}
	transport := Transport{
		ja3:      ja3,
		ua:       ua,
		proxyURL: parsedProxy.url,
		dialer:   &dialer,
		conns:    &connPool,
	}
	transport.applyTransports()

	return transport, nil
}

func (t *Transport) applyTransports() {
	t.t1 = &t1{
		Transport: http.Transport{
			DialTLS: t.dialWithConn1,
		},
	}
	t.t2 = &t2{
		Transport: http2.Transport{
			DialTLS: t.dialWithConn2,
		},
	}
}

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		return nil, fmt.Errorf("you don't need ssstls for requests with the HTTP scheme; please use the default net/http package")
	case "https":
		return t.httpsRoundTrip(req)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", req.URL.Scheme)
	}
}

func (t *Transport) httpsRoundTrip(req *http.Request) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}

	key := fmt.Sprintf("%s:%s", req.Host, port)

	var transport http.RoundTripper

	getTransport := func(version connVersion) http.RoundTripper {
		switch version {
		case h1:
			return t.t1
		case h2:
			return t.t2
		default:
			return nil
		}
	}

	// We don't want to write lock the entire version map after connection initialization
	version, exist := t.conns.getConnVersion(key) // Read Lock()/Unlock()
	if exist && version != -1 {
		// ^ Main branch, when we know the http version ^
		transport = getTransport(version)
	} else {
		// ^ Branch for sites with unknown http version ^

		// Read and write map in one transaction
		t.conns.connVersionsMu.Lock()

		// Perform an additional existence check with a locked mutex to ensure that reading 'not exist' occurs only once
		entry, exist := t.conns.connVersions[key]
		if exist {
			version := entry.version

			// Unlock the version map and lock the concrete site entry.
			// We don't want to wait for connection initialization for all sites
			t.conns.connVersionsMu.Unlock()

			// If conn hasn't been initialized yet
			if version == -1 {
				// Wait for conn initialization
				entry.Lock()
				version = t.conns.connVersions[key].version
				entry.Unlock()
			}
			transport = getTransport(version)
		} else {
			t.conns.connVersions[key] = connVersionEntry{&sync.Mutex{}, -1}
			entry := t.conns.connVersions[key]

			// Lock all threads with the same key until conn initialization
			entry.Lock()
			// Unlocks on conn initialization or on error
			defer entry.Unlock()

			t.conns.connVersionsMu.Unlock()
		}
	}

	if transport != nil {
		return transport.RoundTrip(req)
	}

	conn, err := t.dialTLS("tcp", fmt.Sprintf("%s:%s", req.Host, port))
	if err != nil {
		return nil, fmt.Errorf("dial TLS: %s", err)
	}

	{
		version := conn.ConnectionState().NegotiatedProtocol
		t.conns.setWaitingConn(key, conn)
		switch version {
		case "h2":
			t.conns.setConnVersion(key, h2)
			return t.t2.RoundTrip(req)
		case "http/1.1", "":
			t.conns.setConnVersion(key, h1)
			return t.t1.RoundTrip(req)
		default:
			return nil, fmt.Errorf("unsuported http version: %s", version)
		}
	}
}

func (t Transport) dialTLS(network, address string) (*utls.UConn, error) {
	spec, err := stringToSpec(t.ja3, t.ua)
	if err != nil {
		return nil, fmt.Errorf("string to spec: %v", err)
	}

	conn, err := t.dialer.Dial(network, address)
	if err != nil {
		return nil, closeWithErr(conn, fmt.Errorf("dial: %v", err))
	}

	host := strings.Split(address, ":")[0]

	{
		conn := utls.UClient(conn, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloCustom)
		if err := conn.ApplyPreset(spec); err != nil {
			return nil, closeWithErr(conn, fmt.Errorf("uclient: %v", err))
		}

		if err := conn.Handshake(); err != nil {
			return nil, closeWithErr(conn, fmt.Errorf("handhake: %v", err))
		}

		return conn, nil
	}
}

func (t Transport) dialWithConn(network, address string) (net.Conn, error) {
	waitingConn, exist := t.conns.getWaitingConn(address)
	if exist && waitingConn.flag.CompareAndSwap(true, false) {
		return waitingConn.conn, nil
	}
	return t.dialTLS(network, address)
}

func (t Transport) dialWithConn1(network, address string) (net.Conn, error) {
	return t.dialWithConn(network, address)
}

func (t Transport) dialWithConn2(network, address string, _ *tls.Config) (net.Conn, error) {
	return t.dialWithConn(network, address)
}

func closeWithErr(conn net.Conn, e error) error {
	const connCloseErrMsg = "failed to close connection: %v, with err: %v"
	if conn == nil {
		return errors.New("failed to close <nil> connection")
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf(connCloseErrMsg, err, e)
	}
	return e
}

type parsedProxy struct {
	url  url.URL
	auth string
}

func parseProxyURL(proxyURL url.URL) (parsedProxy, error) {
	var parsedProxy parsedProxy

	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
		}
	case "":
		return parsedProxy, errors.New("specify scheme explicitly (https://)")
	default:
		return parsedProxy, fmt.Errorf("proxy scheme is not supported: %s", proxyURL.Scheme)
	}

	parsedProxy.url = proxyURL

	if proxyURL.User != nil {
		if proxyURL.User.Username() != "" {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()

			auth := username + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			parsedProxy.auth = basicAuth
		}
	}
	return parsedProxy, nil
}

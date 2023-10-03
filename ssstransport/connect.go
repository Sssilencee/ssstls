package ssstransport

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"
)

type dialer struct {
	proxyURL      url.URL
	defaultHeader http.Header
	dialer        net.Dialer
}

func (d *dialer) Dial(network, address string) (net.Conn, error) {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}
	for k, v := range d.defaultHeader {
		req.Header[k] = v
	}

	var (
		conn               net.Conn
		err                error
		negotiatedProtocol string
	)

	switch d.proxyURL.Scheme {
	case "http":
		conn, err = d.dialer.Dial(network, d.proxyURL.Host)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("scheme is not supported: %s", d.proxyURL.Scheme)
	}

	switch negotiatedProtocol {
	case "http/1.1", "":
		return connectHTTP1(req, conn)
	case "h2":
		t := http2.Transport{}
		clientConn, err := t.NewClientConn(conn)
		if err != nil {
			return conn, fmt.Errorf("http2 new connect: %v", err)
		}

		proxyConn, err := connectHTTP2(req, conn, clientConn)
		if err != nil {
			return conn, fmt.Errorf("http2 connect: %v", err)
		}
		return proxyConn, err
	default:
		return conn, fmt.Errorf("negotiated unsupported application layer protocol: %s", negotiatedProtocol)
	}
}

const proxyErrMsg = "proxy responded with non 200 code: %s"

func connectHTTP1(req *http.Request, conn net.Conn) (net.Conn, error) {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("request write: %v", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, fmt.Errorf("read response: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(proxyErrMsg, res.Status)
	}
	return conn, nil
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func connectHTTP2(req *http.Request, conn net.Conn, clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	res, err := clientConn.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("round trip: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(proxyErrMsg, res.Status)
	}
	return http2Conn{conn, pw, res.Body}, nil
}

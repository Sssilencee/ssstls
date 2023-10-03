package ssstransport

import (
	"net"
	"sync"
	"sync/atomic"
)

type connectionPool struct {
	connVersionsMu sync.RWMutex
	connVersions   map[string]connVersionEntry
	waitingConnsMu sync.RWMutex
	waitingConns   map[string]waitingConn
}

func newConnectionPool() connectionPool {
	return connectionPool{
		connVersionsMu: sync.RWMutex{},
		connVersions:   make(map[string]connVersionEntry),
		waitingConnsMu: sync.RWMutex{},
		waitingConns:   make(map[string]waitingConn),
	}
}

type connVersionEntry struct {
	*sync.Mutex
	version connVersion
}

type waitingConn struct {
	flag *atomic.Bool
	conn net.Conn
}

func (c *connectionPool) getConnVersion(key string) (connVersion, bool) {
	c.connVersionsMu.RLock()
	conn, exist := c.connVersions[key]
	c.connVersionsMu.RUnlock()
	return conn.version, exist
}

func (c *connectionPool) setConnVersion(key string, value connVersion) {
	c.connVersionsMu.Lock()
	c.connVersions[key] = connVersionEntry{version: value}
	c.connVersionsMu.Unlock()
}

func (c *connectionPool) getWaitingConn(key string) (waitingConn, bool) {
	c.waitingConnsMu.RLock()
	conn, exist := c.waitingConns[key]
	c.waitingConnsMu.RUnlock()
	return conn, exist
}

func (c *connectionPool) setWaitingConn(key string, value net.Conn) {
	c.waitingConnsMu.Lock()
	c.waitingConns[key] = waitingConn{&atomic.Bool{}, value}
	c.waitingConns[key].flag.Store(true)
	c.waitingConnsMu.Unlock()
}

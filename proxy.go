package srp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type ReverseProxy struct {
	rp  httputil.ReverseProxy
	reg Registry
	mu  sync.RWMutex
	log Logger
}

type Registry map[string]*struct {
	HealthPath   string
	Backends     []string
	liveBackends []string
}

type Logger interface {
	Printf(format string, vals ...interface{})
}

// NewProxy from a given Registry.
func NewProxy(log Logger, reg Registry) *ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}
	transport := newTransport(reg)
	rp := httputil.ReverseProxy{Director: director, Transport: transport}
	return &ReverseProxy{rp: rp, log: log, reg: reg}
}

// ServeHTTP implements the http.RoundTripper interface.
func (r *ReverseProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.rp.ServeHTTP(w, req)
}

// NewRegistry for a given configuration file. This reports an error if any
// frontend host has no backends.
func NewRegistry(filename string) (Registry, error) {
	byt, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "read file %q", filename)
	}
	reg := Registry{}
	err = json.Unmarshal(byt, &reg)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal config")
	}
	for host, v := range reg {
		if len(v.Backends) == 0 {
			return nil, fmt.Errorf("missing backends for %q", host)
		}
	}
	return reg, nil
}

// Hosts for the registry.
func (r Registry) Hosts() []string {
	hosts := []string{}
	for k := range r {
		hosts = append(hosts, k)
	}
	return hosts
}

// CheckHealth of backend servers in the registry concurrently, up to 10 at a
// time. If an unexpected error is returned during any of the checks,
// CheckHealth immediately exits, reporting that error.
func (r *ReverseProxy) CheckHealth(client *http.Client) error {
	regClone := Registry{}
	for k, v := range r.reg {
		regClone[k] = v
	}
	changed := false
	semaphore := make(chan int, 10)
	for host, frontend := range regClone {
		if len(frontend.HealthPath) == 0 {
			continue
		}
		changed = true
		liveBackends := []string{}
		ipchan := make(chan string)
		errchan := make(chan error, 1)
		for _, ip := range frontend.Backends {
			target := "http://" + ip + frontend.HealthPath
			semaphore <- 1
			go ping(client, ip, target, semaphore, ipchan, errchan)
		}
		f := regClone[host]
		for i := 0; i < len(frontend.Backends); i++ {
			select {
			case ip := <-ipchan:
				if ip == "" {
					continue
				}
				liveBackends = append(liveBackends, ip)
			case err := <-errchan:
				return errors.Wrap(err, "err on channel")
			}
		}
		f.liveBackends = liveBackends
	}
	if changed {
		r.UpdateRegistry(regClone)
	}
	return nil
}

func (r *ReverseProxy) UpdateRegistry(reg Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reg = reg
	r.rp.Transport = newTransport(reg)
}

func newTransport(reg Registry) http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: func(network, addr string) (net.Conn, error) {
			endpoints := reg[addr].Backends
			randInt := rand.Int()
			endpoint := endpoints[randInt%len(endpoints)]
			conn, err := net.Dial(network, endpoint)
			if len(endpoints) < 2 || err == nil {
				return conn, err
			}
			// Retry on other endpoints if there are multiple
			conn, err = net.Dial(network, endpoints[(randInt+1)%len(endpoints)])
			if len(endpoints) < 3 || err == nil {
				return conn, err
			}
			return net.Dial(network, endpoints[(randInt+2)%len(endpoints)])
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
}

func ping(
	client *http.Client,
	ip, target string,
	semaphore chan int,
	ipchan chan string,
	errchan chan error,
) {
	defer func() {
		semaphore <- 1
	}()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		errchan <- errors.Wrap(err, "new request")
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s: failed connection: %s", ip, err)
		ipchan <- ""
		return
	}
	if err = resp.Body.Close(); err != nil {
		errchan <- errors.Wrap(err, "close resp body")
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("%s: expected status code 200, got %d",
			ip, resp.StatusCode)
		ipchan <- ""
		return
	}
	ipchan <- ip
}

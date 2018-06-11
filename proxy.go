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

// ReverseProxy
type ReverseProxy struct {
	rp  httputil.ReverseProxy
	reg Registry
	mu  sync.RWMutex
	log Logger
}

// Registry maps hosts to backends with other helpful info, such as
// healthchecks.
type Registry map[string]*struct {
	HealthPath   string
	Backends     []string
	liveBackends []string
}

// Logger logs error messages for the caller where those errors don't require
// returning, i.e. the logging itself constitutes handling the error.
type Logger interface {
	Printf(format string, vals ...interface{})
}

type healthCheck struct {
	host       string
	ip         string
	healthPath string
	err        error
}

// NewProxy from a given Registry.
func NewProxy(log Logger, reg Registry) *ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		log.Printf("%s requested %s %s", req.RemoteAddr, req.Method, req.Host)
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

func (r Registry) clone() Registry {
	clone := Registry{}
	for k, v := range r {
		clone[k] = v
	}
	return clone
}

// CheckHealth of backend servers in the registry concurrently, up to 10 at a
// time. If an unexpected error is returned during any of the checks,
// CheckHealth immediately exits, reporting that error.
func (r *ReverseProxy) CheckHealth(client *http.Client) {
	checks := []*healthCheck{}
	regClone := r.reg.clone()
	changed := false
	r.mu.RLock()
	for host, frontend := range regClone {
		if frontend.HealthPath == "" {
			frontend.liveBackends = frontend.Backends
			continue
		}
		changed = true
		frontend.liveBackends = []string{}
		for _, ip := range frontend.Backends {
			checks = append(checks, &healthCheck{
				host:       host,
				ip:         ip,
				healthPath: frontend.HealthPath,
			})
		}
	}
	r.mu.RUnlock()
	max := 10
	if len(checks) < max {
		max = len(checks)
	}
	jobCh := make(chan *healthCheck, max)
	resultCh := make(chan *healthCheck)
	for i := 0; i < max; i++ {
		go ping(jobCh, resultCh)
	}
	for _, check := range checks {
		jobCh <- check
	}
	for i := 0; i < len(checks); i++ {
		checks[i] = <-resultCh
	}
	close(jobCh)
	for _, check := range checks {
		if check.err != nil {
			log.Printf("check health: %s failed: %s\n", check.ip, check.err)
			continue
		}
		host := regClone[check.host]
		host.liveBackends = append(host.liveBackends, check.ip)
		log.Printf("check health: %s 200 OK\n", check.ip)
	}
	if changed {
		r.UpdateRegistry(regClone)
	}
}

// UpdateRegistry for the reverse proxy with new frontends, backends, and
// health checks.
func (r *ReverseProxy) UpdateRegistry(reg Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reg = reg
	r.rp.Transport = newTransport(reg)
}

func ping(jobCh, resultCh chan *healthCheck) {
	for job := range jobCh {
		target := "http://" + job.ip + job.healthPath
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			job.err = errors.Wrap(err, "new request")
			resultCh <- job
			continue
		}
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			job.err = errors.Wrap(err, "do")
			resultCh <- job
			continue
		}
		if err = resp.Body.Close(); err != nil {
			job.err = errors.Wrap(err, "close resp body")
			resultCh <- job
			continue
		}
		if resp.StatusCode != http.StatusOK {
			job.err = fmt.Errorf("expected status code 200, got %d",
				resp.StatusCode)
			resultCh <- job
			continue
		}
		resultCh <- job
	}
}

func newTransport(reg Registry) http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: func(network, addr string) (net.Conn, error) {
			endpoints := reg[addr].liveBackends
			if len(endpoints) == 0 {
				return nil, fmt.Errorf("no live backend for %s", addr)
			}
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

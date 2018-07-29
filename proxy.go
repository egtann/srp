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
)

// ReverseProxy maps frontend hosts to backends. If HealthPath is set in the
// config.json file, ReverseProxy checks the health of backend servers
// periodically and automatically removes them from rotation until health
// checks pass.
type ReverseProxy struct {
	rp       httputil.ReverseProxy
	reg      Registry
	jobCh    chan *healthCheck
	resultCh chan *healthCheck
	mu       sync.RWMutex
	log      Logger
}

// Registry maps hosts to backends with other helpful info, such as
// healthchecks.
type Registry map[string]*backend

type backend struct {
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
		req.Header.Set("X-Real-IP", req.RemoteAddr)
		log.Printf("%s requested %s %s", req.RemoteAddr, req.Method, req.Host)
	}
	transport := newTransport(reg)
	rp := httputil.ReverseProxy{Director: director, Transport: transport}
	jobCh := make(chan *healthCheck)
	resultCh := make(chan *healthCheck)
	for i := 0; i < 10; i++ {
		go func(jobCh <-chan *healthCheck, resultCh chan<- *healthCheck) {
			for job := range jobCh {
				job.err = ping(job)
				resultCh <- job
			}
		}(jobCh, resultCh)
	}
	return &ReverseProxy{
		rp:       rp,
		log:      log,
		reg:      reg,
		jobCh:    jobCh,
		resultCh: resultCh,
	}
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
		return nil, fmt.Errorf("read config file %q: %s", filename, err)
	}
	reg := Registry{}
	err = json.Unmarshal(byt, &reg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal config: %s", err)
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

func (r *ReverseProxy) cloneRegistry() Registry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clone := make(Registry, len(r.reg))
	for host, fe := range r.reg {
		cfe := &backend{
			HealthPath: fe.HealthPath,
			Backends:   make([]string, len(fe.Backends)),
		}
		for i, be := range fe.Backends {
			cfe.Backends[i] = be
		}
		clone[host] = cfe
	}
	return clone
}

// CheckHealth of backend servers in the registry concurrently, and update the
// registry so requests are only routed to healthy servers.
func (r *ReverseProxy) CheckHealth() error {
	checks := []*healthCheck{}
	regClone := r.cloneRegistry()
	for host, frontend := range regClone {
		if frontend.HealthPath == "" {
			frontend.liveBackends = frontend.Backends
			continue
		}
		frontend.liveBackends = []string{}
		for _, ip := range frontend.Backends {
			checks = append(checks, &healthCheck{
				host:       host,
				ip:         ip,
				healthPath: frontend.HealthPath,
			})
		}
	}
	if len(checks) == 0 {
		return nil
	}
	go func() {
		for _, check := range checks {
			r.jobCh <- check
		}
	}()
	for i := 0; i < len(checks); i++ {
		check := <-r.resultCh
		if check.err != nil {
			log.Printf("check health: %s failed: %s\n", check.ip, check.err)
			continue
		}
		host := regClone[check.host]
		host.liveBackends = append(host.liveBackends, check.ip)
		log.Printf("check health: %s 200 OK\n", check.ip)
	}
	r.UpdateRegistry(regClone)
	return nil
}

// UpdateRegistry for the reverse proxy with new frontends, backends, and
// health checks.
func (r *ReverseProxy) UpdateRegistry(reg Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reg = reg
	r.rp.Transport = newTransport(reg)
}

func ping(job *healthCheck) error {
	target := "http://" + job.ip + job.healthPath
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return fmt.Errorf("new request: %s", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %s", err)
	}
	if err = resp.Body.Close(); err != nil {
		return fmt.Errorf("close resp body: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d",
			resp.StatusCode)
	}
	return nil
}

func newTransport(reg Registry) http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: func(network, addr string) (net.Conn, error) {
			// Trim training ":80"
			if len(addr) <= 3 {
				return nil, fmt.Errorf("invalid address %q", addr)
			}
			addrShort := addr[:len(addr)-3]
			host, ok := reg[addrShort]
			if !ok {
				return nil, fmt.Errorf("no host for %s", addr)
			}
			endpoints := host.liveBackends
			if len(endpoints) == 0 {
				return nil, fmt.Errorf("no live backend for %s", addr)
			}
			randInt := rand.Int()
			endpoint := endpoints[randInt%len(endpoints)]
			conn, err := net.Dial(network, endpoint+":80")
			if len(endpoints) < 2 || err == nil {
				return conn, err
			}
			// Retry on other endpoints if there are multiple
			endpoint = endpoints[(randInt+1)%len(endpoints)]
			conn, err = net.Dial(network, endpoint+":80")
			if len(endpoints) < 3 || err == nil {
				return conn, err
			}
			endpoint = endpoints[(randInt+2)%len(endpoints)]
			return net.Dial(network, endpoint+":80")
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
}

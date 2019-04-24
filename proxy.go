package srp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/xid"
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
	ReqPrintf(reqID, format string, vals ...interface{})
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
		reqID := req.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = xid.New().String()
			req.Header.Set("X-Request-ID", reqID)
		}
		log.ReqPrintf(reqID, "%s requested %s %s", req.RemoteAddr, req.Method, req.Host)
	}
	transport := newTransport(reg)
	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		msg := fmt.Sprintf("http: proxy error: %s %s: %v", r.Method, r.URL, err)
		w.Write([]byte(msg))
	}
	rp := httputil.ReverseProxy{
		Director:     director,
		Transport:    transport,
		ErrorHandler: errorHandler,
	}
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

func newRegistry(r io.Reader) (Registry, error) {
	byt, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
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

// NewRegistry for a given configuration file. This reports an error if any
// frontend host has no backends.
func NewRegistry(filename string) (Registry, error) {
	fi, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %s", filename, err)
	}
	defer fi.Close()
	return newRegistry(fi)
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
	return cloneRegistryNoLock(r.reg)
}

// cloneRegistryNoLock returns a duplicate registry without acquiring locks.
// Only to be used on existing clones within a single thread or where locking
// is provided outside the function.
func cloneRegistryNoLock(reg Registry) Registry {
	clone := make(Registry, len(reg))
	for host, fe := range reg {
		cfe := &backend{
			HealthPath: fe.HealthPath,
			Backends:   make([]string, len(fe.Backends)),
		}
		copy(cfe.Backends, fe.Backends)
		clone[host] = cfe
	}
	return clone

}

// CheckHealth of backend servers in the registry concurrently, and update the
// registry so requests are only routed to healthy servers.
func (r *ReverseProxy) CheckHealth() error {
	checks := []*healthCheck{}
	origReg := r.cloneRegistry()
	newReg := cloneRegistryNoLock(origReg)
	for host, frontend := range newReg {
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
			r.log.Printf("check health: %s failed: %s", check.ip, check.err)
			continue
		}
		host := newReg[check.host]
		host.liveBackends = append(host.liveBackends, check.ip)
		r.log.Printf("check health: %s 200 OK", check.ip)
	}

	// Determine if the registry changed. If it's the same as before, we
	// can exit early.
	if !diff(origReg, newReg) {
		return nil
	}

	// UpdateRegistry acquires a stop-the-world write lock, so we only call
	// it when the new registry differs from the last one.
	r.UpdateRegistry(newReg)
	return nil
}

func diff(reg1, reg2 Registry) bool {
	for key := range reg1 {
		// Exit quickly if lengths are different
		if len(reg1[key].liveBackends) != len(reg2[key].liveBackends) {
			return true
		}

		// Sort our live backends to get better performance when
		// diffing the live backends.
		sort.Slice(reg1[key].liveBackends, func(i, j int) bool {
			return reg1[key].liveBackends[i] < reg1[key].liveBackends[j]
		})
		sort.Slice(reg2[key].liveBackends, func(i, j int) bool {
			return reg2[key].liveBackends[i] < reg2[key].liveBackends[j]
		})

		// Compare the two and exit on the first different string
		for i, ip := range reg1[key].liveBackends {
			if reg2[key].liveBackends[i] != ip {
				return true
			}
		}
	}
	return false
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
	req.Header.Add("X-Role", "srp")
	client := cleanhttp.DefaultClient()
	client.Timeout = 10 * time.Second
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
	transport := cleanhttp.DefaultTransport()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = func(
		ctx context.Context,
		network, addr string,
	) (net.Conn, error) {
		// Trim trailing port, if any
		addrShort := strings.SplitN(addr, ":", 2)[0]
		host, ok := reg[addrShort]
		if !ok {
			return nil, fmt.Errorf("no host for %s", addr)
		}
		endpoints := host.liveBackends
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("no live backend for %s", addr)
		}
		return retryDial(network, endpoints, 3)
	}
	return transport
}

func retryDial(network string, endpoints []string, tries int) (net.Conn, error) {
	var err error
	randInt := rand.Int()
	for i := 0; i < min(tries, len(endpoints)); i++ {
		var conn net.Conn
		endpoint := endpoints[(randInt+i)%len(endpoints)]
		conn, err = net.Dial(network, endpoint+":80")
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("failed dial: %s", err.Error())
}

func min(i1, i2 int) int {
	if i1 <= i2 {
		return i1
	}
	return i2
}

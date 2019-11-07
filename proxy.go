package srp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/rs/xid"
)

// ReverseProxy maps frontend hosts to backends. If HealthPath is set in the
// config.json file, ReverseProxy checks the health of backend servers
// periodically and automatically removes them from rotation until health
// checks pass.
type ReverseProxy struct {
	rp       httputil.ReverseProxy
	reg      *Registry
	jobCh    chan *healthCheck
	resultCh chan *healthCheck
	mu       sync.RWMutex
	log      Logger
}

// Registry maps hosts to backends with other helpful info, such as
// healthchecks.
type Registry struct {
	// Services maps hostnames to one of the following:
	//
	// * IPs with optional healthcheck paths, OR
	// * A redirect to another hostname
	Services map[string]*backend

	// API restricts internal API access to a subnet, which should be an
	// private LAN.
	API struct{ Subnet string }
}

// redirect describes how SRP should redirect to another host.
type redirect struct {
	// URL to which SRP should redirect. If DiscardPath is false (the
	// default), the URL's path will be overwritten.
	URL string

	// url is the parsed form of URL.
	url *url.URL

	// Permanent indicates whether the client should redirect itself in
	// future requests. By default the redirect is temporary.
	Permanent bool

	// DiscardPath will strip any path for the URL while redirecting. By
	// default the path is preserved.
	DiscardPath bool
}

type backend struct {
	HealthPath   string
	Backends     []string
	liveBackends []string

	// Redirect from a given hostname to another. If provided, HealthPath
	// and Backends MUST be empty.
	Redirect *redirect
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
func NewProxy(log Logger, reg *Registry) *ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		req.Header.Set("X-Real-IP", req.RemoteAddr)
		reqID := req.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = xid.New().String()
			req.Header.Set("X-Request-ID", reqID)
		}
		log.ReqPrintf(reqID, "%s requested %s %s", req.RemoteAddr,
			req.Method, req.Host)
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

func (r *ReverseProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Handle redirects before proxying. Non-existent host errors will be
	// handled by the reverse proxy, so we don't need to handle them here.
	host, ok := r.reg.Services[req.Host]
	if ok && host.Redirect != nil {
		doRedirect(w, req, host.Redirect)
		return
	}
	r.rp.ServeHTTP(w, req)
}

func doRedirect(w http.ResponseWriter, r *http.Request, rdr *redirect) {
	uri := rdr.url
	if rdr.DiscardPath {
		uri.Path = ""
	} else {
		uri.Path = r.URL.Path
	}
	code := http.StatusTemporaryRedirect
	if rdr.Permanent {
		code = http.StatusPermanentRedirect
	}
	http.Redirect(w, r, uri.String(), code)
}

func newRegistry(r io.Reader) (*Registry, error) {
	byt, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	reg := &Registry{}
	err = json.Unmarshal(byt, reg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	for host, v := range reg.Services {
		if host == "" {
			return nil, errors.New("host cannot be empty")
		}
		if v.Redirect != nil {
			if v.Redirect.URL == "" {
				return nil, fmt.Errorf("%s: URL cannot be empty", host)
			}
			if len(v.Backends) > 0 {
				return nil, fmt.Errorf("%s: Backends must be empty for redirect", host)
			}
			if v.HealthPath != "" {
				return nil, fmt.Errorf("%s: HealthPath must be empty for redirect", host)
			}
			v.Redirect.url, err = url.Parse(v.Redirect.URL)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w",
					v.Redirect.URL, err)
			}
			continue
		}
		if len(v.Backends) == 0 {
			return nil, fmt.Errorf("%s: Backends cannot be empty", host)
		}
	}
	return reg, nil
}

// NewRegistry for a given configuration file. This reports an error if any
// frontend host has no backends.
func NewRegistry(filename string) (*Registry, error) {
	fi, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filename, err)
	}
	defer fi.Close()
	return newRegistry(fi)
}

// Hosts for the registry suitable for generating HTTPS certificates. This
// automatically removes *.internal domains.
func (r *Registry) Hosts() []string {
	hosts := []string{}
	for k := range r.Services {
		if !strings.HasSuffix(k, ".internal") {
			hosts = append(hosts, k)
		}
	}
	return hosts
}

func (r *ReverseProxy) cloneRegistry() *Registry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return cloneRegistryNoLock(r.reg)
}

// cloneRegistryNoLock returns a duplicate registry without acquiring locks.
// Only to be used on existing clones within a single thread or where locking
// is provided outside the function.
func cloneRegistryNoLock(reg *Registry) *Registry {
	clone := &Registry{
		Services: make(map[string]*backend, len(reg.Services)),
		API:      reg.API,
	}
	for host, fe := range reg.Services {
		cfe := &backend{
			Redirect:     fe.Redirect,
			HealthPath:   fe.HealthPath,
			Backends:     make([]string, len(fe.Backends)),
			liveBackends: make([]string, len(fe.liveBackends)),
		}
		copy(cfe.Backends, fe.Backends)
		copy(cfe.liveBackends, fe.liveBackends)
		clone.Services[host] = cfe
	}
	return clone
}

// CheckHealth of backend servers in the registry concurrently, and update the
// registry so requests are only routed to healthy servers.
func (r *ReverseProxy) CheckHealth() error {
	checks := []*healthCheck{}
	origReg := r.cloneRegistry()
	newReg := cloneRegistryNoLock(origReg)
	for host, frontend := range newReg.Services {
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
		host := newReg.Services[check.host]
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

func diff(reg1, reg2 *Registry) bool {
	for key := range reg1.Services {
		// Exit quickly if lengths are different
		lb1 := reg1.Services[key].liveBackends
		lb2 := reg2.Services[key].liveBackends
		if len(lb1) != len(lb2) {
			return true
		}

		// Sort our live backends to get better performance when
		// diffing the live backends.
		sort.Slice(lb1, func(i, j int) bool { return lb1[i] < lb1[j] })
		sort.Slice(lb2, func(i, j int) bool { return lb2[i] < lb2[j] })

		// Compare the two and exit on the first different string
		for i, ip := range lb1 {
			if lb2[i] != ip {
				return true
			}
		}
	}
	return false
}

// UpdateRegistry for the reverse proxy with new frontends, backends, and
// health checks.
func (r *ReverseProxy) UpdateRegistry(reg *Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.reg = reg
	r.rp.Transport = newTransport(reg)
}

func ping(job *healthCheck) error {
	target := "http://" + job.ip + job.healthPath
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Add("X-Role", "srp")
	client := cleanhttp.DefaultClient()
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	if err = resp.Body.Close(); err != nil {
		return fmt.Errorf("close resp body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d",
			resp.StatusCode)
	}
	return nil
}

func newTransport(reg *Registry) http.RoundTripper {
	transport := cleanhttp.DefaultTransport()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = func(
		ctx context.Context,
		network, addr string,
	) (net.Conn, error) {
		hostNoPort, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("split host port: %w", err)
		}
		host, ok := reg.Services[hostNoPort]
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
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			host = endpoint
			port = "80"
		}
		conn, err = net.Dial(network, net.JoinHostPort(host, port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("failed dial: %w", err)
}

func min(i1, i2 int) int {
	if i1 <= i2 {
		return i1
	}
	return i2
}

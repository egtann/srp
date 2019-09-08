package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/egtann/srp"
	"golang.org/x/crypto/acme/autocert"
)

const timeout = 30 * time.Second

func main() {
	portTmp := flag.String("p", "3000", "port")
	config := flag.String("c", "config.json", "config file")
	sslURL := flag.String("url", "", "enable ssl on the proxy's url (optional)")
	flag.Usage = func() {
		usage([]string{})
	}
	flag.Parse()
	issues := []string{}
	port := strings.TrimLeft(*portTmp, ":")
	portInt, err := strconv.Atoi(port)
	if err != nil {
		issues = append(issues, "port must be an integer")
	}
	if portInt < 0 {
		issues = append(issues, "port cannot be negative")
	}
	var selfURL *url.URL
	if len(*sslURL) > 0 {
		selfURL, err = url.ParseRequestURI(*sslURL)
		if err != nil {
			issues = append(issues, "invalid url")
		}
	}
	reg, err := srp.NewRegistry(*config)
	if err != nil {
		issues = append(issues, err.Error())
	}
	if len(issues) > 0 {
		usage(issues)
		os.Exit(1)
	}
	rand.Seed(time.Now().UnixNano())
	proxy := srp.NewProxy(&logger{}, reg)

	// Set up the API only if Subnet is configured and the internal
	// IP of the SRP server can be determined.
	srv := &http.Server{
		// TODO(egtann) wrap proxy to allow API requests over the
		// whitelisted subnet
		Handler:        proxy,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		MaxHeaderBytes: 1 << 20,
	}
	if len(*sslURL) > 0 {
		hosts := append(reg.Hosts(), selfURL.Host)
		m := &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("get cert for %s", hello.ServerName)
			cert, err := m.GetCertificate(hello)
			if err != nil {
				log.Println("failed to get cert:", err)
			}
			return cert, err
		}
		srv.TLSConfig = &tls.Config{GetCertificate: getCert}
		apiHandler, err := proxy.RedirectHTTPHandler()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			err = http.ListenAndServe(":80", m.HTTPHandler(apiHandler))
			if err != nil {
				log.Fatal(fmt.Printf("listen and serve: %s", err))
			}
		}()
		port = "443"
		srv.Addr = ":443"
		go func() {
			log.Println("serving tls")
			if err = srv.ListenAndServeTLS("", ""); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		srv.Addr = ":" + port
		go func() {
			if err = srv.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
	}
	log.Println("listening on", port)
	if err = proxy.CheckHealth(); err != nil {
		log.Println("check health", err)
	}
	sighupCh := make(chan bool)
	go hotReloadConfig(*config, proxy, sighupCh)
	go checkHealth(proxy, sighupCh)
	gracefulRestart(srv, timeout)
}

// logger implements the srp.Logger interface.
type logger struct{}

func (l *logger) Printf(format string, vals ...interface{}) {
	log.Printf(format, vals...)
}

func (l *logger) ReqPrintf(reqID, format string, vals ...interface{}) {
	log.Printf(reqID+": "+format, vals...)
}

// checkHealth of backend servers constantly. We cancel the current health
// check when the reloaded channel receives a message, so a new health check
// with the new registry can be started.
func checkHealth(proxy *srp.ReverseProxy, sighupCh <-chan bool) {
	for {
		select {
		case <-time.After(3 * time.Second):
			err := proxy.CheckHealth()
			if err != nil {
				log.Println("check health", err)
			}
		case <-sighupCh:
			return
		}
	}
}

// hotReloadConfig listens for a reload signal (sighup), then reloads the
// registry from the config file. This recursively calls itself, so it can
// handle the signal multiple times.
func hotReloadConfig(
	filename string,
	proxy *srp.ReverseProxy,
	sighupCh chan bool,
) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGHUP)
	<-stop

	log.Println("reloading config...")
	reg, err := srp.NewRegistry(filename)
	if err != nil {
		log.Fatal(err)
	}
	proxy.UpdateRegistry(reg)
	log.Println("reloaded config")
	sighupCh <- true
	go checkHealth(proxy, sighupCh)
	hotReloadConfig(filename, proxy, sighupCh)
}

// gracefulRestart listens for an interupt or terminate signal. When either is
// received, it stops accepting new connections and allows all existing
// connections up to 10 seconds to complete. If connections do not shut down in
// time, this exits with 1.
func gracefulRestart(srv *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Println("failed to shutdown server gracefully", err)
		os.Exit(1)
	}
	log.Println("shut down")
}

func usage(issues []string) {
	fmt.Print(`usage:

    srp [options...]

global options:

    [-p]    port, default "3000"
    [-c]    config file, default "config.json"
    [-url]  url of the reverse proxy for https

config file:

    The config file contains JSON that maps your frontend hosts to backends. It
    needs to be defined. For example:

    {
        "127.0.0.1:3000": {
	    "HealthPath": "/health",
	    "Backends": [
                "127.0.0.1:3001",
                "127.0.0.1:3002"
	    ]
	}
    }

    Available options for each frontend are: HealthPath, Backends.

    If HealthPath is provided, SRP will check the health of the backend servers
    every few seconds and remove any from rotation until they come back online.

notes:

    * The url flag is optional. If provided, srp will use https. If not
      provided (such as when testing on 127.0.0.1), srp will use http.

    * After terminating TLS, SRP communicates over HTTP (plaintext) to the
      backend servers. Some cloud providers automatically encrypt traffic over
      their internal IP network (including Google Cloud). Check to ensure that
      your cloud provider does this before using SRP in production.

`)
	if len(issues) > 0 {
		fmt.Printf("errors:\n\n")
		for _, issue := range issues {
			fmt.Println("    " + issue)
		}
	}
}

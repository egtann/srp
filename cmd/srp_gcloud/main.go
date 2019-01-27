package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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
	"github.com/egtann/srp/gcloud/cache"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/acme/autocert"
)

const timeout = 30 * time.Second

func main() {
	portTmp := flag.String("p", "3000", "port")
	config := flag.String("c", "config.json", "config file")
	sslURL := flag.String("url", "", "enable ssl on the proxy's url (optional)")
	bucket := flag.String("b", "", "google bucket for tls certs")
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
	if *bucket == "" {
		issues = append(issues, "bucket cannot be empty")
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

	zerolog.TimeFieldFormat = "" // Unix format
	zerolog.TimestampFieldName = "ts"
	zerolog.MessageFieldName = "msg"
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()
	proxy := srp.NewProxy(&logger{log: log}, reg)
	srv := &http.Server{
		Handler:        proxy,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		MaxHeaderBytes: 1 << 20,
	}
	if len(*sslURL) > 0 {
		hosts := append(reg.Hosts(), selfURL.Host)
		log.Info().Strs("hosts", hosts).Msg("got hosts")
		c, err := cache.New(log, *bucket)
		if err != nil {
			log.Fatal().Err(err).Msg("new cache")
		}
		m := &autocert.Manager{
			Cache:      c,
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// log.Info().Str("server", hello.ServerName).Msg("get cert")
			cert, err := m.GetCertificate(hello)
			if err != nil {
				log.Info().Err(err).Msg("failed to get cert")
			}
			return cert, err
		}
		srv.TLSConfig = &tls.Config{GetCertificate: getCert}
		go func() {
			err = http.ListenAndServe(":http", m.HTTPHandler(nil))
			if err != nil {
				log.Fatal().Err(err).Msg("listen and serve http")
			}
		}()
		port = "443"
		srv.Addr = ":https"
		go func() {
			log.Info().Msg("serving tls")
			if err = srv.ListenAndServeTLS("", ""); err != nil {
				log.Fatal().Err(err).Msg("listen and serve tls")
			}
		}()
	} else {
		srv.Addr = ":" + port
		go func() {
			if err = srv.ListenAndServe(); err != nil {
				log.Fatal().Err(err).Msg("listen and serve")
			}
		}()
	}
	log.Info().Str("port", port).Msg("listening")
	if err = proxy.CheckHealth(); err != nil {
		log.Info().Err(err).Msg("check health")
	}
	sighupCh := make(chan bool)
	go hotReloadConfig(log, *config, proxy, sighupCh)
	go checkHealth(log, proxy, sighupCh)
	gracefulRestart(log, srv, timeout)
}

// logger implements the srp.Logger interface.
type logger struct {
	log zerolog.Logger
}

func (l *logger) Printf(format string, vals ...interface{}) {
	l.log.Info().Msgf(format, vals...)
}

func (l *logger) ReqPrintf(reqID, format string, vals ...interface{}) {
	l.log.Info().Str("req_id", reqID).Msgf(format, vals...)
}

// checkHealth of backend servers constantly. We cancel the current health
// check when the reloaded channel receives a message, so a new health check
// with the new registry can be started.
func checkHealth(
	log zerolog.Logger,
	proxy *srp.ReverseProxy,
	sighupCh <-chan bool,
) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := proxy.CheckHealth()
			if err != nil {
				log.Info().Err(err).Msg("check health")
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
	log zerolog.Logger,
	filename string,
	proxy *srp.ReverseProxy,
	sighupCh chan bool,
) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGHUP)
	<-stop
	log.Info().Msg("reloading config...")
	reg, err := srp.NewRegistry(filename)
	if err != nil {
		log.Fatal().Err(err).Msg("reload registry")
	}
	proxy.UpdateRegistry(reg)
	log.Info().Msg("reloaded config")
	sighupCh <- true
	go checkHealth(log, proxy, sighupCh)
	hotReloadConfig(log, filename, proxy, sighupCh)
}

// gracefulRestart listens for an interupt or terminate signal. When either is
// received, it stops accepting new connections and allows all existing
// connections up to 10 seconds to complete. If connections do not shut down in
// time, this exits with 1.
func gracefulRestart(
	log zerolog.Logger,
	srv *http.Server,
	timeout time.Duration,
) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Info().Err(err).Msg("failed to shutdown server gracefully")
		os.Exit(1)
	}
	log.Info().Msg("shut down")
}

func usage(issues []string) {
	fmt.Print(`usage:

    srp [options...]

global options:

    [-p]    port, default "3000"
    [-c]    config file, default "config.json"
    [-url]  url of the reverse proxy for https
    [-b]    cloud bucket for tls cert storage

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

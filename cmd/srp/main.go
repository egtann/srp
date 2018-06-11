package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/egtann/srp"
	"golang.org/x/crypto/acme/autocert"
)

const timeout = 10 * time.Second

func main() {
	portTmp := flag.String("p", "3000", "port")
	config := flag.String("c", "config.json", "config file")
	sslURL := flag.String("url", "", "enable ssl on the proxy's url (optional)")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	reg, err := srp.NewRegistry(*config)
	if err != nil {
		log.Fatal(err)
	}
	proxy := srp.NewProxy(&Logger{}, reg)

	// Start the proxy using SSL if possible
	var srv *http.Server
	var port string
	if len(*sslURL) > 0 {
		hosts := append(reg.Hosts(), *sslURL)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		go http.ListenAndServe(":http", m.HTTPHandler(nil))
		srv = &http.Server{
			Addr:           ":https",
			Handler:        proxy,
			TLSConfig:      &tls.Config{GetCertificate: m.GetCertificate},
			ReadTimeout:    timeout,
			WriteTimeout:   timeout,
			MaxHeaderBytes: 1 << 20,
		}
		port = "443"
	} else {
		port = strings.TrimLeft(*portTmp, ":")
		srv = &http.Server{
			Addr:           ":" + port,
			Handler:        proxy,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
	}
	go func() {
		log.Println("listening on", port)
		if err = srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	reload := make(chan bool)
	go hotReloadConfig(*config, proxy, reload)
	go checkHealth(proxy, reload)
	gracefulRestart(srv, timeout)
}

// Logger implements the srp.Logger interface.
type Logger struct{}

func (l *Logger) Printf(format string, vals ...interface{}) {
	log.Printf(format, vals...)
}

// checkHealth of backend servers constantly. We cancel the current health
// check when the reloaded channel receives a message, so a new health check
// with the new registry can be started.
func checkHealth(proxy *srp.ReverseProxy, reload <-chan bool) {
	client := &http.Client{Timeout: timeout}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := proxy.CheckHealth(client)
			if err != nil {
				log.Println("failed to check health:", err)
				continue
			}
		case <-reload:
			return
		}
	}
}

// hotReloadConfig listens for a reload signal, then reloads the registry from
// the config file. This recursively calls itself, so it can handle the signal
// multiple times.
func hotReloadConfig(filename string, proxy *srp.ReverseProxy, reload chan bool) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGHUP)
	<-stop
	log.Println("reloading config...")
	reg, err := srp.NewRegistry(filename)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("reloaded config")
	proxy.UpdateRegistry(reg)
	reload <- true
	go checkHealth(proxy, reload)
	hotReloadConfig(filename, proxy, reload)
}

// gracefulRestart listens for an interupt or terminate signal. When either is
// received, it stops accepting new connections and allows all existing
// connections up to 10 seconds to complete. If connections do not shut down in
// time, this exits with 1.
func gracefulRestart(srv *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutdown started")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Println("failed to shutdown server gracefully", err)
		os.Exit(1)
	}
	log.Println("shutdown completed")
}

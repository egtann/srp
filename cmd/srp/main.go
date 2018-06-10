package main

import (
	"crypto/tls"
	"flag"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/egtann/srp"
	"golang.org/x/crypto/acme/autocert"
)

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

	go func() {
		// Check health at boot and constantly
		client := &http.Client{Timeout: 10 * time.Second}
		err := proxy.CheckHealth(client)
		if err != nil {
			log.Println("failed to check health:", err)
		}
		for range time.Tick(time.Second) {
			err := proxy.CheckHealth(client)
			if err != nil {
				log.Println("failed to check health:", err)
				continue
			}
		}
	}()

	// Start the proxy using SSL if possible
	if len(*sslURL) > 0 {
		hosts := append(reg.Hosts(), *sslURL)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		go http.ListenAndServe(":http", m.HTTPHandler(nil))
		s := &http.Server{
			Addr:           ":https",
			Handler:        proxy,
			TLSConfig:      &tls.Config{GetCertificate: m.GetCertificate},
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		log.Println("listening on 443")
		log.Fatal(s.ListenAndServe())
	} else {
		port := strings.TrimLeft(*portTmp, ":")
		log.Println("listening on", port)
		s := &http.Server{
			Addr:           ":" + port,
			Handler:        proxy,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		log.Fatal(s.ListenAndServe())
	}
}

// Logger implements the srp.Logger interface.
type Logger struct{}

func (l *Logger) Printf(format string, vals ...interface{}) {
	log.Printf(format, vals...)
}

// Package banner is a middleware for srp that spots bad actors by analyzing
// access patterns and silently drops their requests.
package banner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/egtann/srp"
	"golang.org/x/time/rate"
)

type Banner struct {
	// lims maps ip addresss to rate limiters. The map is pruned
	// periodically to limit memory usage.
	lims   map[string]*accessor
	limsMu sync.RWMutex

	// bannedIPs records IPs that shouldn't be allowed access.
	bannedIPs   map[string]struct{}
	bannedIPsMu sync.RWMutex

	// maxRPS describes the maximum failed requests per second before
	// triggering a ban.
	maxRPS float64

	// writer keeps an optional persistant record of bans by writing to
	// disk or logs.
	writer   io.Writer
	writerMu sync.Mutex
}

type accessor struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// Record responses with error status codes and the header X-Banner-Cost. It
// strips X-Banner-Cost from the header.
//
// This records failed accesses from each IP, and if any pass a threshold,
// they're banned for 10 minutes.
func (b *Banner) Record(log srp.Logger) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode < 400 {
			return nil
		}

		// Determine cost of infraction. This enables quicker bans for
		// sensitive errors like incorrect API keys, bad logins, and
		// 404s when scanning for vulnerabilities.
		cost := 1
		costHeader := resp.Header.Get("X-Banner-Cost")
		if costHeader != "" {
			var err error
			cost, err = strconv.Atoi(costHeader)
			if err != nil {
				return fmt.Errorf("parse cost: %s", err)
			}
		}
		resp.Header.Del("X-Banner-Cost")

		b.limsMu.RLock()
		acc, ok := b.lims[resp.Request.RemoteAddr]
		b.limsMu.RUnlock()
		now := time.Now()
		if ok {
			log.Printf("record: existing ip %s\n", resp.Request.RemoteAddr)
			acc.lastUsed = now
		} else {
			log.Printf("record: new ip %s\n", resp.Request.RemoteAddr)
			lim := rate.NewLimiter(rate.Limit(b.maxRPS), 3)
			acc = &accessor{
				limiter:  lim,
				lastUsed: now,
			}
			b.limsMu.Lock()
			b.lims[resp.Request.RemoteAddr] = acc
			b.limsMu.Unlock()
		}
		if ok := acc.limiter.AllowN(now, cost); !ok {
			if err := b.ban(resp.Request.RemoteAddr); err != nil {
				return fmt.Errorf("write ban: %s", err)
			}
		}
		return nil
	}
}

// Monitor inbound requests and cancel any from banned IPs.
func (b *Banner) Monitor(log srp.Logger) func(*http.Request) {
	return func(req *http.Request) {
		b.bannedIPsMu.RLock()
		defer b.bannedIPsMu.RUnlock()
		if _, exist := b.bannedIPs[req.RemoteAddr]; exist {
			// This is a banned IP, so cancel the request
			// immediately.
			//
			// TODO is there a better option that doesn't require a
			// custom ReverseProxy implementation or modifying the
			// apps themselves?
			log.Printf("monitor: bad ip %s\n", req.RemoteAddr)
			ctx, cancel := context.WithCancel(req.Context())
			req = req.WithContext(ctx)
			cancel()
			return
		}

		// Good IP
		log.Printf("monitor: good ip %s\n", req.RemoteAddr)
	}
}

func (b *Banner) ban(ip string) error {
	b.bannedIPsMu.Lock()
	b.bannedIPs[ip] = struct{}{}
	b.bannedIPsMu.Unlock()

	if b.writer != nil {
		b.writerMu.Lock()
		defer b.writerMu.Unlock()

		if _, err := b.writer.Write([]byte(ip + "\n")); err != nil {
			return err
		}
	}
	return nil
}

// New banner enforcing a max failed requests per minute.
func New(maxRPM float64) *Banner {
	b := &Banner{
		lims:   map[string]*accessor{},
		maxRPS: maxRPM / 60,
	}
	return b
}

// WithBannedIPs starts the banner with a given state.
func (b *Banner) WithBannedIPs(ips []string) *Banner {
	for _, ip := range ips {
		b.bannedIPs[ip] = struct{}{}
	}
	return b
}

// WithStorage persists banned IP addresses.
func (b *Banner) WithStorage(w io.Writer) *Banner {
	b.writer = w
	return b
}

// WithPruningEvery removes unused limiters to free up memory. It runs every
// given duration and prunes entries that haven't been accessed in 10*dur.
func (b *Banner) WithPruningEvery(dur time.Duration) *Banner {
	tick := time.NewTicker(dur)
	go func() {
		for {
			select {
			case now := <-tick.C:
				b.pruneLimits(now, 10*dur)
			}
		}
	}()
	return b
}

func (b *Banner) pruneLimits(now time.Time, threshold time.Duration) {
	b.limsMu.Lock()
	defer b.limsMu.Unlock()

	for ip, acc := range b.lims {
		if now.After(acc.lastUsed.Add(threshold)) {
			delete(b.lims, ip)
		}
	}
}

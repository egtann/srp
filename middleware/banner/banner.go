// Package banner is a middleware for srp that spots bad actors by analyzing
// access patterns and silently drops their requests.
package banner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/egtann/srp"
	"golang.org/x/time/rate"
)

type Banner struct {
	// counts maps ip addreses to error counts. The map is pruned
	// periodically to limit memory usage.
	counts   map[string]*counter
	countsMu sync.RWMutex

	// blacklist records IPs that shouldn't be allowed access.
	blacklist   map[string]struct{}
	blacklistMu sync.RWMutex

	// white
	whitelist map[string]struct{}

	banThreshold int
	duration     time.Duration

	// writer keeps an optional persistant record of bans by writing to
	// disk or logs.
	writer   io.Writer
	writerMu sync.Mutex
}

type counter struct {
	val       int
	createdAt time.Time
}

// Record responses with error status codes and the header X-Banner. Record
// strips X-Banner from the header.
//
// This records failed accesses from each IP, and if any pass a threshold,
// they're banned for 10 minutes.
func (b *Banner) Record(log srp.Logger) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode < 400 {
			return nil
		}

		b.countsMu.RLock()
		cnt, ok := b.counts[resp.Request.RemoteAddr]
		b.countsMu.RUnlock()
		now := time.Now()
		if ok {
			log.Printf("record: existing ip %s\n", resp.Request.RemoteAddr)
			cnt.val++
		} else {
			log.Printf("record: new ip %s\n", resp.Request.RemoteAddr)
			lim := rate.NewLimiter(rate.Limit(b.maxRPS), 3)
			cnt = &counter{
				val:       1,
				createdAt: now,
			}
			b.countsMu.Lock()
			b.counts[resp.Request.RemoteAddr] = cnt
			b.countsMu.Unlock()
		}
		if ok := cnt.limiter.AllowN(now, cost); !ok {
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
		b.blacklistMu.RLock()
		defer b.blacklistMu.RUnlock()
		if _, exist := b.blacklist[req.RemoteAddr]; !exist {
			// Good IP
			log.Printf("monitor: good ip %s\n", req.RemoteAddr)
			return
		}

		// This is a banned IP, so cancel the request immediately.
		//
		// TODO is there a better option that doesn't require a custom
		// ReverseProxy implementation or modifying the apps
		// themselves?
		log.Printf("monitor: bad ip %s\n", req.RemoteAddr)
		ctx, cancel := context.WithCancel(req.Context())
		req = req.WithContext(ctx)
		cancel()
	}
}

func (b *Banner) ban(ip string) error {
	b.blacklistMu.Lock()
	b.blacklist[ip] = struct{}{}
	b.blacklistMu.Unlock()

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
func New(banThreshold int, dur time.Duration) *Banner {
	b := &Banner{
		counts:       map[string]*counter{},
		banThreshold: banThreshold,
		duration:     dur,
	}
	return b
}

// WithBlacklist starts the banner with a given state of banned IPs.
func (b *Banner) WithBlacklist(ips []string) *Banner {
	for _, ip := range ips {
		b.blacklist[ip] = struct{}{}
	}
	return b
}

// WithStorage persists banned IP addresses.
func (b *Banner) WithStorage(w io.Writer) *Banner {
	b.writer = w
	return b
}

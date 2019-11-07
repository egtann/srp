# SRP

SRP stands for Simple Reverse Proxy. It does what it says on the tin, and not a
whole lot more.

**Warning: this is alpha quality software and not ready for production.**

## Features

* Proxy requests from a host to one of many backend IPs/ports
* Redirection to and from hosts
* Automate HTTPS with TLS termination
* Load balance using a simple algorithm
* Check health automatically
* API to retrieve healthy services
* Live reloaded config file

And nothing else.

## Installing

```bash
go get github.com/egtann/srp/cmd/srp
```

Then run `srp -h` for usage help.

## Config file format

The config file has two main parts:

1. Services maps requests to backend services.
1. API restricts access via an IP subnet.

```json
{
	"Services": {
		"www.example.com": {
			"HealthPath": "/health",
			"Backends": [
				"127.0.0.1:3001",
				"127.0.0.1:3002",
				"127.0.0.1:3003",
				"127.0.0.1:3004",
				"127.0.0.1:3005"
			]
		},
		"example.com": {
			"Redirect": {
				"URL": "https://www.example.com",
				"StatusCode": 301
			}
		}
	},
	"API": {
		"Subnet": "10.0.0.0/24"
	}
}
```

## Automatic healthchecks

If you provide a `HealthPath` in the config file, SRP will check the health of
your servers every few seconds and stop sending requests to any that fail until
the health checks start succeeding. Additionally, if any single request fails,
SRP will try that same request again using a different backend (3 tries max).

## API

SRP includes a simple API to retrieve each services' healthy backends. Combined
with something like github.com/egtann/lanhttp, the API enables your apps to
communicate over an internal network, rather than through the public internet,
without re-configuring your servers or modifying DNS.

By default the API is disabled. When configured with `Subnet`, the API responds
to `/services` over the appropriate subnet with JSON resembling the following:

```
{
	"www.example.internal": {
		"HealthPath": "/health",
		"Backends": [
			"10.0.0.1:3000",
			"10.0.0.2:3000"
		]
	}
}
```

Only the healthy IPs will be returned in the API.

lanhttp or similar can help you periodically call this API to update healthy
IPs and route *.internal traffic directly to the live IPs, skipping SRP
entirely, to keep chatty internal networks from impacting the performance of
SRP.

## Why build SRP?

Complexity doesn't belong in the infrastructure layer. When something goes
wrong at this level, it can be catastrophic. You need to diagnose the issue
quickly and deliver a fix in minutes to meet your SLAs. A small, simple and
well-tested codebase is the only way to achieve that.

HAProxy, Nginx, and Apache are very complex, which is far beyond the need of
most projects. Several new Go-based reverse proxies that use autocert, such as
Traefik and Caddy, are very large and complex as well, with plenty of
opportunity for bugs.

Instead, SRP keeps it simple. There's a much smaller surface for bugs. It's
easier and faster to debug if issues occur (especially nice when they occur in
production and you need to roll out a fix quickly).

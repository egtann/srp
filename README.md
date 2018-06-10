# SRP

SRP stands for Simple Reverse Proxy. It does what it says on the tin, and not a
whole lot more.

**Warning: this is alpha quality software and not ready for production.**

## Features

* Proxy requests from a host to one of many backend IPs/ports
* Automate HTTPS with TLS termination
* Load balance using a simple algorithm
* Check health automatically
* Live reloaded config file

And nothing else.

## Installing

```bash
go get github.com/egtann/srp/cmd/srp
```

Then run `srp -h` for usage help.

## Config file format

The config file maps requests to backend services.

```json
{
	"127.0.0.1:3000": {
		"HealthPath": "/health",
		"Backends": [
			"127.0.0.1:3001",
			"127.0.0.1:3002",
			"127.0.0.1:3003",
			"127.0.0.1:3004",
			"127.0.0.1:3005"
		]
	}
}
```

## Automatic healthchecks

If you provide a `HealthPath` in the config file, SRP will check the health of
your servers every few seconds and stop sending requests to any that fail until
the health checks start succeeding. Additionally, if any single request fails,
SRP will try that same request again using a different backend (3 tries max).

## Why build SRP?

HAProxy, Nginx, Apache, etc. don't do automatic HTTPS. They're also very
complex, which is far beyond the need of most projects. Several new Go-based
reverse proxies that use autocert, such as Traefik and Caddy, are very large
and complex as well, with plenty of opportunity for bugs.

Instead, SRP keeps it simple. There's a much smaller surface for bugs. It's
easier and faster to debug if issues occur (especially nice when they occur in
production and you need to roll out a fix quickly).

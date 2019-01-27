// Package cache manages autocert certificates in Google Cloud Storage. It's
// based on this:
//
// https://github.com/kelseyhightower/gcscache/blob/be47e5be6f2bc26b0d2239c1d915498c78ee6f3d/cache.go
//
// However this version uses the passed-in context.
package cache

import (
	"context"
	"io/ioutil"

	"cloud.google.com/go/storage"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/acme/autocert"
)

// Cache implements the autocert.Cache interface using Google Cloud Storage.
type Cache struct {
	client *storage.Client
	bucket string
	log    zerolog.Logger
}

// New creates and initializes a new Cache backed by the given Google Cloud
// Storage bucket.
func New(log zerolog.Logger, bucket string) (*Cache, error) {
	client, err := storage.NewClient(context.Background())
	if err != nil {
		return nil, err
	}
	c := &Cache{
		client: client,
		bucket: bucket,
		log:    log,
	}
	return c, nil
}

// Get certificate data from the specified object name.
func (c *Cache) Get(ctx context.Context, name string) ([]byte, error) {
	clog := c.log.With().Str("name", name).Logger()
	// clog.Info().Msg("get cert")
	r, err := c.client.Bucket(c.bucket).Object(name).NewReader(ctx)
	if err == storage.ErrObjectNotExist {
		clog.Info().Msg("cache miss")
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		clog.Info().Err(err).Msg("failed to get cert")
		return nil, err
	}
	// clog.Info().Msg("reading cert")
	defer r.Close()
	return ioutil.ReadAll(r)
}

// Put the certificate data to the specified object name.
func (c *Cache) Put(ctx context.Context, name string, data []byte) error {
	c.log.Info().Str("name", name).Msg("putting cert")
	w := c.client.Bucket(c.bucket).Object(name).NewWriter(ctx)
	w.Write(data)
	return w.Close()
}

// Delete the specified object name.
func (c *Cache) Delete(ctx context.Context, name string) error {
	clog := c.log.With().Str("name", name).Logger()
	clog.Info().Msg("deleting cert")
	o := c.client.Bucket(c.bucket).Object(name)
	err := o.Delete(ctx)
	if err == storage.ErrObjectNotExist {
		clog.Info().Msg("cert does not exist")
		return nil
	}
	return err
}

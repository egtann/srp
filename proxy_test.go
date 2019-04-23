package srp

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func BenchmarkServeHTTP(b *testing.B) {
	content := `{
		"frontend": {
			"HealthPath": "/health",
			"Backends": ["1", "2"]
		}
	}`
	reg, err := newRegistry(bytes.NewBufferString(content))
	if err != nil {
		panic(err)
	}
	proxy := NewProxy(noopLogger{}, reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		proxy.ServeHTTP(w, r)
	}
}

type noopLogger struct{}

func (n noopLogger) Printf(format string, vals ...interface{})           {}
func (n noopLogger) ReqPrintf(reqID, format string, vals ...interface{}) {}

package config

import (
	"net/url"
	"strings"
	"testing"

	"github.com/bmizerany/assert"
)

func testOptions() *Options {
	o := newOptions()
	o.Upstreams = []string{"http://127.0.0.1:8080"}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := newOptions()
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: upstream",
	})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())
}

func TestProxyURLs(t *testing.T) {
	o := testOptions()
	t.Logf("%#v / %#v", o.Upstreams, o.ProxyURLs)
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8081")
	assert.Equal(t, nil, o.Validate())
	t.Logf("%#v / %#v", o.Upstreams, o.ProxyURLs)
	expected := []*url.URL{
		&url.URL{Scheme: "http", Host: "127.0.0.1:8080", Path: "/"},
		// note the '/' was added
		&url.URL{Scheme: "http", Host: "127.0.0.1:8081", Path: "/"},
	}
	assert.Equal(t, expected, o.ProxyURLs)
}

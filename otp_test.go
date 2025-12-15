package otp_test

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/ghosind/go-assert"
)

func URLsEqual(a *assert.Assertion, ua, ub string) {
	na := normalizeURL(a, ua)
	nb := normalizeURL(a, ub)

	a.DeepEqualNow(na, nb)
}

func normalizeURL(a *assert.Assertion, u string) *url.URL {
	n, err := url.Parse(u)
	if err != nil {
		a.Fatalf("failed to parse url %s: %v", u, err)
		return nil
	}

	n.Scheme = strings.ToLower(n.Scheme)
	n.Host = strings.ToLower(n.Host)

	n.Host = stripDefaultPort(n.Scheme, n.Host)

	if n.Path == "" {
		n.Path = "/"
	}

	q := n.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sorted := url.Values{}
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			sorted.Add(k, v)
		}
	}
	n.RawQuery = sorted.Encode()

	n.Fragment = ""

	return n
}

func stripDefaultPort(scheme, host string) string {
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			if (scheme == "http" && p == "80") ||
				(scheme == "https" && p == "443") {
				return h
			}
		}
	}
	return host
}

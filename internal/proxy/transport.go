package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

func NewDirectTransport(verifyTLS bool, timeout time.Duration) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifyTLS,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:  timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	}
}

func NewTorTransport(socksAddr string, verifyTLS bool, timeout time.Duration) (*http.Transport, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, err
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errSOCKSNoContext
	}

	return &http.Transport{
		DialContext: contextDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifyTLS,
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:  timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       90 * time.Second,
	}, nil
}

package proxy

import "errors"

var (
	errSOCKSNoContext = errors.New("SOCKS5 dialer does not support DialContext")
)

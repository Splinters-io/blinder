// uat-target is a loopback-only synthetic target for manual Blinder acceptance tests.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/Splinters-io/blinder/tests/fixture"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "Loopback fixture address")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("fixture must listen on a loopback IP address")
	}
	log.Printf("Synthetic UAT target at http://%s; credentials: tester / fixture-only", *listen)
	log.Fatal(http.ListenAndServe(*listen, fixture.Handler()))
}

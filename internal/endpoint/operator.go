// Package endpoint defines the reserved local endpoints shared by the proxy,
// operator interface and certificate setup.
package endpoint

import "strings"

// OperatorHost must never be used to serve proxied target content.
const OperatorHost = "blinder-operator.localhost"

// ChallengeSuffix is reserved for isolated, per-challenge content origins.
// It must not be used as a target alias or share the operator origin.
const ChallengeSuffix = "blinder-challenge.localhost"
const ChallengeWildcard = "*." + ChallengeSuffix

// ChallengeExampleHost is a concrete hostname for certificate checks. A
// wildcard SAN is not itself a browser endpoint or an input to VerifyHostname.
const ChallengeExampleHost = "00000000000000000000000000000000." + ChallengeSuffix

// IsChallengeHost reserves the entire namespace, including malformed challenge
// IDs. Callers must separately validate an ID before serving challenge content.
func IsChallengeHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == ChallengeSuffix || strings.HasSuffix(host, "."+ChallengeSuffix)
}

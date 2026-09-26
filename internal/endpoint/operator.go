// Package endpoint defines the reserved local endpoints shared by the proxy,
// operator interface and certificate setup.
package endpoint

// OperatorHost must never be used to serve proxied target content.
const OperatorHost = "blinder-operator.localhost"

package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func paranoidGate() *scrub.Gate {
	return scrub.NewGate(
		[]string{"acmecorp.io"},
		[]string{"AcmeCorp"},
		"alias.local",
	)
}

func TestParanoidPreservesButtonText(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><button>Submit</button><button type="submit">Login</button></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Submit") {
		t.Fatal("paranoid replaced button text 'Submit'")
	}
	if !strings.Contains(got, "Login") {
		t.Fatal("paranoid replaced button text 'Login'")
	}
}

func TestParanoidPreservesLabelText(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><form><label>Username</label><input type="text"><label>Password</label><input type="password"></form></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Username") {
		t.Fatal("paranoid replaced label text 'Username'")
	}
	if !strings.Contains(got, "Password") {
		t.Fatal("paranoid replaced label text 'Password'")
	}
}

func TestParanoidPreservesLegendText(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><fieldset><legend>Account Details</legend><input type="text"></fieldset></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Account Details") {
		t.Fatal("paranoid replaced legend text")
	}
}

func TestParanoidPreservesSummaryText(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><details><summary>Show advanced options</summary><p>Hidden content here</p></details></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Show advanced options") {
		t.Fatal("paranoid replaced summary toggle text")
	}
}

func TestParanoidStillReplacesDisplayText(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><h1>Welcome to our platform</h1><p>700 hands-on security labs for learning web application vulnerabilities</p></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "Welcome to our platform") {
		t.Fatal("paranoid should replace heading text")
	}
	if strings.Contains(got, "700 hands-on") {
		t.Fatal("paranoid should replace paragraph text")
	}
}

func TestParanoidPreservesNestedInteractive(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><button><span>Cancel</span> order</button></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Cancel") {
		t.Fatal("paranoid replaced text inside nested button>span")
	}
	if !strings.Contains(got, "order") {
		t.Fatal("paranoid replaced text inside button")
	}
}

func TestParanoidPreservesOutputElement(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><output>Calculation result</output></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Calculation result") {
		t.Fatal("paranoid replaced output element text")
	}
}

func TestParanoidStillScrubsIdentityInPreservedElements(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><button>Login to AcmeCorp</button><label>AcmeCorp username</label></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "AcmeCorp") {
		t.Fatal("identity token leaked through preserved interactive element")
	}
}

func TestParanoidPreservesMeterAndProgress(t *testing.T) {
	gate := paranoidGate()
	body := []byte(`<html><body><meter value="0.7">70%</meter><progress value="50" max="100">50%</progress></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "70%") {
		t.Fatal("paranoid replaced meter fallback text")
	}
	if !strings.Contains(got, "50%") {
		t.Fatal("paranoid replaced progress fallback text")
	}
}

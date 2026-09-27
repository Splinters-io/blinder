package config

import (
	"testing"

	"github.com/Splinters-io/blinder/internal/endpoint"
)

func TestChallengeAliasNamespaceIsReserved(t *testing.T) {
	for _, alias := range []string{
		endpoint.ChallengeSuffix,
		endpoint.ChallengeExampleHost,
		"nested.invalid." + endpoint.ChallengeSuffix,
		"BLINDER-CHALLENGE.LOCALHOST.",
		"ABCDEF.BLINDER-CHALLENGE.LOCALHOST.",
	} {
		t.Run(alias, func(t *testing.T) {
			_, err := New("https://example.com", "", alias, nil, true, false, false, "", "", 0, "", "", 0, 0)
			if err == nil {
				t.Fatalf("reserved challenge alias accepted: %s", alias)
			}
		})
	}
	for _, alias := range []string{"not-" + endpoint.ChallengeSuffix, endpoint.ChallengeSuffix + ".example", "target.local"} {
		if _, err := New("https://example.com", "", alias, nil, true, false, false, "", "", 0, "", "", 0, 0); err != nil {
			t.Fatalf("unrelated alias %s rejected: %v", alias, err)
		}
	}
}

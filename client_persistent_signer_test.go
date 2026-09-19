package mls

import (
	"bytes"
	"context"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestBasicEd25519SeedRetainsSigningIdentity(t *testing.T) {
	ctx := context.Background()
	identity := []byte("persisted-client")
	firstSeed := bytes.Repeat([]byte{0x45}, 32)
	secondSeed := bytes.Repeat([]byte{0x46}, 32)
	signingKey := func(seed []byte) []byte {
		t.Helper()
		client, err := NewClient(identity, ciphersuite.MLS128DHKEMX25519, WithBasicEd25519Seed(seed))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		groupID, err := client.CreateGroup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		members, err := client.ListMembers(ctx, groupID)
		if err != nil || len(members) != 1 {
			t.Fatalf("members=%d, error=%v", len(members), err)
		}
		return append([]byte(nil), members[0].SigningKey...)
	}
	if !bytes.Equal(signingKey(firstSeed), signingKey(firstSeed)) {
		t.Fatal("same seed changed the client's signing identity")
	}
	if bytes.Equal(signingKey(firstSeed), signingKey(secondSeed)) {
		t.Fatal("different seeds reused the same signing identity")
	}
}

func TestBasicEd25519SeedRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name     string
		identity []byte
		suite    ciphersuite.CipherSuite
		seed     []byte
	}{
		{"short_seed", []byte("alice"), ciphersuite.MLS128DHKEMX25519, []byte("short")},
		{"missing_identity", nil, ciphersuite.MLS128DHKEMX25519, bytes.Repeat([]byte{1}, 32)},
		{"wrong_suite", []byte("alice"), ciphersuite.MLS128DHKEMP256, bytes.Repeat([]byte{1}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.identity, test.suite, WithBasicEd25519Seed(test.seed))
			if err == nil {
				_ = client.Close()
				t.Fatal("invalid signing configuration was accepted")
			}
		})
	}
}

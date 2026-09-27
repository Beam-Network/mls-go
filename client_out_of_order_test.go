package mls

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/secrettree"
)

// newOutOfOrderPair returns alice (sender) and bob (receiver) in a two-member
// group. Bob uses CacheNone, so every ReceiveMessage reloads the persisted
// snapshot: retained out-of-order keys must survive persistence.
func newOutOfOrderPair(t *testing.T, bobOptions ...ClientOption) (alice, bob *Client, aliceGroup, bobGroup []byte) {
	t.Helper()
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256
	alice, err := NewClient([]byte("alice"), cs)
	if err != nil {
		t.Fatal(err)
	}
	bob, err = NewClient([]byte("bob"), cs, append([]ClientOption{WithCacheStrategy(CacheNone)}, bobOptions...)...)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	aliceGroup, err = alice.CreateGroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, welcome, err := alice.InviteMember(ctx, aliceGroup, kp)
	if err != nil {
		t.Fatal(err)
	}
	bobGroup, err = bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, aliceGroup, bobGroup
}

func sendMessages(t *testing.T, c *Client, groupID []byte, count int) [][]byte {
	t.Helper()
	out := make([][]byte, count)
	for i := range count {
		ct, err := c.SendMessage(context.Background(), groupID, []byte(fmt.Sprintf("m%d", i)))
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		out[i] = ct
	}
	return out
}

func receiveExpect(t *testing.T, c *Client, groupID, ct []byte, want string) {
	t.Helper()
	got, err := c.ReceiveMessage(context.Background(), groupID, ct)
	if err != nil {
		t.Fatalf("receive %s: %v", want, err)
	}
	if string(got.Plaintext) != want {
		t.Fatalf("plaintext = %q, want %q", got.Plaintext, want)
	}
}

// TestClientReceivesDelayedMessageAfterNewerOnes reproduces the room-channel
// failover case: a delayed message arrives after newer messages from the same
// sender. Before retention the late message failed with "generation N already
// advanced past".
func TestClientReceivesDelayedMessageAfterNewerOnes(t *testing.T) {
	alice, bob, aliceGroup, bobGroup := newOutOfOrderPair(t)
	msgs := sendMessages(t, alice, aliceGroup, 6)
	for _, i := range []int{1, 2, 3, 4, 5, 0} {
		receiveExpect(t, bob, bobGroup, msgs[i], fmt.Sprintf("m%d", i))
	}
	for _, i := range []int{0, 5} {
		_, err := bob.ReceiveMessage(context.Background(), bobGroup, msgs[i])
		if !errors.Is(err, secrettree.ErrGenerationConsumed) {
			t.Fatalf("replay of m%d: error = %v, want ErrGenerationConsumed", i, err)
		}
	}
}

func TestClientOutOfOrderWindowIsConfigurable(t *testing.T) {
	alice, bob, aliceGroup, bobGroup := newOutOfOrderPair(t,
		WithSenderRatchetConfig(secrettree.SenderRatchetConfig{OutOfOrderTolerance: 2, MaximumForwardDistance: 4}))
	msgs := sendMessages(t, alice, aliceGroup, 10)
	_, err := bob.ReceiveMessage(context.Background(), bobGroup, msgs[5])
	if !errors.Is(err, secrettree.ErrGenerationTooFarAhead) {
		t.Fatalf("m5 from generation 0: error = %v, want ErrGenerationTooFarAhead", err)
	}
	receiveExpect(t, bob, bobGroup, msgs[4], "m4")
	receiveExpect(t, bob, bobGroup, msgs[8], "m8")
	_, err = bob.ReceiveMessage(context.Background(), bobGroup, msgs[5])
	if !errors.Is(err, secrettree.ErrGenerationTooOld) {
		t.Fatalf("m5 behind window: error = %v, want ErrGenerationTooOld", err)
	}
	receiveExpect(t, bob, bobGroup, msgs[7], "m7")
}

func TestClientRetainedKeysExpire(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	alice, bob, aliceGroup, bobGroup := newOutOfOrderPair(t,
		WithSenderRatchetConfig(secrettree.SenderRatchetConfig{MaxRetentionAge: time.Minute, Now: func() time.Time { return clock }}))
	msgs := sendMessages(t, alice, aliceGroup, 3)
	receiveExpect(t, bob, bobGroup, msgs[2], "m2")
	receiveExpect(t, bob, bobGroup, msgs[0], "m0")
	clock = clock.Add(2 * time.Minute)
	_, err := bob.ReceiveMessage(context.Background(), bobGroup, msgs[1])
	if !errors.Is(err, secrettree.ErrGenerationConsumed) {
		t.Fatalf("expired m1: error = %v, want ErrGenerationConsumed", err)
	}
}

func TestClientRetainedKeysPurgedOnEpochChange(t *testing.T) {
	ctx := context.Background()
	alice, bob, aliceGroup, bobGroup := newOutOfOrderPair(t)
	msgs := sendMessages(t, alice, aliceGroup, 3)
	receiveExpect(t, bob, bobGroup, msgs[2], "m2")
	if n := loadGroupForTest(t, bob, bobGroup).SecretTree().RetainedKeyCount(); n == 0 {
		t.Fatal("expected retained keys for m0 and m1 before the epoch change")
	}

	commit, err := bob.SelfUpdate(ctx, bobGroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.ProcessCommit(ctx, aliceGroup, commit); err != nil {
		t.Fatal(err)
	}
	if n := loadGroupForTest(t, bob, bobGroup).SecretTree().RetainedKeyCount(); n != 0 {
		t.Fatalf("retained keys after epoch change = %d, want 0", n)
	}
	if _, err := bob.ReceiveMessage(ctx, bobGroup, msgs[1]); err == nil {
		t.Fatal("m1 from the previous epoch decrypted after the epoch change")
	}
	next := sendMessages(t, alice, aliceGroup, 1)
	receiveExpect(t, bob, bobGroup, next[0], "m0")
}

// TestGroupEpochChangePurgesHistoricalRetainedKeys covers CacheAlways, where
// the previous epoch's secret tree stays in memory for late handshake
// messages: its retained out-of-order keys are still deleted.
func TestGroupEpochChangePurgesHistoricalRetainedKeys(t *testing.T) {
	ctx := context.Background()
	alice, bob, aliceGroup, bobGroup := newOutOfOrderPair(t, WithCacheStrategy(CacheAlways))
	msgs := sendMessages(t, alice, aliceGroup, 3)
	receiveExpect(t, bob, bobGroup, msgs[2], "m2")
	oldTree := loadGroupForTest(t, bob, bobGroup).SecretTree()
	if oldTree.RetainedKeyCount() == 0 {
		t.Fatal("expected retained keys before the epoch change")
	}
	if _, err := bob.SelfUpdate(ctx, bobGroup); err != nil {
		t.Fatal(err)
	}
	if n := oldTree.RetainedKeyCount(); n != 0 {
		t.Fatalf("previous epoch retained keys = %d, want 0", n)
	}
	_, err := bob.ReceiveMessage(ctx, bobGroup, msgs[1])
	if !errors.Is(err, secrettree.ErrGenerationConsumed) {
		t.Fatalf("m1 after epoch change: error = %v, want ErrGenerationConsumed", err)
	}
}

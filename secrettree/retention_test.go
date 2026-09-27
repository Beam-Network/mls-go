package secrettree

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// newSenderReceiver returns two independent trees derived from the same
// encryption secret: one used by the sender, one by the receiver.
func newSenderReceiver(t *testing.T) (sender, receiver *LeafSecret) {
	t.Helper()
	cs := ciphersuite.MLS128DHKEMP256
	root, err := ciphersuite.NewSecretRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	sendTree, err := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 4, cs)
	if err != nil {
		t.Fatal(err)
	}
	recvTree, err := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 4, cs)
	if err != nil {
		t.Fatal(err)
	}
	sender, err = sendTree.LeafForIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err = recvTree.LeafForIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver
}

type sealed struct {
	gen uint32
	ct  []byte
}

func sealGenerations(t *testing.T, sender *LeafSecret, count int) []sealed {
	t.Helper()
	out := make([]sealed, 0, count)
	for range count {
		seq := sender.NextSequenceNumber()
		ct, err := sender.Encrypt([]byte{byte(seq)}, []byte("aad"), seq)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", seq, err)
		}
		out = append(out, sealed{gen: uint32(seq), ct: ct})
	}
	return out
}

func openGeneration(receiver *LeafSecret, msg sealed, cfg SenderRatchetConfig) ([]byte, error) {
	key, nonce, err := receiver.DecryptionKeyNonce(msg.gen, false, cfg)
	if err != nil {
		return nil, err
	}
	pt, err := ciphersuite.DecryptWithCipherSuite(key, nonce, msg.ct, []byte("aad"), receiver.cs)
	if err != nil {
		return nil, err
	}
	return pt, receiver.ConsumeGeneration(msg.gen, false)
}

func requireGenerationError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	var genErr *GenerationError
	if !errors.As(err, &genErr) {
		t.Fatalf("error %v is not a *GenerationError", err)
	}
}

func TestOutOfOrderWithinWindowDecrypts(t *testing.T) {
	sender, receiver := newSenderReceiver(t)
	msgs := sealGenerations(t, sender, 6)
	order := []int{5, 1, 3, 0, 4, 2}
	for _, i := range order {
		pt, err := openGeneration(receiver, msgs[i], SenderRatchetConfig{})
		if err != nil {
			t.Fatalf("generation %d: %v", msgs[i].gen, err)
		}
		if !bytes.Equal(pt, []byte{byte(i)}) {
			t.Fatalf("generation %d plaintext = %x", msgs[i].gen, pt)
		}
	}
	if got := receiver.RetainedGenerations(); len(got) != 0 {
		t.Fatalf("retained after consuming every generation = %v, want none", got)
	}
}

func TestReplayIsRejected(t *testing.T) {
	sender, receiver := newSenderReceiver(t)
	msgs := sealGenerations(t, sender, 3)
	for _, i := range []int{2, 0} {
		if _, err := openGeneration(receiver, msgs[i], SenderRatchetConfig{}); err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}
	}
	// Replay of the head generation and of a previously retained generation.
	for _, i := range []int{2, 0} {
		_, err := openGeneration(receiver, msgs[i], SenderRatchetConfig{})
		requireGenerationError(t, err, ErrGenerationConsumed)
	}
	// The untouched skipped generation still decrypts exactly once.
	if _, err := openGeneration(receiver, msgs[1], SenderRatchetConfig{}); err != nil {
		t.Fatalf("generation 1: %v", err)
	}
	_, err := openGeneration(receiver, msgs[1], SenderRatchetConfig{})
	requireGenerationError(t, err, ErrGenerationConsumed)
}

func TestGenerationBeyondWindowIsRejected(t *testing.T) {
	sender, receiver := newSenderReceiver(t)
	msgs := sealGenerations(t, sender, 11)
	cfg := SenderRatchetConfig{OutOfOrderTolerance: 4}
	if _, err := openGeneration(receiver, msgs[10], cfg); err != nil {
		t.Fatal(err)
	}
	// Head is 11 after consuming 10: only generations 7..9 remain within the
	// window (11 - g <= 4); 6 was retained when 10 arrived and ages out now.
	for _, i := range []int{5, 6} {
		_, err := openGeneration(receiver, msgs[i], cfg)
		requireGenerationError(t, err, ErrGenerationTooOld)
	}
	if got, want := receiver.RetainedGenerations(), []uint32{7, 8, 9}; !equalGenerations(got, want) {
		t.Fatalf("retained = %v, want %v", got, want)
	}
	if _, err := openGeneration(receiver, msgs[7], cfg); err != nil {
		t.Fatalf("generation 7 inside window: %v", err)
	}
}

func TestMaximumForwardDistance(t *testing.T) {
	sender, receiver := newSenderReceiver(t)
	msgs := sealGenerations(t, sender, 10)
	cfg := SenderRatchetConfig{MaximumForwardDistance: 8, OutOfOrderTolerance: 16}
	_, err := openGeneration(receiver, msgs[9], cfg)
	requireGenerationError(t, err, ErrGenerationTooFarAhead)
	if receiver.CurrentGeneration() != 0 || len(receiver.RetainedGenerations()) != 0 {
		t.Fatalf("rejected generation mutated the ratchet: head=%d retained=%v",
			receiver.CurrentGeneration(), receiver.RetainedGenerations())
	}
	if _, err := openGeneration(receiver, msgs[8], cfg); err != nil {
		t.Fatalf("generation 8 at the maximum distance: %v", err)
	}
	if _, err := openGeneration(receiver, msgs[9], cfg); err != nil {
		t.Fatalf("generation 9 after catching up: %v", err)
	}
}

func TestRetainedKeysExpire(t *testing.T) {
	sender, receiver := newSenderReceiver(t)
	msgs := sealGenerations(t, sender, 4)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cfg := SenderRatchetConfig{MaxRetentionAge: time.Minute, Now: clock.Now}
	if _, err := openGeneration(receiver, msgs[3], cfg); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(30 * time.Second)
	if _, err := openGeneration(receiver, msgs[0], cfg); err != nil {
		t.Fatalf("generation 0 before expiry: %v", err)
	}
	clock.now = clock.now.Add(31 * time.Second)
	_, err := openGeneration(receiver, msgs[1], cfg)
	requireGenerationError(t, err, ErrGenerationConsumed)
	if got := receiver.RetainedGenerations(); len(got) != 0 {
		t.Fatalf("retained after expiry = %v, want none", got)
	}
}

func TestRetainedKeysSurviveMarshalFull(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	root, _ := ciphersuite.NewSecretRandom(32)
	sendTree, _ := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 2, cs)
	recvTree, _ := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 2, cs)
	sender, _ := sendTree.LeafForIndex(0)
	receiver, _ := recvTree.LeafForIndex(0)
	msgs := sealGenerations(t, sender, 4)
	if _, err := openGeneration(receiver, msgs[3], SenderRatchetConfig{}); err != nil {
		t.Fatal(err)
	}

	state := recvTree.MarshalFull()
	for _, retained := range state.LeafStates[0].RetainedKeys {
		if retained.Generation >= 3 {
			t.Fatalf("persisted retained generation %d at or ahead of the consumed head", retained.Generation)
		}
	}
	restored, err := UnmarshalFull(state, cs)
	if err != nil {
		t.Fatal(err)
	}
	restoredLeaf, _ := restored.LeafForIndex(0)
	if _, err := openGeneration(restoredLeaf, msgs[1], SenderRatchetConfig{}); err != nil {
		t.Fatalf("late generation after restore: %v", err)
	}
	_, err = openGeneration(restoredLeaf, msgs[3], SenderRatchetConfig{})
	requireGenerationError(t, err, ErrGenerationConsumed)

	// A consumed generation stays consumed across another persist/restore cycle.
	again, err := UnmarshalFull(restored.MarshalFull(), cs)
	if err != nil {
		t.Fatal(err)
	}
	againLeaf, _ := again.LeafForIndex(0)
	_, err = openGeneration(againLeaf, msgs[1], SenderRatchetConfig{})
	requireGenerationError(t, err, ErrGenerationConsumed)
	if _, err := openGeneration(againLeaf, msgs[0], SenderRatchetConfig{}); err != nil {
		t.Fatalf("generation 0 after second restore: %v", err)
	}
}

func TestPurgeRetainedKeysOnEpochChange(t *testing.T) {
	cs := ciphersuite.MLS128DHKEMP256
	root, _ := ciphersuite.NewSecretRandom(32)
	sendTree, _ := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 2, cs)
	recvTree, _ := NewTree(ciphersuite.NewSecret(append([]byte(nil), root.AsSlice()...)), 2, cs)
	sender, _ := sendTree.LeafForIndex(1)
	receiver, _ := recvTree.LeafForIndex(1)
	msgs := sealGenerations(t, sender, 5)
	if _, err := openGeneration(receiver, msgs[4], SenderRatchetConfig{}); err != nil {
		t.Fatal(err)
	}
	if recvTree.RetainedKeyCount() == 0 {
		t.Fatal("expected retained keys before the epoch ends")
	}
	recvTree.PurgeRetainedKeys()
	if n := recvTree.RetainedKeyCount(); n != 0 {
		t.Fatalf("retained keys after purge = %d, want 0", n)
	}
	if keys := recvTree.MarshalFull().LeafStates[1].RetainedKeys; len(keys) != 0 {
		t.Fatalf("persisted retained keys after purge = %d, want 0", len(keys))
	}
	_, err := openGeneration(receiver, msgs[2], SenderRatchetConfig{})
	requireGenerationError(t, err, ErrGenerationConsumed)
}

func TestSenderRatchetDoesNotRetainOwnKeys(t *testing.T) {
	sender, _ := newSenderReceiver(t)
	sealGenerations(t, sender, 8)
	if got := sender.RetainedGenerations(); len(got) != 0 {
		t.Fatalf("sender retained generations %v; only receivers retain skipped keys", got)
	}
}

func equalGenerations(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

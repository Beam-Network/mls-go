package secrettree

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// Out-of-order tolerance for receiving (RFC 9420 §9.2).
//
// When a message with generation j arrives from a sender whose ratchet is at
// generation h < j, the receiver ratchets forward to j. The key and nonce of
// the skipped generations h..j-1 are "unconsumed" values which RFC 9420 §9.2
// explicitly allows a member to keep "for some reasonable amount of time to
// handle out-of-order message delivery". This file implements that retention
// with the same bounds as OpenMLS' SenderRatchetConfiguration:
//
//   - OutOfOrderTolerance: only the key/nonce pairs of the last N skipped
//     generations behind the ratchet head are retained. Older generations are
//     rejected with ErrGenerationTooOld.
//   - MaximumForwardDistance: a single message may not ratchet a sender more
//     than M generations ahead (ErrGenerationTooFarAhead). This bounds the HKDF
//     work an authenticated-but-hostile member can force on a receiver.
//   - MaxRetentionAge: retained pairs are purged after this age even when they
//     are still inside the window. They are also purged when the epoch ends
//     (Tree.PurgeRetainedKeys) because a new epoch uses a new secret tree.
//
// Forward-secrecy trade-off: only derived key/nonce pairs are retained, never
// ratchet secrets, so a compromise of retained state reveals at most the
// (bounded, time-limited) set of skipped messages from that sender in the
// current epoch; it never reveals consumed messages or any future generation.
// A retained pair is deleted as soon as it decrypts a message (ConsumeGeneration),
// which is also what makes a replay of that message fail.
//
// Generations are shared between the handshake and application ratchets of a
// leaf (this library's senders draw both from one per-leaf counter), so
// consuming generation j on either ratchet consumes j for the leaf.

const (
	// DefaultOutOfOrderTolerance is the default number of skipped generations
	// per sender whose keys are retained behind the ratchet head.
	DefaultOutOfOrderTolerance uint32 = 128
	// DefaultMaximumForwardDistance is the default maximum number of
	// generations a single received message may advance a sender's ratchet.
	DefaultMaximumForwardDistance uint32 = 1 << 16
	// DefaultMaxRetentionAge is the default lifetime of a retained key/nonce.
	DefaultMaxRetentionAge = 5 * time.Minute
)

var (
	// ErrGenerationTooOld reports a generation behind the out-of-order window.
	ErrGenerationTooOld = errors.New("generation is older than the out-of-order window")
	// ErrGenerationConsumed reports a generation inside the window whose key is
	// no longer retained: it already decrypted a message (replay) or expired.
	ErrGenerationConsumed = errors.New("generation key already consumed or expired")
	// ErrGenerationTooFarAhead reports a generation beyond the maximum forward distance.
	ErrGenerationTooFarAhead = errors.New("generation exceeds the maximum forward distance")
)

// GenerationError describes a rejected sender generation. It unwraps to one of
// ErrGenerationTooOld, ErrGenerationConsumed or ErrGenerationTooFarAhead.
type GenerationError struct {
	LeafIndex  uint32
	Generation uint32
	Current    uint64
	Handshake  bool
	Reason     error
}

func (e *GenerationError) Error() string {
	ratchet := "application"
	if e.Handshake {
		ratchet = "handshake"
	}
	return fmt.Sprintf("%v: leaf %d %s generation %d (current: %d)", e.Reason, e.LeafIndex, ratchet, e.Generation, e.Current)
}

func (e *GenerationError) Unwrap() error { return e.Reason }

// SenderRatchetConfig bounds out-of-order tolerance on the receiving side.
// Zero fields select the defaults; a negative MaxRetentionAge disables the
// age bound (the window and epoch bounds still apply).
type SenderRatchetConfig struct {
	OutOfOrderTolerance    uint32
	MaximumForwardDistance uint32
	MaxRetentionAge        time.Duration
	// Now overrides the clock used to timestamp and expire retained keys.
	Now func() time.Time
}

// Normalized returns the configuration with defaults applied.
func (c SenderRatchetConfig) Normalized() SenderRatchetConfig {
	if c.OutOfOrderTolerance == 0 {
		c.OutOfOrderTolerance = DefaultOutOfOrderTolerance
	}
	if c.MaximumForwardDistance == 0 {
		c.MaximumForwardDistance = DefaultMaximumForwardDistance
	}
	if c.MaxRetentionAge == 0 {
		c.MaxRetentionAge = DefaultMaxRetentionAge
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

type retainedID struct {
	generation uint32
	handshake  bool
}

type retainedKey struct {
	key        []byte
	nonce      []byte
	retainedAt time.Time
}

func (rk *retainedKey) zero() {
	clear(rk.key)
	clear(rk.nonce)
	rk.key, rk.nonce = nil, nil
}

// RetainedKeyState is the persisted form of one retained key/nonce pair.
type RetainedKeyState struct {
	Generation         uint32 `json:"generation"`
	Handshake          bool   `json:"handshake,omitempty"`
	Key                []byte `json:"key"`
	Nonce              []byte `json:"nonce"`
	RetainedAtUnixNano int64  `json:"retained_at_unix_nano"`
}

// DecryptionKeyNonce returns the content key and nonce to open a message from
// this leaf at generation. A generation ahead of the ratchet advances it (up to
// MaximumForwardDistance) and retains the skipped generations' key/nonce pairs
// inside the OutOfOrderTolerance window. A generation behind the ratchet is
// served only from those retained pairs.
//
// The returned values are not consumed: after the AEAD open succeeds, callers
// MUST call ConsumeGeneration so the key is deleted and replays are rejected.
func (ls *LeafSecret) DecryptionKeyNonce(generation uint32, handshake bool, cfg SenderRatchetConfig) (key, nonce []byte, err error) {
	cfg = cfg.Normalized()
	now := cfg.Now()
	ls.purgeRetained(cfg, now)
	if uint64(generation) < ls.generation {
		if rk, ok := ls.retained[retainedID{generation: generation, handshake: handshake}]; ok {
			return cloneBytes(rk.key), cloneBytes(rk.nonce), nil
		}
		reason := ErrGenerationConsumed
		if ls.generation-uint64(generation) > uint64(cfg.OutOfOrderTolerance) {
			reason = ErrGenerationTooOld
		}
		return nil, nil, ls.generationError(generation, handshake, reason)
	}
	if uint64(generation)-ls.generation > uint64(cfg.MaximumForwardDistance) {
		return nil, nil, ls.generationError(generation, handshake, ErrGenerationTooFarAhead)
	}
	var retainFrom uint32
	if generation > cfg.OutOfOrderTolerance {
		retainFrom = generation - cfg.OutOfOrderTolerance
	}
	for ls.generation < uint64(generation) {
		if err := ls.stepRatchets(uint32(ls.generation) >= retainFrom, now); err != nil {
			return nil, nil, err
		}
	}
	ls.purgeRetained(cfg, now)
	return ls.headKeyNonce(handshake)
}

// ConsumeGeneration deletes the key material for generation after it decrypted
// a message (RFC 9420 §9.2). A retained generation loses its retained pairs; the
// head generation advances the ratchet so its secret is deleted. Either way a
// replay of the same generation is subsequently rejected.
func (ls *LeafSecret) ConsumeGeneration(generation uint32, handshake bool) error {
	if uint64(generation) < ls.generation {
		id := retainedID{generation: generation, handshake: handshake}
		if _, ok := ls.retained[id]; !ok {
			return ls.generationError(generation, handshake, ErrGenerationConsumed)
		}
		for _, kind := range []bool{false, true} {
			other := retainedID{generation: generation, handshake: kind}
			if rk, ok := ls.retained[other]; ok {
				rk.zero()
				delete(ls.retained, other)
			}
		}
		return nil
	}
	if uint64(generation) == ls.generation {
		return ls.stepRatchets(false, time.Time{})
	}
	return fmt.Errorf("consume generation %d ahead of ratchet (current: %d)", generation, ls.generation)
}

// RetainedGenerations lists the generations with a retained application key.
func (ls *LeafSecret) RetainedGenerations() []uint32 {
	out := make([]uint32, 0, len(ls.retained))
	for id := range ls.retained {
		if !id.handshake {
			out = append(out, id.generation)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PurgeRetainedKeys zeroes every retained out-of-order key in the tree. Groups
// call it when the epoch ends.
func (t *Tree) PurgeRetainedKeys() {
	if t == nil {
		return
	}
	for _, leaf := range t.leafCache {
		if leaf != nil {
			leaf.dropRetained()
		}
	}
}

// PurgeExpiredRetainedKeys drops retained keys that are older than the
// configured age or outside the out-of-order window, for every leaf.
func (t *Tree) PurgeExpiredRetainedKeys(cfg SenderRatchetConfig) {
	if t == nil {
		return
	}
	cfg = cfg.Normalized()
	now := cfg.Now()
	for _, leaf := range t.leafCache {
		if leaf != nil {
			leaf.purgeRetained(cfg, now)
		}
	}
}

// RetainedKeyCount returns the number of retained key/nonce pairs in the tree.
func (t *Tree) RetainedKeyCount() int {
	if t == nil {
		return 0
	}
	count := 0
	for _, leaf := range t.leafCache {
		if leaf != nil {
			count += len(leaf.retained)
		}
	}
	return count
}

// stepRatchets advances both ratchets by one generation and deletes the
// previous ratchet secrets. When retain is set, the key/nonce pairs of the
// generation being left are kept for out-of-order delivery.
func (ls *LeafSecret) stepRatchets(retain bool, now time.Time) error {
	if ls.generation >= math.MaxUint32 {
		return fmt.Errorf("ratchet generation exhausted for leaf %d", ls.leafIndex)
	}
	g := uint32(ls.generation)
	genBytes := uint32ToBytes(g)
	if retain {
		for _, handshake := range []bool{false, true} {
			key, nonce, err := ls.headKeyNonce(handshake)
			if err != nil {
				return err
			}
			if ls.retained == nil {
				ls.retained = make(map[retainedID]*retainedKey)
			}
			ls.retained[retainedID{generation: g, handshake: handshake}] = &retainedKey{key: key, nonce: nonce, retainedAt: now}
		}
	}
	nh := ls.cs.HashLength()
	next, err := ls.applicationRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
	if err != nil {
		return fmt.Errorf("advance application ratchet (gen %d): %w", g, err)
	}
	nextHs, err := ls.handshakeRatchetSecret.KdfExpandLabel("secret", genBytes, nh)
	if err != nil {
		next.SecureZero()
		return fmt.Errorf("advance handshake ratchet (gen %d): %w", g, err)
	}
	ls.applicationRatchetSecret.SecureZero() // RFC §9.2: delete consumed secret
	ls.applicationRatchetSecret = next
	ls.handshakeRatchetSecret.SecureZero() // RFC §9.2: delete consumed secret
	ls.handshakeRatchetSecret = nextHs
	ls.generation++
	return nil
}

// headKeyNonce derives the key and nonce for the current ratchet generation.
func (ls *LeafSecret) headKeyNonce(handshake bool) (key, nonce []byte, err error) {
	secret := ls.applicationRatchetSecret
	if handshake {
		secret = ls.handshakeRatchetSecret
	}
	if secret == nil {
		return nil, nil, fmt.Errorf("ratchet secret for leaf %d deleted", ls.leafIndex)
	}
	genBytes := uint32ToBytes(uint32(ls.generation))
	k, err := secret.KdfExpandLabel("key", genBytes, ls.cs.AeadKeyLength())
	if err != nil {
		return nil, nil, fmt.Errorf("deriving key (gen %d): %w", ls.generation, err)
	}
	n, err := secret.KdfExpandLabel("nonce", genBytes, ls.cs.AeadNonceLength())
	if err != nil {
		k.SecureZero()
		return nil, nil, fmt.Errorf("deriving nonce (gen %d): %w", ls.generation, err)
	}
	return k.AsSlice(), n.AsSlice(), nil
}

func (ls *LeafSecret) purgeRetained(cfg SenderRatchetConfig, now time.Time) {
	for id, rk := range ls.retained {
		expired := cfg.MaxRetentionAge > 0 && now.Sub(rk.retainedAt) > cfg.MaxRetentionAge
		outside := ls.generation-uint64(id.generation) > uint64(cfg.OutOfOrderTolerance)
		if expired || outside {
			rk.zero()
			delete(ls.retained, id)
		}
	}
}

func (ls *LeafSecret) dropRetained() {
	for id, rk := range ls.retained {
		rk.zero()
		delete(ls.retained, id)
	}
	ls.retained = nil
}

func (ls *LeafSecret) generationError(generation uint32, handshake bool, reason error) error {
	return &GenerationError{
		LeafIndex:  ls.leafIndex,
		Generation: generation,
		Current:    ls.generation,
		Handshake:  handshake,
		Reason:     reason,
	}
}

func (ls *LeafSecret) marshalRetained() []RetainedKeyState {
	if len(ls.retained) == 0 {
		return nil
	}
	out := make([]RetainedKeyState, 0, len(ls.retained))
	for id, rk := range ls.retained {
		out = append(out, RetainedKeyState{
			Generation:         id.generation,
			Handshake:          id.handshake,
			Key:                cloneBytes(rk.key),
			Nonce:              cloneBytes(rk.nonce),
			RetainedAtUnixNano: rk.retainedAt.UnixNano(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Generation != out[j].Generation {
			return out[i].Generation < out[j].Generation
		}
		return !out[i].Handshake && out[j].Handshake
	})
	return out
}

func (ls *LeafSecret) unmarshalRetained(states []RetainedKeyState) error {
	for _, state := range states {
		if uint64(state.Generation) >= ls.generation {
			return fmt.Errorf("retained generation %d is not behind ratchet (current: %d)", state.Generation, ls.generation)
		}
		if len(state.Key) != ls.cs.AeadKeyLength() || len(state.Nonce) != ls.cs.AeadNonceLength() {
			return fmt.Errorf("retained key for generation %d has invalid length", state.Generation)
		}
		if ls.retained == nil {
			ls.retained = make(map[retainedID]*retainedKey)
		}
		ls.retained[retainedID{generation: state.Generation, handshake: state.Handshake}] = &retainedKey{
			key:        cloneBytes(state.Key),
			nonce:      cloneBytes(state.Nonce),
			retainedAt: time.Unix(0, state.RetainedAtUnixNano),
		}
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

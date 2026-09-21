package state

// AnchorState is the rollback-protected state stored in RPMB. Legacy anchors
// contain only Generation; Bound is false until Open migrates them.
type AnchorState struct {
	Generation uint32
	BlobHash   BlobHash
	Bound      bool
}

// Anchor is the rollback-protection anchor: a hardware-monotonic store of the
// latest committed state generation and the exact blob committed there.
//
// On hardware it is backed by an eMMC RPMB sector (an authenticated write
// both records the generation and advances the RPMB hardware write counter,
// which cannot be rolled back). Tests and emulated runs use an in-memory
// fake. See ROLLBACK.md for how the store cross-checks the microSD blob
// generation against this anchor.
type Anchor interface {
	// Anchor returns the latest committed state, authenticated. A fresh
	// (never-written) anchor has generation 0 and Bound false.
	Anchor() (AnchorState, error)

	// SetAnchor records next as the latest committed state. Its generation
	// must advance, except that a legacy unbound record may be bound at the
	// same generation during migration. The implementation advances the
	// underlying hardware counter as a side effect.
	SetAnchor(next AnchorState) error
}

// rpmbAnchorSector is the RPMB sector holding the anchor record. Sector 0 is
// reserved as the CVE-2020-13799 dummy/invalidation block, so the anchor lives
// at sector 1.
const rpmbAnchorSector = 1

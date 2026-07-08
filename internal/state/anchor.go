package state

// Anchor is the rollback-protection anchor: a hardware-monotonic store of the
// latest committed state generation.
//
// On hardware it is backed by an eMMC RPMB sector (an authenticated write
// both records the generation and advances the RPMB hardware write counter,
// which cannot be rolled back). Tests and emulated runs use an in-memory
// fake. See ROLLBACK.md for how the store cross-checks the microSD blob
// generation against this anchor.
type Anchor interface {
	// Anchor returns the latest committed generation, authenticated. A
	// fresh (never-written) anchor returns 0.
	Anchor() (uint32, error)

	// SetAnchor records g as the latest committed generation. It must be
	// monotonic: g strictly greater than the current value. The
	// implementation advances the underlying hardware counter as a side
	// effect.
	SetAnchor(g uint32) error
}

// rpmbAnchorSector is the RPMB sector holding the generation. Sector 0 is
// reserved as the CVE-2020-13799 dummy/invalidation block (see internal/rpmb
// Init), so the anchor lives at sector 1.
const rpmbAnchorSector = 1

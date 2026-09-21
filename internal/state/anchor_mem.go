package state

import (
	"fmt"
	"sync"
)

// MemAnchor is an in-memory Anchor for tests and emulated (QEMU) runs, where
// no eMMC RPMB exists.
//
// Like the hardware anchor its generation is monotonic, except for binding a
// legacy record. Tests reuse it across store instances to model a reboot while
// storage rollback is simulated separately. It provides no hardware rollback
// protection.
type MemAnchor struct {
	mu    sync.Mutex
	state AnchorState
}

// NewMemAnchor returns a fresh anchor reading 0.
func NewMemAnchor() *MemAnchor { return &MemAnchor{} }

func (a *MemAnchor) Anchor() (AnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *MemAnchor) SetAnchor(next AnchorState) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !next.Bound {
		return fmt.Errorf("anchor state is not bound to a blob")
	}
	if next.Generation < a.state.Generation ||
		(next.Generation == a.state.Generation && a.state.Bound) {
		return fmt.Errorf("anchor not monotonic: setting %d over %d", next.Generation, a.state.Generation)
	}
	a.state = next
	return nil
}

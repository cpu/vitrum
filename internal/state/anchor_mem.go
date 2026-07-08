package state

import (
	"fmt"
	"sync"
)

// MemAnchor is an in-memory Anchor for tests and emulated (QEMU) runs, where
// no eMMC RPMB exists.
//
// Like the hardware anchor it is strictly monotonic, so a test can reuse the
// same MemAnchor across store instances to model a reboot while a storage
// rollback is simulated separately. It provides no hardware rollback
// protection; it exists to exercise the store's generation cross-check logic
// off-hardware.
type MemAnchor struct {
	mu sync.Mutex
	g  uint32
}

// NewMemAnchor returns a fresh anchor reading 0.
func NewMemAnchor() *MemAnchor { return &MemAnchor{} }

func (a *MemAnchor) Anchor() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.g, nil
}

func (a *MemAnchor) SetAnchor(g uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if g <= a.g {
		return fmt.Errorf("anchor not monotonic: setting %d over %d", g, a.g)
	}
	a.g = g
	return nil
}

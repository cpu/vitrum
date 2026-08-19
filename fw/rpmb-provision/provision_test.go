package main

import (
	"bytes"
	"testing"

	"github.com/cpu/vitrum/fw/internal/hab"
	"github.com/cpu/vitrum/internal/rpmb"
)

func cleanHAB() hab.Status { return hab.Status{Status: "success", Config: "closed", State: "trusted"} }

func TestProvisionRPMB(t *testing.T) {
	card := rpmb.NewFakeCard()
	status := provisionRPMB(card, true, cleanHAB(), func() ([]byte, error) {
		return bytes.Repeat([]byte{0xa5}, 32), nil
	})
	if !status.Success || !status.UnprogrammedBefore || !status.KeyProgrammed || !status.AuthenticatedCounter {
		t.Fatalf("status = %+v", status)
	}
	if !card.Programmed() {
		t.Fatal("key was not programmed")
	}
}

func TestProvisionRPMBRefusesUnsafeStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
		hab    hab.Status
	}{
		{name: "insecure SNVS", secure: false, hab: cleanHAB()},
		{name: "HAB failure", secure: true, hab: hab.Status{Status: "success", Failures: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := rpmb.NewFakeCard()
			called := false
			status := provisionRPMB(card, tc.secure, tc.hab, func() ([]byte, error) {
				called = true
				return make([]byte, 32), nil
			})
			if status.Success || card.Programmed() || called {
				t.Fatalf("unsafe provisioning: status=%+v programmed=%v deriveCalled=%v", status, card.Programmed(), called)
			}
		})
	}
}

func TestProvisionRPMBRefusesProgrammedCard(t *testing.T) {
	card := rpmb.NewFakeCard()
	key := bytes.Repeat([]byte{0xa5}, 32)
	p, err := rpmb.Init(card, key, 0, false)
	if err != nil || p.ProgramKey() != nil {
		t.Fatal("fixture key programming failed")
	}
	status := provisionRPMB(card, true, cleanHAB(), func() ([]byte, error) { return key, nil })
	if status.Success || status.UnprogrammedBefore {
		t.Fatalf("status = %+v", status)
	}
}

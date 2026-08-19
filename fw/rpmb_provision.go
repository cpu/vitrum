package main

import (
	"errors"
	"fmt"

	"github.com/cpu/vitrum/fw/internal/hab"
	"github.com/cpu/vitrum/internal/rpmb"
)

type rpmbProvisionStatus struct {
	HAB                  hab.Status `json:"hab"`
	SNVSSecure           bool       `json:"snvs_secure"`
	UnprogrammedBefore   bool       `json:"unprogrammed_before"`
	KeyProgrammed        bool       `json:"key_programmed"`
	AuthenticatedCounter bool       `json:"authenticated_counter"`
	Counter              uint32     `json:"counter,omitempty"`
	Success              bool       `json:"success"`
	Error                string     `json:"error,omitempty"`
}

func provisionRPMB(card rpmb.Transport, secure bool, boot hab.Status, derive func() ([]byte, error)) (status rpmbProvisionStatus) {
	status.HAB = boot
	status.SNVSSecure = secure
	fail := func(err error) rpmbProvisionStatus {
		status.Error = err.Error()
		return status
	}

	if boot.Status != "success" || boot.Failures != 0 {
		return fail(fmt.Errorf("HAB boot not clean: status=%s failures=%d", boot.Status, boot.Failures))
	}
	if !secure {
		return fail(errors.New("SNVS is not secure; refusing RPMB programming"))
	}

	probe, err := rpmb.Init(card, make([]byte, 32), 0, false)
	if err != nil {
		return fail(fmt.Errorf("RPMB probe init: %w", err))
	}
	_, err = probe.Counter(false)
	var opErr *rpmb.OperationError
	if !errors.As(err, &opErr) || opErr.Result != rpmb.AuthenticationKeyNotYetProgrammed {
		if err == nil {
			return fail(errors.New("RPMB key is already programmed; refusing to modify it"))
		}
		return fail(fmt.Errorf("RPMB programming state is inconclusive: %w", err))
	}
	status.UnprogrammedBefore = true

	key, err := derive()
	if err != nil {
		return fail(fmt.Errorf("RPMB key derivation: %w", err))
	}
	p, err := rpmb.Init(card, key, 0, false)
	if err != nil {
		return fail(fmt.Errorf("RPMB init: %w", err))
	}
	if err := p.ProgramKey(); err != nil {
		return fail(fmt.Errorf("RPMB key programming: %w", err))
	}
	status.KeyProgrammed = true

	status.Counter, err = p.Counter(true)
	if err != nil {
		return fail(fmt.Errorf("authenticated RPMB counter verification: %w", err))
	}
	status.AuthenticatedCounter = true
	status.Success = true
	return status
}

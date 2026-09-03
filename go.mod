module github.com/cpu/vitrum

go 1.27.0

require (
	filippo.io/torchwood v0.9.0
	github.com/usbarmory/go-net v0.0.0-20260714134120-c2c964e7084c
	github.com/usbarmory/rpmb v0.0.0-20260903082741-fa6a72563433
	github.com/usbarmory/tamago v1.27.1-0.20260825170449-b5e01530ebca
	golang.org/x/crypto v0.56.0
	golang.org/x/mod v0.40.0
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/soypat/lneto v0.2.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/telemetry v0.0.0-20260811182544-a038080d80e5 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.org/x/vuln v1.7.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250911055229-61a46406f068 // indirect
	honnef.co/go/tools v0.8.1 // indirect
)

tool (
	github.com/usbarmory/tamago/cmd/tamago
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

//go:build !usbarmory && !mx6ullevk

package main

import "log"

// Host builds (go build/vet/test without firmware tags) get this stub so the
// package remains a valid main package.
func main() {
	log.Fatal("vitrum firmware must be built via make (TARGET=usbarmory|mx6ullevk)")
}

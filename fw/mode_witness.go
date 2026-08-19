//go:build !rpmbprovision && (usbarmory || mx6ullevk)

package main

func main() {
	firmwareMain()
}

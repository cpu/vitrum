//go:build mx6ullevk

package main

func habReport() habStatus {
	return habStatus{Status: "unavailable", Config: "unavailable", State: "unavailable"}
}

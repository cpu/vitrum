//go:build mx6ullevk

package hab

func Report() Status {
	return Status{Status: "unavailable", Config: "unavailable", State: "unavailable"}
}

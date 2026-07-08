package main

import (
	"fmt"
	"strings"

	"github.com/cpu/vitrum/internal/config"
)

// resolveLog resolves a fetchable log from either a -log-name handle or three
// explicit flags.
//
// The two forms are mutually exclusive and exactly one must be supplied. The
// explicit form builds an ad-hoc fetchableLog with no Name.
func resolveLog(name, monitoringURL, origin, logKey string) (fetchableLog, error) {
	if name != "" {
		if monitoringURL != "" || origin != "" || logKey != "" {
			return fetchableLog{}, fmt.Errorf("-log-name is mutually exclusive with -log/-origin/-log-key")
		}

		l, ok := fetchableByName(name)
		if !ok {
			return fetchableLog{}, fmt.Errorf("unknown -log-name %q (known: %s)", name, strings.Join(fetchableNames(), ", "))
		}

		return l, nil
	}

	if monitoringURL == "" || origin == "" || logKey == "" {
		return fetchableLog{}, fmt.Errorf("provide -log-name, or all of -log, -origin and -log-key")
	}

	return fetchableLog{
		MonitoringURL: monitoringURL,
		Log:           config.Log{Origin: origin, VKey: logKey},
	}, nil
}

// fetchableNames returns every -log-name handle, for error messages.
func fetchableNames() []string {
	names := make([]string, len(fetchableLogs))
	for i, l := range fetchableLogs {
		names[i] = l.Name
	}

	return names
}

// fetchableByName returns the fetchable log with the given -log-name handle,
// or false if none matches.
func fetchableByName(name string) (fetchableLog, bool) {
	if name == "" {
		return fetchableLog{}, false
	}

	for _, l := range fetchableLogs {
		if l.Name == name {
			return l, true
		}
	}

	return fetchableLog{}, false
}

// fetchableLog is a log the host tooling can read from directly.
//
// A fetchableLog is the identity (origin + verifier key) plus the read-path
// prefix to reach it, paired with a short handle to name it on the
// command line.
type fetchableLog struct {
	// Name is the -log-name handle for `feed`/`record`.
	Name string

	// MonitoringURL is the log's read-path prefix, where /checkpoint and
	// /tile/... live (c2sp.org/tlog-tiles).
	MonitoringURL string

	// Log is the identity (Origin + VKey) from the config.Logs registry.
	config.Log
}

// fetchableLogs is the set of logs the host tooling can drive by name. The
// identities come from config.Logs; entries here add only the handle and
// the read path.
var fetchableLogs = []fetchableLog{
	{
		// keyserver.geomys.org (https://words.filippo.io/keyserver-tlog/)
		Name:          "keyserver",
		MonitoringURL: "https://keyserver.geomys.org/tlog/",
		Log:           mustConfigLog("keyserver.geomys.org"),
	},
}

// mustConfigLog returns the config.Logs entry with the given origin,
// panicking at init if the registry no longer contains it.
func mustConfigLog(origin string) config.Log {
	for _, l := range config.Logs {
		if l.Origin == origin {
			return l
		}
	}

	panic(fmt.Sprintf("origin %q not in config.Logs", origin))
}

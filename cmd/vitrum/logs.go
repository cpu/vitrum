package main

import (
	"fmt"
	"strings"

	"github.com/cpu/vitrum/internal/config"
)

// resolveLog resolves either a named log or an explicit log configuration.
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

// fetchableNames returns every -log-name handle.
func fetchableNames() []string {
	names := make([]string, len(fetchableLogs))
	for i, l := range fetchableLogs {
		names[i] = l.Name
	}

	return names
}

// fetchableByName looks up a -log-name handle.
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

// fetchableLog is a log the host tooling can read by name.
type fetchableLog struct {
	// Name is the -log-name handle for `feed`/`record`.
	Name string

	// MonitoringURL is the log's read-path prefix, where /checkpoint and
	// /tile/... live (c2sp.org/tlog-tiles).
	MonitoringURL string

	// Log is the identity from config.Logs.
	config.Log
}

// fetchableLogs adds command-line names and read paths to config.Logs entries.
var fetchableLogs = []fetchableLog{
	{
		// keyserver.geomys.org (https://words.filippo.io/keyserver-tlog/)
		Name:          "keyserver",
		MonitoringURL: "https://keyserver.geomys.org/tlog/",
		Log:           mustConfigLog("keyserver.geomys.org"),
	},
}

// mustConfigLog returns a config.Logs entry or panics during initialization.
func mustConfigLog(origin string) config.Log {
	for _, l := range config.Logs {
		if l.Origin == origin {
			return l
		}
	}

	panic(fmt.Sprintf("origin %q not in config.Logs", origin))
}

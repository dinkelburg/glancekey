package main

import "strings"

// The app's name, as in Core/Sources/AppCore/Brand.swift, which explains how to rename the app. appName is only
// what you see. appID also names this binary, its systemd service, config folder, socket and keyring entry, and
// the checker's files under /etc and /usr/local, so changing it means setting up again.
const (
	appName      = "GlanceKey"
	appID        = "glancekey"
	defaultRelay = "https://relay.glancekey.com"

	agentCommand = appID + "-agent"
	urlScheme    = appID
)

// envPrefix starts the environment variables that change settings for testing, e.g. GLANCEKEY_RELAY.
var envPrefix = strings.ToUpper(appID) + "_"

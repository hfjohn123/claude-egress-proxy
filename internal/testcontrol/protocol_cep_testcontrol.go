//go:build cep_testcontrol

package testcontrol

// Protocol identifies the tagged-only control channel. The server has no
// control-pipe wiring until it exposes each injectable dependency; this marker
// lets the external harness reject an ordinary binary before any test begins.
const Protocol = "cep-testcontrol-v1"

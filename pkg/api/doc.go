// Package api is the public, library-shaped surface of Semantic
// Firewall. The CLI in cmd/sfw and the MCP server in the sibling
// semantic_firewall_mcp repo both consume it; everything in
// internal/cli is implementation glue that orchestrates flag parsing
// and process boundaries on top of the entry points defined here.
//
// The entry points return the same JSON-serialisable types from
// pkg/models that the CLI prints, so callers can either marshal them
// directly or inspect the structured values in-process.
package api

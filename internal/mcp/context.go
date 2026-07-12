// internal/mcp/context.go
package mcp

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/scrypster/muninndb/internal/auth"
)

const mcpSessionHeader = "Mcp-Session-Id"

// authFromRequest extracts the Bearer token from the Authorization header.
// Returns AuthContext{Authorized: true} if token matches or no token is required.
func authFromRequest(r *http.Request, requiredToken string) AuthContext {
	if requiredToken == "" {
		return AuthContext{Authorized: true}
	}
	header := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(header, "Bearer ")
	if !found || token == "" {
		return AuthContext{Authorized: false}
	}
	return AuthContext{Token: token, Authorized: subtle.ConstantTimeCompare([]byte(token), []byte(requiredToken)) == 1}
}

// sessionFromRequest looks up a session by the Mcp-Session-Id header.
// Returns (nil, "") if no header present.
// Returns (nil, sessionID) if header present but session not found or expired.
func sessionFromRequest(r *http.Request, store sessionStore) (sess *mcpSession, sessionID string) {
	sessionID = r.Header.Get(mcpSessionHeader)
	if sessionID == "" {
		return nil, ""
	}
	sess, ok := store.Get(sessionID)
	if !ok {
		return nil, sessionID
	}
	return sess, sessionID
}

// validateSessionToken checks that the bearer token matches the session's token hash.
// Returns an error string if invalid, "" if valid.
// Precondition: sess must not be nil.
func validateSessionToken(sess *mcpSession, token string) string {
	h := sha256.Sum256([]byte(token))
	if h != sess.tokenHash {
		return "token does not match session"
	}
	return ""
}

// resolveVault determines the effective vault for a tool call.
//
// Resolution order (Opus-approved):
//  1. Session pinned vault — if session exists and arg matches or is absent: use session vault
//  2. Session pinned vault — if arg differs: return vault mismatch error
//  3. No session + explicit arg: use arg
//  4. No session + no arg: use "default"
//
// Returns (vault, errMsg). errMsg is non-empty on error.
func resolveVault(sess *mcpSession, args map[string]any) (vault string, errMsg string) {
	argVault, hasArg := vaultFromArgs(args)

	if sess != nil {
		if !hasArg || argVault == "" || argVault == sess.vault {
			return sess.vault, ""
		}
		return "", fmt.Sprintf(
			"vault mismatch: session pinned to %q but tool call specified %q — "+
				"omit vault arg or match the session vault",
			sess.vault, argVault,
		)
	}

	if hasArg && argVault != "" {
		return argVault, ""
	}
	return "default", ""
}

// vaultFromArgs extracts the vault parameter from tool arguments.
// Returns ("", false) if vault is missing or empty.
// Validates that the vault name contains only lowercase letters, digits, hyphens, and underscores (max 64 chars).
func vaultFromArgs(args map[string]any) (string, bool) {
	v, ok := args["vault"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	if !isValidVaultName(s) {
		return "", false
	}
	return s, true
}

// isValidVaultName returns true if name is a valid vault name: 1–64 characters,
// containing only lowercase letters, digits, hyphens, and underscores.
func isValidVaultName(name string) bool {
	return auth.ValidVaultName(name)
}

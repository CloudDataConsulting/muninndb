package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
)

type allVaultsEngine struct{ MockEngine }

func (e *allVaultsEngine) ListVaults(_ context.Context) ([]string, error) {
	return []string{"default", "vault-a", "vault-b", "public-vault"}, nil
}

func decodeVaultList(t *testing.T, recorder *httptest.ResponseRecorder) []string {
	t.Helper()
	var vaults []string
	if err := json.NewDecoder(recorder.Body).Decode(&vaults); err != nil {
		t.Fatalf("decode vault list: %v (body=%s)", err, recorder.Body.String())
	}
	return vaults
}

func TestListVaultsReturnsOnlyAuthorizedFactsUnlessAdmin(t *testing.T) {
	store := newTestAuthStore(t)
	for _, cfg := range []auth.VaultConfig{
		{Name: "default", Public: false},
		{Name: "vault-a", Public: false},
		{Name: "vault-b", Public: false},
		{Name: "public-vault", Public: true},
		{Name: "config-only", Public: false},
	} {
		if err := store.SetVaultConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
	keyA, _, err := store.GenerateAPIKey("vault-a", "a", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("vault-list-admin-session-secret")
	server := NewServer("localhost:0", &allVaultsEngine{}, store, secret, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)
	t.Cleanup(func() {
		select {
		case <-server.shutdown:
		default:
			close(server.shutdown)
		}
	})

	t.Run("scoped API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vaults?vault=vault-a", nil)
		req.Header.Set("Authorization", "Bearer "+keyA)
		writer := httptest.NewRecorder()
		server.mux.ServeHTTP(writer, req)
		if writer.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
		}
		if vaults := decodeVaultList(t, writer); len(vaults) != 1 || vaults[0] != "vault-a" {
			t.Fatalf("vaults=%v, want [vault-a]", vaults)
		}
	})

	t.Run("cross-vault key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vaults?vault=vault-b", nil)
		req.Header.Set("Authorization", "Bearer "+keyA)
		writer := httptest.NewRecorder()
		server.mux.ServeHTTP(writer, req)
		if writer.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s, want 401", writer.Code, writer.Body.String())
		}
	})

	t.Run("anonymous public", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vaults?vault=public-vault", nil)
		writer := httptest.NewRecorder()
		server.mux.ServeHTTP(writer, req)
		if writer.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
		}
		if vaults := decodeVaultList(t, writer); len(vaults) != 1 || vaults[0] != "public-vault" {
			t.Fatalf("vaults=%v, want [public-vault]", vaults)
		}
	})

	t.Run("anonymous private", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vaults?vault=vault-b", nil)
		writer := httptest.NewRecorder()
		server.mux.ServeHTTP(writer, req)
		if writer.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s, want 401", writer.Code, writer.Body.String())
		}
	})

	t.Run("valid admin session", func(t *testing.T) {
		token, err := auth.NewSessionToken("admin", secret)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/vaults", nil)
		req.AddCookie(&http.Cookie{Name: "muninn_session", Value: token})
		writer := httptest.NewRecorder()
		server.mux.ServeHTTP(writer, req)
		if writer.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
		}
		vaults := decodeVaultList(t, writer)
		sort.Strings(vaults)
		want := []string{"config-only", "default", "public-vault", "vault-a", "vault-b"}
		if len(vaults) != len(want) {
			t.Fatalf("admin vaults=%v, want %v", vaults, want)
		}
		for i := range want {
			if vaults[i] != want[i] {
				t.Fatalf("admin vaults=%v, want %v", vaults, want)
			}
		}
	})
}

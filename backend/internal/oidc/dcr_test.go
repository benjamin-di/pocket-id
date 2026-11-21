package oidc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

func setupDCRTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := testutils.NewDatabaseForTest(t)

	require.NoError(t, db.Exec(`INSERT INTO oidc_claim_mapping_policies (id, name, claim_mappings, created_at) VALUES ('policy-mcp', 'MCP API claims', '[]', CURRENT_TIMESTAMP)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO apis (id, name, audience, created_at) VALUES ('api-all', 'Example MCP', 'https://mcp.example.com/all/mcp', CURRENT_TIMESTAMP)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO api_permissions (id, api_id, key, name, created_at) VALUES ('perm-all-use', 'api-all', 'all:use', 'Use all', CURRENT_TIMESTAMP)`).Error)

	return db
}

func postDCR(t *testing.T, handler *dcrHandler, body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/oidc/register", handler.register)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oidc/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestDCR_DisabledWhenAllowlistEmptyOrWildcard(t *testing.T) {
	db := setupDCRTestDB(t)
	for _, allowlist := range [][]string{nil, {}, {"*"}} {
		h := newDCRHandler(db, DCRConfig{RedirectURIAllowlist: allowlist})
		w := postDCR(t, h, map[string]any{
			"client_name":                "Gemini",
			"redirect_uris":              []string{"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-abc"},
			"token_endpoint_auth_method": "none",
		})
		assert.Equal(t, http.StatusNotFound, w.Code)
	}
}

func TestDCR_AllowsGeminiAndLoopbackAndAppliesPolicyAndGrants(t *testing.T) {
	db := setupDCRTestDB(t)
	h := newDCRHandler(db, DCRConfig{
		RedirectURIAllowlist: []string{
			"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-*",
			"http://127.0.0.1/callback",
			"http://localhost/callback",
		},
		AccessTokenDurationMinutes:  15,
		RefreshTokenDurationMinutes: 43200,
		ClaimMappingPolicy:          "MCP API claims",
		AllowedAPIGrants:            []string{"https://mcp.example.com/all/mcp=all:use"},
		MaxClients:                  10,
	})

	geminiURI := "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-0123456789abcdef01234567"
	w := postDCR(t, h, map[string]any{
		"client_name":                "Gemini Connected App",
		"redirect_uris":              []string{geminiURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var resp dcrRegisterResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.ClientID, "dcr-")
	assert.Equal(t, "none", resp.TokenEndpointAuthMethod)
	assert.Equal(t, []string{geminiURI}, resp.RedirectURIs)

	// Verify persisted client settings, claim-mapping policy, and API grant
	var stored model.OidcClient
	require.NoError(t, db.First(&stored, "id = ?", resp.ClientID).Error)
	assert.True(t, stored.IsPublic)
	assert.True(t, stored.PkceEnabled)
	assert.False(t, stored.SkipConsent)
	assert.Equal(t, int64(15), stored.AccessTokenDurationMinutes)
	assert.Equal(t, int64(43200), stored.RefreshTokenDurationMinutes)
	require.NotNil(t, stored.ClaimMappingPolicyId)
	assert.Equal(t, "policy-mcp", *stored.ClaimMappingPolicyId)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, []string(Client{OidcClient: stored}.GetGrantTypes()))

	var apiCount int64
	require.NoError(t, db.Table("oidc_clients_allowed_apis").Where("oidc_client_id = ? AND api_id = ? AND subject_type = ?", resp.ClientID, "api-all", SubjectTypeUser).Count(&apiCount).Error)
	assert.Equal(t, int64(1), apiCount)

	var permCount int64
	require.NoError(t, db.Table("oidc_clients_allowed_api_permissions").Where("oidc_client_id = ? AND api_permission_id = ? AND subject_type = ?", resp.ClientID, "perm-all-use", SubjectTypeUser).Count(&permCount).Error)
	assert.Equal(t, int64(1), permCount)

	// Re-registering the same redirect URI reuses the existing client ID
	w2 := postDCR(t, h, map[string]any{
		"client_name":   "Gemini Connected App",
		"redirect_uris": []string{geminiURI},
	})
	require.Equal(t, http.StatusCreated, w2.Code)
	var resp2 dcrRegisterResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp2))
	assert.Equal(t, resp.ClientID, resp2.ClientID)

	// Ephemeral loopback port matches http://127.0.0.1/callback per RFC 8252
	w3 := postDCR(t, h, map[string]any{
		"client_name":   "Antigravity",
		"redirect_uris": []string{"http://127.0.0.1:45123/callback"},
		"grant_types":   []string{"authorization_code"},
	})
	require.Equal(t, http.StatusCreated, w3.Code, w3.Body.String())

	// Reusing a code-only registration returns the persisted grant_types rather than advertising refresh_token
	w4 := postDCR(t, h, map[string]any{
		"client_name":   "Antigravity",
		"redirect_uris": []string{"http://127.0.0.1:45123/callback"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	require.Equal(t, http.StatusCreated, w4.Code, w4.Body.String())
	var resp4 dcrRegisterResponse
	require.NoError(t, json.Unmarshal(w4.Body.Bytes(), &resp4))
	assert.Equal(t, []string{"authorization_code"}, resp4.GrantTypes)

	// A standard registered client with a dcr- prefix and empty MetadataGrantTypes retains default grants
	standardPrefixed := Client{OidcClient: model.OidcClient{Base: model.Base{ID: "dcr-example"}, ClientType: model.OidcClientTypeStandard}}
	assert.Contains(t, []string(standardPrefixed.GetGrantTypes()), "refresh_token")
	assert.Contains(t, []string(standardPrefixed.GetGrantTypes()), "client_credentials")
}

func TestDCR_RejectsDisallowedURIsAuthMethodsGrantsAndEnforcesCap(t *testing.T) {
	db := setupDCRTestDB(t)
	h := newDCRHandler(db, DCRConfig{
		RedirectURIAllowlist: []string{
			"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-*",
			"http://127.0.0.1/callback",
		},
		MaxClients: 1,
	})

	cases := []struct {
		name string
		body map[string]any
	}{
		{"foreign redirect URI", map[string]any{"redirect_uris": []string{"https://evil.example/callback"}}},
		{"wildcard in requested URI", map[string]any{"redirect_uris": []string{"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-*"}}},
		{"non-loopback http", map[string]any{"redirect_uris": []string{"http://example.com/callback"}}},
		{"confidential client", map[string]any{"redirect_uris": []string{"http://127.0.0.1:9999/callback"}, "token_endpoint_auth_method": "client_secret_basic"}},
		{"client_credentials grant", map[string]any{"redirect_uris": []string{"http://127.0.0.1:9999/callback"}, "grant_types": []string{"client_credentials"}}},
		{"implicit response_type", map[string]any{"redirect_uris": []string{"http://127.0.0.1:9999/callback"}, "response_types": []string{"token"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postDCR(t, h, tc.body)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}

	// Fill capacity of 1, then verify the second distinct client is rejected with 429
	w1 := postDCR(t, h, map[string]any{"redirect_uris": []string{"http://127.0.0.1:11111/callback"}})
	require.Equal(t, http.StatusCreated, w1.Code)
	w2 := postDCR(t, h, map[string]any{"redirect_uris": []string{"http://127.0.0.1:22222/callback"}})
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}

func TestDCR_SanitizeLogRedirectURIs(t *testing.T) {
	got := sanitizeDCRLogRedirectURIs([]string{
		"https://alice:synthetic-password@example.invalid/callback?code=secret#frag",
		"http://127.0.0.1:45123/callback?state=abc",
		"not-a-valid-uri",
	})
	assert.Equal(t, []string{
		"https://example.invalid/callback",
		"http://127.0.0.1:45123/callback",
		"<invalid-uri>",
	}, got)
}

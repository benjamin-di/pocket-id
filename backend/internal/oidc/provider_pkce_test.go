package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
	"github.com/stretchr/testify/require"
)

func TestProviderRequiresS256PKCE(t *testing.T) {
	const (
		issuer    = "https://issuer.example.com"
		callback  = "https://client.example.com/callback"
		clientID  = "pkce-client"
		secret    = "test-client-secret"
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	for _, public := range []bool{true, false} {
		kind := "confidential"
		if public {
			kind = "public"
		}
		t.Run(kind, func(t *testing.T) {
			for _, scenario := range []string{"valid verifier", "wrong verifier", "missing verifier", "plain", "omitted method", "unknown method", "missing challenge"} {
				t.Run(scenario, func(t *testing.T) {
					db := testutils.NewDatabaseForTest(t)
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
					require.NoError(t, db.Create(&model.OidcClient{
						Base: model.Base{ID: clientID}, Name: "PKCE client", IsPublic: public,
						CallbackURLs: datatype.StringList{callback}, Credentials: testClientCredentials(secret),
					}).Error)
					provider, err := newProvider(NewStore(db, nil), nil, testTokenSigner{key: key}, Config{
						BaseURL: issuer, TokenBaseURL: issuer, Secret: []byte("test-secret"),
					}, nil)
					require.NoError(t, err)
					params := url.Values{
						"client_id": {clientID}, "redirect_uri": {callback}, "response_type": {"code"},
						"scope": {"openid"}, "state": {"state-with-enough-entropy"},
						"code_challenge": {challenge}, "code_challenge_method": {"S256"},
					}
					switch scenario {
					case "plain":
						params.Set("code_challenge_method", "plain")
						params.Set("code_challenge", verifier)
					case "omitted method":
						params.Del("code_challenge_method")
						params.Set("code_challenge", verifier)
					case "unknown method":
						params.Set("code_challenge_method", "S512")
					case "missing challenge":
						params.Del("code_challenge")
						params.Del("code_challenge_method")
					}
					request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/authorize?"+params.Encode(), nil)
					authorize, err := provider.NewAuthorizeRequest(t.Context(), request)
					require.NoError(t, err)
					authorize.GrantScope("openid")
					authorize.GrantAudience(clientID)
					session := NewAuthenticatedSession("synthetic-user", "passkey", time.Now(), time.Now())
					code, err := provider.NewAuthorizeResponse(t.Context(), authorize, session)
					if scenario == "plain" || scenario == "omitted method" || scenario == "unknown method" || (scenario == "missing challenge" && public) {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					form := url.Values{
						"grant_type": {"authorization_code"}, "code": {code.GetCode()},
						"client_id": {clientID}, "redirect_uri": {callback}, "code_verifier": {verifier},
					}
					switch scenario {
					case "wrong verifier":
						form.Set("code_verifier", strings.Repeat("w", 64))
					case "missing verifier", "missing challenge":
						form.Del("code_verifier")
					}
					request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, issuer+"/api/oidc/token", strings.NewReader(form.Encode()))
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if !public {
						request.SetBasicAuth(clientID, secret)
					}
					access, err := provider.NewAccessRequest(t.Context(), request, NewEmptySession())
					if scenario == "wrong verifier" || scenario == "missing verifier" {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					token, err := provider.NewAccessResponse(t.Context(), access)
					require.NoError(t, err)
					require.NotEmpty(t, token.GetAccessToken())
				})
			}
		})
	}
}

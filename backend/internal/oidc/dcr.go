package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

const (
	dcrClientIDPrefix             = "dcr-"
	dcrConfidentialClientIDPrefix = "dcr-c-"
	dcrMaxBodyBytes               = 16 * 1024
	dcrMaxRedirectURI             = 25
	dcrMaxClientName              = 100
)

type DCRConfig struct {
	RedirectURIAllowlist        []string
	AccessTokenDurationMinutes  int64
	RefreshTokenDurationMinutes int64
	ClaimMappingPolicy          string
	AllowedAPIGrants            []string
	MaxClients                  int
}

type dcrRegisterRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type dcrRegisterResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type dcrAPIGrantSpec struct {
	Audience    string
	Permissions []string
}

type dcrHandler struct {
	db     *gorm.DB
	config DCRConfig
	mu     sync.Mutex
}

func newDCRHandler(db *gorm.DB, config DCRConfig) *dcrHandler {
	return &dcrHandler{
		db:     db,
		config: config,
	}
}

func writeDCRError(c *gin.Context, status int, code, description string) {
	c.JSON(status, gin.H{
		"error":             code,
		"error_description": description,
	})
}

func (h *dcrHandler) register(c *gin.Context) {
	allowlist := SanitizeDCRAllowlist(h.config.RedirectURIAllowlist)
	if len(allowlist) == 0 {
		writeDCRError(c, http.StatusNotFound, "invalid_client_metadata", "Dynamic client registration is disabled")
		return
	}

	// Enforce a strict request size limit before decoding untrusted JSON
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, dcrMaxBodyBytes+1))
	if err != nil {
		writeDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "Failed to read registration request")
		return
	}
	if len(body) > dcrMaxBodyBytes {
		writeDCRError(c, http.StatusRequestEntityTooLarge, "invalid_client_metadata", "Registration payload is too large")
		return
	}

	var req dcrRegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "Registration payload must be valid JSON")
		return
	}

	canonicalURIs, err := validateDCRRedirectURIs(req.RedirectURIs, allowlist)
	if err != nil {
		slog.WarnContext(
			c.Request.Context(),
			"Rejected dynamic OIDC client redirect_uris",
			"reason", err.Error(),
			"redirect_uri_count", len(req.RedirectURIs),
			"redirect_targets", sanitizeDCRLogRedirectURIs(req.RedirectURIs),
		)
		writeDCRError(c, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
		return
	}

	authMethod, grantTypes, responseTypes, clientName, err := validateDCRMetadata(req, canonicalURIs)
	if err != nil {
		slog.WarnContext(
			c.Request.Context(),
			"Rejected dynamic OIDC client metadata",
			"reason", err.Error(),
			"auth_method_present", strings.TrimSpace(req.TokenEndpointAuthMethod) != "",
			"grant_type_count", len(req.GrantTypes),
			"response_type_count", len(req.ResponseTypes),
		)
		writeDCRError(c, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	grantSpecs, err := parseDCRAPIGrants(h.config.AllowedAPIGrants)
	if err != nil {
		slog.ErrorContext(c.Request.Context(), "Invalid DCR API grant configuration", "error", err)
		writeDCRError(c, http.StatusInternalServerError, "server_error", "Dynamic client registration is misconfigured")
		return
	}

	client, plainSecret, err := h.createOrReuseClient(c.Request.Context(), clientName, canonicalURIs, authMethod, grantTypes, grantSpecs)
	if err != nil {
		var capErr *dcrCapacityError
		if errors.As(err, &capErr) {
			writeDCRError(c, http.StatusTooManyRequests, "invalid_client_metadata", capErr.Error())
			return
		}
		slog.ErrorContext(c.Request.Context(), "Failed to register dynamic OIDC client", "error", err)
		writeDCRError(c, http.StatusInternalServerError, "server_error", "Failed to register dynamic client")
		return
	}

	issuedAt := time.Time(client.CreatedAt).Unix()
	if issuedAt <= 0 {
		issuedAt = time.Now().Unix()
	}

	persistedGrants := []string(client.MetadataGrantTypes)
	if len(persistedGrants) == 0 {
		persistedGrants = grantTypes
	}

	resp := dcrRegisterResponse{
		ClientID:                client.ID,
		ClientIDIssuedAt:        issuedAt,
		ClientName:              client.Name,
		RedirectURIs:            []string(client.CallbackURLs),
		GrantTypes:              persistedGrants,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
	}
	if plainSecret != "" {
		zero := int64(0)
		resp.ClientSecret = plainSecret
		resp.ClientSecretExpiresAt = &zero
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusCreated, resp)
}

type dcrCapacityError struct {
	msg string
}

func (e *dcrCapacityError) Error() string { return e.msg }

// SanitizeDCRAllowlist filters out empty, invalid, and bare-wildcard redirect URI patterns
func SanitizeDCRAllowlist(raw []string) []string {
	cleaned := make([]string, 0, len(raw))
	for _, entry := range raw {
		pattern := strings.TrimSpace(entry)
		// Never accept an empty entry or a bare global wildcard
		if pattern == "" || pattern == "*" {
			continue
		}
		if err := utils.ValidateCallbackURLPattern(pattern); err != nil {
			continue
		}
		cleaned = append(cleaned, pattern)
	}
	return cleaned
}

// sanitizeDCRLogRedirectURIs strips userinfo, query parameters, and fragments before logging.
func sanitizeDCRLogRedirectURIs(uris []string) []string {
	limit := min(len(uris), dcrMaxRedirectURI)
	sanitized := make([]string, 0, limit)
	for _, raw := range uris[:limit] {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			sanitized = append(sanitized, "<invalid-uri>")
			continue
		}
		clean := url.URL{
			Scheme: strings.ToLower(parsed.Scheme),
			Host:   parsed.Host,
			Path:   parsed.Path,
		}
		sanitized = append(sanitized, clean.String())
	}
	return sanitized
}

func dcrClientID(canonicalURIs []string) string {
	encoded, _ := json.Marshal(canonicalURIs)
	sum := sha256.Sum256(encoded)
	return dcrClientIDPrefix + hex.EncodeToString(sum[:12])
}

func dcrConfidentialClientID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("failed to generate dynamic client ID: %w", err)
	}
	return dcrConfidentialClientIDPrefix + hex.EncodeToString(raw[:]), nil
}

func validateDCRRedirectURIs(uris []string, allowlist []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, errors.New("redirect_uris is required")
	}
	if len(uris) > dcrMaxRedirectURI {
		return nil, fmt.Errorf("redirect_uris may contain at most %d entries", dcrMaxRedirectURI)
	}

	seen := make(map[string]struct{}, len(uris))
	canonical := make([]string, 0, len(uris))
	for _, raw := range uris {
		uri := strings.TrimSpace(raw)
		if uri == "" || strings.Contains(uri, "*") {
			return nil, errors.New("redirect_uris must contain exact URIs without wildcards")
		}
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, errors.New("redirect_uris must be valid absolute URLs")
		}
		if parsed.Fragment != "" || parsed.User != nil {
			return nil, errors.New("redirect_uris must not contain fragments or userinfo")
		}
		scheme := strings.ToLower(parsed.Scheme)
		host := strings.ToLower(parsed.Hostname())
		if scheme == "http" {
			if host != "127.0.0.1" && host != "::1" && host != "localhost" {
				return nil, errors.New("http redirect_uris are permitted only for loopback hosts")
			}
		} else if scheme != "https" {
			return nil, errors.New("redirect_uris must use https or loopback http")
		}

		matched, err := utils.GetCallbackURLFromList(allowlist, uri)
		if err != nil || matched == "" {
			return nil, errors.New("redirect_uri is not permitted by this server")
		}

		if _, exists := seen[uri]; !exists {
			seen[uri] = struct{}{}
			canonical = append(canonical, uri)
		}
	}

	slices.Sort(canonical)
	return canonical, nil
}

func validateDCRMetadata(req dcrRegisterRequest, canonicalURIs []string) (string, []string, []string, string, error) {
	authMethod := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	switch authMethod {
	case "none":
	case "client_secret_basic", "client_secret_post":
		for _, uri := range canonicalURIs {
			parsed, err := url.Parse(uri)
			if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
				return "", nil, nil, "", errors.New("confidential dynamic clients require https redirect_uris")
			}
		}
	default:
		return "", nil, nil, "", errors.New("token_endpoint_auth_method is not permitted")
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	} else {
		hasAuthCode := false
		for _, g := range grantTypes {
			switch g {
			case "authorization_code":
				hasAuthCode = true
			case "refresh_token":
			default:
				return "", nil, nil, "", errors.New("grant_type is not permitted")
			}
		}
		if !hasAuthCode {
			return "", nil, nil, "", errors.New("grant_types must include authorization_code")
		}
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	} else {
		for _, rt := range responseTypes {
			if rt != "code" {
				return "", nil, nil, "", errors.New("response_type is not permitted")
			}
		}
	}

	clientName := strings.TrimSpace(req.ClientName)
	if clientName == "" {
		clientName = "Dynamic OAuth Client"
	}
	if len(clientName) > dcrMaxClientName {
		clientName = clientName[:dcrMaxClientName]
	}

	return authMethod, grantTypes, responseTypes, clientName, nil
}

func parseDCRAPIGrants(entries []string) ([]dcrAPIGrantSpec, error) {
	specs := make([]dcrAPIGrantSpec, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		audience, rawPerms, ok := strings.Cut(trimmed, "=")
		audience = strings.TrimSpace(audience)
		if !ok || audience == "" {
			return nil, fmt.Errorf("invalid DCR API grant %q: expected <audience>=<perm1>|<perm2>", trimmed)
		}
		var perms []string
		for p := range strings.SplitSeq(rawPerms, "|") {
			p = strings.TrimSpace(p)
			if p != "" {
				perms = append(perms, p)
			}
		}
		if len(perms) == 0 {
			return nil, fmt.Errorf("invalid DCR API grant %q: at least one permission is required", trimmed)
		}
		specs = append(specs, dcrAPIGrantSpec{Audience: audience, Permissions: perms})
	}
	return specs, nil
}

func (h *dcrHandler) createOrReuseClient(ctx context.Context, clientName string, canonicalURIs []string, authMethod string, grantTypes []string, grantSpecs []dcrAPIGrantSpec) (model.OidcClient, string, error) {
	// Serialize deduplication, capacity checking, and insertion so concurrent registrations cannot exceed the cap
	h.mu.Lock()
	defer h.mu.Unlock()

	tx := h.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	isPublic := authMethod == "none"
	var clientID string
	if isPublic {
		// Deduplicate repeated public registrations via deterministic primary key derived from the canonical redirect URI set
		clientID = dcrClientID(canonicalURIs)
		var existing model.OidcClient
		err := tx.First(&existing, "id = ?", clientID).Error
		if err == nil {
			if err := tx.Commit().Error; err != nil {
				return model.OidcClient{}, "", err
			}
			return existing, "", nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return model.OidcClient{}, "", err
		}
	} else {
		// Issue a fresh isolated client ID and secret per confidential registration so prior registrations are never overwritten or exposed
		var err error
		clientID, err = dcrConfidentialClientID()
		if err != nil {
			return model.OidcClient{}, "", err
		}
	}

	var count int64
	if err := tx.Model(&model.OidcClient{}).Where("id LIKE ?", dcrClientIDPrefix+"%").Count(&count).Error; err != nil {
		return model.OidcClient{}, "", err
	}

	maxClients := h.config.MaxClients
	if maxClients <= 0 {
		maxClients = 200
	}
	if int(count) >= maxClients {
		return model.OidcClient{}, "", &dcrCapacityError{msg: "dynamic client registration capacity reached"}
	}

	// Resolve the optional claim-mapping policy before inserting the client, avoiding UUID type errors on Postgres when matching by name
	var policyID *string
	if policySelector := strings.TrimSpace(h.config.ClaimMappingPolicy); policySelector != "" {
		var row struct{ ID string }
		query := tx.Table("oidc_claim_mapping_policies").Select("id")
		if _, parseErr := uuid.Parse(policySelector); parseErr == nil {
			query = query.Where("id = ?", policySelector)
		} else {
			query = query.Where("name = ?", policySelector)
		}
		if err := query.Take(&row).Error; err != nil {
			return model.OidcClient{}, "", fmt.Errorf("claim mapping policy %q not found: %w", policySelector, err)
		}
		policyID = &row.ID
	}

	accessMinutes := h.config.AccessTokenDurationMinutes
	if !model.IsValidTokenDurationMinutes(accessMinutes) {
		accessMinutes = 15
	}
	refreshMinutes := h.config.RefreshTokenDurationMinutes
	if !model.IsValidTokenDurationMinutes(refreshMinutes) {
		refreshMinutes = model.DefaultRefreshTokenDurationMinutes
	}

	now := datatype.DateTime(time.Now())
	var (
		plainSecret string
		credentials model.OidcClientCredentials
	)
	if !isPublic {
		var err error
		plainSecret, err = utils.GenerateRandomAlphanumericString(32)
		if err != nil {
			return model.OidcClient{}, "", fmt.Errorf("failed to generate dynamic client secret: %w", err)
		}
		credentials.Secrets = []model.OidcClientSecret{
			{
				ID:        uuid.NewString(),
				Algorithm: model.OidcClientSecretHashSHA256,
				Hash:      utils.CreateSha256Hash(plainSecret),
				Prefix:    plainSecret[:model.OidcClientSecretPrefixLength],
				CreatedAt: now,
			},
		}
	}

	client := model.OidcClient{
		Base: model.Base{
			ID:        clientID,
			CreatedAt: now,
		},
		Name:                        clientName,
		CallbackURLs:                datatype.StringList(canonicalURIs),
		IsPublic:                    isPublic,
		PkceEnabled:                 true,
		PkceSupported:               true,
		SkipConsent:                 false,
		RequiresReauthentication:    false,
		Credentials:                 credentials,
		ClientType:                  model.OidcClientTypeStandard,
		MetadataGrantTypes:          datatype.StringList(grantTypes),
		AccessTokenDurationMinutes:  accessMinutes,
		RefreshTokenDurationMinutes: refreshMinutes,
		ClaimMappingPolicyId:        policyID,
	}

	if err := tx.Create(&client).Error; err != nil {
		return model.OidcClient{}, "", err
	}

	// Attach configured user-delegated API grants atomically within the same transaction
	for _, spec := range grantSpecs {
		var apiRow struct{ ID string }
		if err := tx.Table("apis").Select("id").Where("audience = ?", spec.Audience).Take(&apiRow).Error; err != nil {
			return model.OidcClient{}, "", fmt.Errorf("API audience %q not found: %w", spec.Audience, err)
		}

		var permRows []struct {
			ID  string
			Key string
		}
		if err := tx.Table("api_permissions").
			Select("id, key").
			Where("api_id = ? AND key IN ?", apiRow.ID, spec.Permissions).
			Find(&permRows).Error; err != nil {
			return model.OidcClient{}, "", err
		}
		if len(permRows) != len(spec.Permissions) {
			return model.OidcClient{}, "", fmt.Errorf("one or more permissions missing on API %q", spec.Audience)
		}

		if err := tx.Table("oidc_clients_allowed_apis").Create(map[string]any{
			"oidc_client_id": client.ID,
			"api_id":         apiRow.ID,
			"subject_type":   SubjectTypeUser,
		}).Error; err != nil {
			return model.OidcClient{}, "", err
		}

		for _, perm := range permRows {
			if err := tx.Table("oidc_clients_allowed_api_permissions").Create(map[string]any{
				"oidc_client_id":    client.ID,
				"api_permission_id": perm.ID,
				"subject_type":      SubjectTypeUser,
			}).Error; err != nil {
				return model.OidcClient{}, "", err
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		return model.OidcClient{}, "", err
	}

	return client, plainSecret, nil
}

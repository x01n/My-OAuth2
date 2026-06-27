package handler

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"server/internal/config"
	"server/internal/model"
	"server/internal/repository"
	"server/internal/service"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

type SAMLAuthHandler struct {
	providerRepo    *repository.SAMLProviderRepository
	samlAuthService *service.SAMLAuthService
	cfg             *config.Config
	baseURL         string
	frontendURL     string
	webhookService  *service.WebhookService
}

func NewSAMLAuthHandler(
	providerRepo *repository.SAMLProviderRepository,
	samlAuthService *service.SAMLAuthService,
	cfg *config.Config,
	baseURL string,
	frontendURL string,
) *SAMLAuthHandler {
	return &SAMLAuthHandler{
		providerRepo:    providerRepo,
		samlAuthService: samlAuthService,
		cfg:             cfg,
		baseURL:         strings.TrimRight(baseURL, "/"),
		frontendURL:     strings.TrimRight(frontendURL, "/"),
	}
}

func (h *SAMLAuthHandler) SetWebhookService(ws *service.WebhookService) {
	h.webhookService = ws
}

func (h *SAMLAuthHandler) StartLogin(c *gin.Context) {
	provider, err := h.enabledProvider(c)
	if err != nil {
		samlRedirectWithError(c, err.Error())
		return
	}
	sp, tracker, err := h.serviceProvider(c, provider)
	if err != nil {
		samlRedirectWithError(c, "Failed to initialize SAML provider")
		return
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := sp.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = sp.GetSSOBindingLocation(binding)
	}
	if bindingLocation == "" {
		samlRedirectWithError(c, "SAML provider does not expose a supported SSO binding")
		return
	}

	authReq, err := sp.MakeAuthenticationRequest(bindingLocation, binding, saml.HTTPPostBinding)
	if err != nil {
		samlRedirectWithError(c, "Failed to build SAML authentication request")
		return
	}
	relayState, err := tracker.TrackRequest(c.Writer, c.Request, authReq.ID)
	if err != nil {
		samlRedirectWithError(c, "Failed to track SAML request")
		return
	}

	returnTo := safeReturnPath(c.Query("return_to"))
	setCookie(c, samlReturnCookieName(provider.Slug), returnTo, 600, "/", isRequestSecure(c), true, http.SameSiteLaxMode)

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, sp)
		if err != nil {
			samlRedirectWithError(c, "Failed to redirect to SAML identity provider")
			return
		}
		c.Redirect(http.StatusFound, redirectURL.String())
		return
	}

	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; form-action *; base-uri 'none'; frame-ancestors 'none'")
	c.Data(http.StatusOK, "text/html; charset=utf-8", authReq.Post(relayState))
}

func (h *SAMLAuthHandler) ACS(c *gin.Context) {
	provider, err := h.provider(c)
	if err != nil || !provider.Enabled {
		samlRedirectWithError(c, "SAML provider not found or disabled")
		return
	}
	sp, tracker, err := h.serviceProvider(c, provider)
	if err != nil {
		samlRedirectWithError(c, "Failed to initialize SAML provider")
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		samlRedirectWithError(c, "Invalid SAML response")
		return
	}

	possibleRequestIDs := []string{}
	if provider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}
	for _, tracked := range tracker.GetTrackedRequests(c.Request) {
		possibleRequestIDs = append(possibleRequestIDs, tracked.SAMLRequestID)
	}

	assertion, err := sp.ParseResponse(c.Request, possibleRequestIDs)
	if err != nil {
		samlRedirectWithError(c, "Invalid SAML response")
		return
	}
	profile, err := h.samlAuthService.ProfileFromAssertion(provider, assertion)
	if err != nil {
		samlRedirectWithError(c, "Invalid SAML assertion")
		return
	}
	user, tokens, err := h.samlAuthService.Login(service.SAMLLoginInput{
		Provider:  provider,
		Profile:   *profile,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		h.redirectSAMLServiceError(c, err)
		return
	}

	if relayState := c.PostForm("RelayState"); relayState != "" {
		_ = tracker.StopTrackingRequest(c.Writer, c.Request, relayState)
	}

	returnTo, cookieErr := c.Cookie(samlReturnCookieName(provider.Slug))
	if cookieErr != nil || returnTo == "" {
		returnTo = safeReturnPath(c.PostForm("RelayState"))
	} else {
		returnTo = safeReturnPath(returnTo)
	}
	setCookie(c, samlReturnCookieName(provider.Slug), "", -1, "/", isRequestSecure(c), true, http.SameSiteLaxMode)

	if h.webhookService != nil {
		go h.webhookService.TriggerEvent(context.Background(), uuid.Nil, model.WebhookEventUserLogin, map[string]any{
			"user_id":  user.ID.String(),
			"email":    user.Email,
			"username": user.Username,
			"source":   "saml",
		})
	}
	EmitAuthEvent(AuthEvent{
		Type:      "user_login",
		AppID:     "",
		AppName:   "System",
		UserID:    user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		Timestamp: time.Now(),
	})

	refreshMaxAge := 30 * 24 * 3600
	if h.cfg != nil {
		refreshMaxAge = h.cfg.JWT.RefreshTokenTTLDays * 24 * 3600
	}
	setAuthTokenCookies(c, tokens, refreshMaxAge)
	c.Redirect(http.StatusFound, returnTo)
}

func (h *SAMLAuthHandler) Metadata(c *gin.Context) {
	provider, err := h.provider(c)
	if err != nil {
		NotFound(c, "SAML provider not found")
		return
	}
	sp, _, err := h.serviceProvider(c, provider)
	if err != nil {
		InternalError(c, "Failed to initialize SAML metadata")
		return
	}
	buf, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		InternalError(c, "Failed to render SAML metadata")
		return
	}
	c.Data(http.StatusOK, "application/samlmetadata+xml; charset=utf-8", buf)
}

func (h *SAMLAuthHandler) enabledProvider(c *gin.Context) (*model.SAMLProvider, error) {
	provider, err := h.provider(c)
	if err != nil {
		return nil, fmt.Errorf("SAML provider not found")
	}
	if !provider.Enabled {
		return nil, fmt.Errorf("SAML provider is disabled")
	}
	return provider, nil
}

func (h *SAMLAuthHandler) provider(c *gin.Context) (*model.SAMLProvider, error) {
	return h.providerRepo.FindBySlug(c.Param("slug"))
}

func (h *SAMLAuthHandler) serviceProvider(c *gin.Context, provider *model.SAMLProvider) (*saml.ServiceProvider, *samlsp.CookieRequestTracker, error) {
	metadata, err := samlsp.ParseMetadata([]byte(provider.MetadataXML))
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := parseRSAPrivateKeyPEM(provider.PrivateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := parseCertificatePEM(provider.CertificatePEM)
	if err != nil {
		return nil, nil, err
	}
	root := h.requestBackendRoot(c.Request)
	metadataURL, err := url.Parse(root + "/api/federation/saml/" + provider.Slug + "/metadata")
	if err != nil {
		return nil, nil, err
	}
	acsURL, err := url.Parse(root + "/api/federation/saml/" + provider.Slug + "/acs")
	if err != nil {
		return nil, nil, err
	}
	entityID := strings.TrimSpace(provider.SPEntityID)
	if entityID == "" {
		entityID = metadataURL.String()
	}
	sp := &saml.ServiceProvider{
		EntityID:              entityID,
		Key:                   privateKey,
		Certificate:           certificate,
		MetadataURL:           *metadataURL,
		AcsURL:                *acsURL,
		IDPMetadata:           metadata,
		AllowIDPInitiated:     provider.AllowIDPInitiated,
		DefaultRedirectURI:    safeReturnPath(provider.DefaultRedirectPath),
		AuthnNameIDFormat:     saml.NameIDFormat(provider.NameIDFormat),
		MetadataValidDuration: 48 * time.Hour,
	}
	if provider.SignRequests {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	trackerURL := *metadataURL
	trackerURL.Path = strings.TrimSuffix(metadataURL.Path, "/metadata") + "/"
	trackerOpts := samlsp.Options{
		URL:            trackerURL,
		Key:            privateKey,
		Certificate:    certificate,
		CookieSameSite: http.SameSiteLaxMode,
	}
	tracker := &samlsp.CookieRequestTracker{
		ServiceProvider: sp,
		NamePrefix:      "saml_" + provider.Slug + "_",
		Codec:           samlsp.DefaultTrackedRequestCodec(trackerOpts),
		MaxAge:          saml.MaxIssueDelay,
		SameSite:        http.SameSiteLaxMode,
	}
	return sp, tracker, nil
}

func (h *SAMLAuthHandler) requestBackendRoot(r *http.Request) string {
	if r != nil {
		host := requestHost(r)
		if host != "" && !isUnusablePublicHost(host) {
			return requestScheme(r) + "://" + host
		}
	}
	if h.baseURL != "" {
		return h.baseURL
	}
	return "http://localhost"
}

func (h *SAMLAuthHandler) redirectSAMLServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrEnterpriseProviderDisabled):
		samlRedirectWithError(c, "SAML provider is disabled")
	case errors.Is(err, service.ErrExternalEmailConflict):
		samlRedirectWithError(c, "Email already registered; please sign in first and link the provider manually")
	case errors.Is(err, service.ErrEnterpriseUserNotFound):
		samlRedirectWithError(c, "SAML user is not allowed")
	case errors.Is(err, service.ErrInvalidCredentials):
		samlRedirectWithError(c, "SAML user is disabled")
	default:
		samlRedirectWithError(c, "Failed to process SAML login")
	}
}

func parseRSAPrivateKeyPEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

func parseCertificatePEM(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func samlReturnCookieName(slug string) string {
	return "saml_return_" + slug
}

func samlRedirectWithError(c *gin.Context, msg string) {
	c.Redirect(http.StatusFound, "/login?error="+url.QueryEscape(msg))
}

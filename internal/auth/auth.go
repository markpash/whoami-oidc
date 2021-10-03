package auth

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	uuid "github.com/nu7hatch/gouuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
)

type AuthConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string

	CallbackPath string
	BaseURL      string
	ProviderURL  string

	SessionDuration time.Duration
}

type AuthState struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier

	sessions *cache.Cache
	states   *cache.Cache

	sessionDuration time.Duration
}

func NewAuthState(ctx context.Context, cfg AuthConfig) (*AuthState, error) {
	q, err := url.Parse(cfg.CallbackPath)
	if err != nil {
		return nil, err
	}

	callbackURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	callbackURL = callbackURL.ResolveReference(q)

	provider, err := oidc.NewProvider(ctx, cfg.ProviderURL)
	if err != nil {
		return nil, err
	}

	state := AuthState{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  callbackURL.String(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: cfg.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),

		sessions: cache.New(cfg.SessionDuration, cfg.SessionDuration),
		states:   cache.New(time.Minute, time.Minute),

		sessionDuration: cfg.SessionDuration,
	}

	return &state, nil
}

func (s *AuthState) AuthCodeURL(state string) string {
	return s.config.AuthCodeURL(state)
}

func (s *AuthState) GetSessionDuration() time.Duration {
	return s.sessionDuration
}

func (s *AuthState) StoreFlowState(fs AuthFlowState) (string, error) {
	// generate a nonce state string
	state, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	s.states.Set(state.String(), &fs, cache.DefaultExpiration)

	return state.String(), nil
}

func (s *AuthState) GetFlowState(key string) (*AuthFlowState, error) {
	// check if the state was created by us
	ret, ok := s.states.Get(key)
	if !ok {
		return nil, errors.New("couldn't retrieve state")
	}

	// if the state was created by us, then retrieve what the state refers to
	// and use it to guide the request back to the original URL.
	fs, ok := ret.(*AuthFlowState)
	if !ok {
		return nil, errors.New("couldn't retrieve state")
	}

	return fs, nil
}

func (s *AuthState) CreateSession(ctx context.Context, code string) (string, error) {
	oauth2Token, err := s.config.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	sessionToken, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	s.sessions.Set(sessionToken.String(), oauth2Token, cache.DefaultExpiration)

	return sessionToken.String(), nil
}

func (s *AuthState) GetSession(key string) (*oauth2.Token, error) {
	ret, ok := s.sessions.Get(key)
	if !ok {
		return nil, errors.New("couldn't retrieve session")
	}

	token, ok := ret.(*oauth2.Token)
	if !ok {
		return nil, errors.New("couldn't retrieve session")
	}

	return token, nil
}

func (s *AuthState) GetIdentity(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("failed to extract id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	var claims oidc.UserInfo
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// AuthFlowState is a state that is stored server-side, it can be
// retrieved using the string in the "state" query parameter in the
// OIDC standard-flow.
type AuthFlowState struct {
	RedirectURL string
}

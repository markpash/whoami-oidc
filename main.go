package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/markpash/whoami-oidc/internal/auth"

	oidc "github.com/coreos/go-oidc/v3/oidc"
)

var authState *auth.AuthState

func main() {
	ctx := context.Background()

	authConfig := auth.AuthConfig{
		ClientID:        "",
		ClientSecret:    "",
		Scopes:          []string{oidc.ScopeOpenID, "profile", "email"},
		CallbackPath:    "/auth/callback",
		BaseURL:         "",
		ProviderURL:     "",
		SessionDuration: 2 * time.Minute,
	}

	as, err := auth.NewAuthState(ctx, authConfig)
	if err != nil {
		panic(err)
	}
	authState = as

	http.HandleFunc("/", index)
	http.HandleFunc("/secret", secret)

	http.HandleFunc(authConfig.CallbackPath, authCallback)

	log.Fatal(http.ListenAndServe(":9090", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "<html>this is a public page, try going to a <a href=\"/secret\">secret</a> one!</html>")
}

func secret(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		authRedirect(w, r)
		return
	}

	oauthToken, err := authState.GetSession(sessionToken.Value)
	if err != nil {
		authRedirect(w, r)
		return
	}

	identity, err := authState.GetIdentity(ctx, oauthToken)
	if err != nil {
		authRedirect(w, r)
		return
	}

	fmt.Fprintf(w, "%+v", identity)
}

func authCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// if the state was created by us, then retrieve what the state refers to
	// and use it to guide the request back to the original URL.
	fs, err := authState.GetFlowState(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	sessionToken, err := authState.CreateSession(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(authState.GetSessionDuration()),
	})

	http.Redirect(w, r, fs.RedirectURL, http.StatusFound)
}

func authRedirect(w http.ResponseWriter, r *http.Request) {
	state, err := authState.StoreFlowState(auth.AuthFlowState{
		RedirectURL: r.RequestURI,
	})
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authState.AuthCodeURL(state), http.StatusFound)
}

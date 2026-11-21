package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// keycloakSub resolves a portal username to the Keycloak subject (the user's
// id). It fails closed: not configured, any HTTP failure, no user and several
// users are all errors, and it never guesses a sub. The secret is read per
// call and never logged or put in an error.

const (
	keycloakTimeout = 5 * time.Second
	keycloakMaxBody = 1 << 20
)

func (e *Execution) keycloakSub(username string) (string, error) {
	c := e.P.Config
	if c.KeycloakURL == "" || c.KeycloakRealm == "" || c.KeycloakClientID == "" || c.KeycloakClientSecretFile == "" {
		return "", errors.New("keycloak lookup is not configured")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", errors.New("keycloak lookup needs a username")
	}
	secret, err := os.ReadFile(c.KeycloakClientSecretFile)
	if err != nil || strings.TrimSpace(string(secret)) == "" {
		return "", errors.New("keycloak client secret is unreadable")
	}
	ctx, cancel := context.WithTimeout(e.Ctx, keycloakTimeout)
	defer cancel()
	// A redirect is never followed: it would carry the credential elsewhere.
	client := &http.Client{Timeout: keycloakTimeout, Transport: e.P.HTTP.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimRight(c.KeycloakURL, "/") + "/realms/" + url.PathEscape(c.KeycloakRealm)

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.KeycloakClientID}, "client_secret": {strings.TrimSpace(string(secret))}}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("keycloak token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := keycloakJSON(client, req, &token); err != nil {
		return "", fmt.Errorf("keycloak token: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("keycloak token: empty access token")
	}

	adminURL := strings.TrimRight(c.KeycloakURL, "/") + "/admin/realms/" + url.PathEscape(c.KeycloakRealm) + "/users?exact=true&username=" + url.QueryEscape(username)
	req, err = http.NewRequestWithContext(ctx, "GET", adminURL, nil)
	if err != nil {
		return "", errors.New("keycloak user request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := keycloakJSON(client, req, &users); err != nil {
		return "", fmt.Errorf("keycloak users: %w", err)
	}
	// Keycloak stores usernames in lower case and honours exact=true. Any
	// other shape is refused: every row for the name counts, and the one id
	// must be set.
	var hits []string
	for _, u := range users {
		if u.Username == username {
			hits = append(hits, u.ID)
		}
	}
	switch len(hits) {
	case 1:
		if hits[0] == "" {
			return "", fmt.Errorf("keycloak user %q has no id", username)
		}
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("keycloak has no user %q", username)
	}
	return "", fmt.Errorf("keycloak has %d users named %q", len(hits), username)
}

func keycloakJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, keycloakMaxBody+1))
	if err != nil {
		return errors.New("read failed")
	}
	if len(body) > keycloakMaxBody {
		return errors.New("response too large")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("bad response")
	}
	return nil
}

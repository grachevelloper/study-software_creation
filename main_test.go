package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func testApp(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	app, err := newApp(Config{DatabasePath: filepath.Join(t.TempDir(), "test.db"), JWTSecret: "test-secret", AccessTTL: 900000000000, RefreshTTL: 604800000000000})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(func() { server.Close(); app.Close() })
	return app, server
}

func requestJSON(t *testing.T, client *http.Client, method, url string, body any, token string, expected int) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected {
		t.Fatalf("%s %s: got %d, want %d: %s", method, url, response.StatusCode, expected, raw)
	}
	if len(raw) == 0 {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode response: %v: %s", err, raw)
	}
	return result
}

func TestFullUserAndSharingFlow(t *testing.T) {
	_, server := testApp(t)
	client := server.Client()
	base := server.URL + "/api/v1"
	credentials := map[string]any{"login": "alice", "password": "strong-pass"}
	user := requestJSON(t, client, http.MethodPost, base+"/auth/register", credentials, "", http.StatusCreated)
	if user["createdAt"] == nil {
		t.Fatal("registration response has no createdAt")
	}
	session := requestJSON(t, client, http.MethodPost, base+"/auth/login", credentials, "", http.StatusOK)
	access := session["accessToken"].(string)
	n := requestJSON(t, client, http.MethodPost, base+"/notes", map[string]any{"title": "Test", "markdown": "# Hello", "lifetimeDays": 7}, access, http.StatusCreated)
	if n["revision"].(float64) != 1 {
		t.Fatalf("unexpected revision: %v", n["revision"])
	}
	id := n["id"].(string)
	loaded := requestJSON(t, client, http.MethodGet, base+"/notes/"+id, nil, access, http.StatusOK)
	if loaded["title"] != "Test" {
		t.Fatalf("unexpected title: %v", loaded["title"])
	}
	readToken := requestJSON(t, client, http.MethodPost, base+"/notes/"+id+"/tokens", map[string]any{"type": "READ", "expiresInMinutes": 60}, access, http.StatusCreated)
	shared := requestJSON(t, client, http.MethodGet, base+"/notes/shared/"+readToken["token"].(string), nil, "", http.StatusOK)
	if shared["markdown"] != "# Hello" {
		t.Fatalf("unexpected markdown: %v", shared["markdown"])
	}
	requestJSON(t, client, http.MethodPatch, base+"/notes/shared/"+readToken["token"].(string), map[string]any{"markdown": "denied", "revision": 1}, "", http.StatusForbidden)
	writeToken := requestJSON(t, client, http.MethodPost, base+"/notes/"+id+"/tokens", map[string]any{"type": "WRITE"}, access, http.StatusCreated)
	updated := requestJSON(t, client, http.MethodPatch, base+"/notes/shared/"+writeToken["token"].(string), map[string]any{"markdown": "# Updated", "revision": 1}, "", http.StatusOK)
	if updated["revision"].(float64) != 2 {
		t.Fatalf("unexpected revision: %v", updated["revision"])
	}
	requestJSON(t, client, http.MethodPatch, base+"/notes/"+id, map[string]any{"markdown": "stale", "revision": 1}, access, http.StatusConflict)
	refreshed := requestJSON(t, client, http.MethodPost, base+"/auth/refresh", map[string]any{"refreshToken": session["refreshToken"]}, "", http.StatusOK)
	requestJSON(t, client, http.MethodPost, base+"/auth/logout", map[string]any{"refreshToken": refreshed["refreshToken"]}, "", http.StatusNoContent)
}

func TestHealthAndStaticPage(t *testing.T) {
	_, server := testApp(t)
	client := server.Client()
	health := requestJSON(t, client, http.MethodGet, server.URL+"/health/ready", nil, "", http.StatusOK)
	if health["status"] != "ok" {
		t.Fatalf("unexpected health: %v", health)
	}
	response, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if !bytes.Contains(body, []byte("Markdown Notes")) {
		t.Fatal("static page was not served")
	}
}

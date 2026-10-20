package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var baseURL = "http://127.0.0.1:8080"

func request(method, path string, body any, token string, expected ...int) map[string]any {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		panic(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	valid := false
	for _, status := range expected {
		valid = valid || res.StatusCode == status
	}
	if !valid {
		panic(fmt.Sprintf("%s %s: HTTP %d: %s", method, path, res.StatusCode, raw))
	}
	if len(raw) == 0 {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}

func main() {
	if len(os.Args) > 1 {
		baseURL = strings.TrimRight(os.Args[1], "/")
	}
	fmt.Println("1/7 health", request("GET", "/health/ready", nil, "", 200))
	credentials := map[string]any{"login": fmt.Sprintf("smoke%d", time.Now().UnixMilli()), "password": "smoke-password"}
	user := request("POST", "/api/v1/auth/register", credentials, "", 201)
	fmt.Println("2/7 register", user["id"])
	session := request("POST", "/api/v1/auth/login", credentials, "", 200)
	fmt.Println("3/7 login", session["expiresAt"])
	note := request("POST", "/api/v1/notes", map[string]any{"title": "Smoke test", "markdown": "# Deployment works", "lifetimeDays": 7}, session["accessToken"].(string), 201)
	fmt.Println("4/7 note", note["id"])
	share := request("POST", fmt.Sprintf("/api/v1/notes/%s/tokens", note["id"]), map[string]any{"type": "READ", "expiresInMinutes": 5}, session["accessToken"].(string), 201)
	fmt.Println("5/7 share", share["type"])
	public := request("GET", "/api/v1/notes/shared/"+share["token"].(string), nil, "", 200)
	fmt.Println("6/7 public read", public["title"])
	request("PATCH", "/api/v1/notes/shared/"+share["token"].(string), map[string]any{"markdown": "forbidden", "revision": 1}, "", 403)
	fmt.Println("7/7 READ token write rejected with 403")
	fmt.Println("SMOKE TEST PASSED")
}

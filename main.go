package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const maxBodyBytes = 2 * 1024 * 1024

var loginPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,40}$`)

//go:embed static/*
var staticFiles embed.FS

type Config struct {
	DatabasePath string
	JWTSecret    string
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
}

type App struct {
	db         *sql.DB
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	handler    http.Handler
	requests   atomic.Uint64
	errors     atomic.Uint64
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

type user struct {
	ID           string
	Login        string
	PasswordHash string
	CreatedAt    string
}

type note struct {
	ID          string `json:"id"`
	OwnerUserID string `json:"-"`
	Title       string `json:"title"`
	Markdown    string `json:"markdown"`
	Revision    int    `json:"revision"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	ExpiredAt   string `json:"expiredAt"`
}

type claims struct {
	Sub   string `json:"sub"`
	Login string `json:"login"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

func defaultConfig() Config {
	accessSeconds := envInt("ACCESS_TTL_SECONDS", 900)
	refreshSeconds := envInt("REFRESH_TTL_SECONDS", 604800)
	return Config{
		DatabasePath: envString("DATABASE_PATH", filepath.Join("data", "notes.db")),
		JWTSecret:    envString("JWT_SECRET", "local-development-secret-change-me"),
		AccessTTL:    time.Duration(accessSeconds) * time.Second,
		RefreshTTL:   time.Duration(refreshSeconds) * time.Second,
	}
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func newApp(cfg Config) (*App, error) {
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(cfg.DatabasePath) + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(8)
	app := &App{db: db, secret: []byte(cfg.JWTSecret), accessTTL: cfg.AccessTTL, refreshTTL: cfg.RefreshTTL}
	if err := app.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	app.handler = app.routes()
	return app, nil
}

func (a *App) Close() error { return a.db.Close() }

func (a *App) initSchema() error {
	_, err := a.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    digest TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    markdown TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expired_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS share_tokens (
    digest TEXT PRIMARY KEY,
    note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('READ', 'WRITE')),
    expires_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_notes_expired ON notes(expired_at);
CREATE INDEX IF NOT EXISTS idx_share_note ON share_tokens(note_id);
`)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	return nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", a.wrap(a.healthLive))
	mux.HandleFunc("GET /health/ready", a.wrap(a.healthReady))
	mux.HandleFunc("GET /metrics", a.wrap(a.metrics))
	mux.HandleFunc("POST /api/v1/auth/register", a.wrap(a.register))
	mux.HandleFunc("POST /api/v1/auth/login", a.wrap(a.login))
	mux.HandleFunc("POST /api/v1/auth/refresh", a.wrap(a.refresh))
	mux.HandleFunc("POST /api/v1/auth/logout", a.wrap(a.logout))
	mux.HandleFunc("POST /api/v1/notes", a.wrap(a.createNote))
	mux.HandleFunc("GET /api/v1/notes/{id}", a.wrap(a.ownNote))
	mux.HandleFunc("PATCH /api/v1/notes/{id}", a.wrap(a.ownNote))
	mux.HandleFunc("POST /api/v1/notes/{id}/tokens", a.wrap(a.createShareToken))
	mux.HandleFunc("GET /api/v1/notes/shared/{token}", a.wrap(a.sharedNote))
	mux.HandleFunc("PATCH /api/v1/notes/shared/{token}", a.wrap(a.sharedNote))

	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(staticRoot))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		content, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	})
	return a.securityHeaders(mux)
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	a.handler.ServeHTTP(w, r)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/health/") {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

type endpoint func(http.ResponseWriter, *http.Request) error

func (a *App) wrap(fn endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			a.errors.Add(1)
			var apiErr *apiError
			if errors.As(err, &apiErr) {
				writeJSON(w, apiErr.status, map[string]string{"error": apiErr.message})
				return
			}
			if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "Объект уже существует"})
				return
			}
			log.Printf("unhandled error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Внутренняя ошибка"})
		}
	}
}

func fail(status int, message string) error { return &apiError{status: status, message: message} }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func readJSON(r *http.Request, value any) error {
	if r.ContentLength > maxBodyBytes {
		return fail(http.StatusRequestEntityTooLarge, "Некорректный размер тела запроса")
	}
	reader := io.LimitReader(r.Body, maxBodyBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fail(http.StatusBadRequest, "Ожидался корректный JSON-объект")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fail(http.StatusBadRequest, "Тело должно содержать один JSON-объект")
	}
	return nil
}

func (a *App) healthLive(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (a *App) healthReady(w http.ResponseWriter, r *http.Request) error {
	if err := a.db.PingContext(r.Context()); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (a *App) metrics(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, err := fmt.Fprintf(w, "# TYPE markdown_notes_http_requests_total counter\nmarkdown_notes_http_requests_total %d\n# TYPE markdown_notes_http_errors_total counter\nmarkdown_notes_http_errors_total %d\n", a.requests.Load(), a.errors.Load())
	return err
}

func (a *App) register(w http.ResponseWriter, r *http.Request) error {
	var request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	request.Login = strings.TrimSpace(request.Login)
	if !loginPattern.MatchString(request.Login) {
		return fail(http.StatusUnprocessableEntity, "Логин: 3-40 латинских букв, цифр или символов _.-")
	}
	if len(request.Password) < 8 {
		return fail(http.StatusUnprocessableEntity, "Пароль должен содержать не менее 8 символов")
	}
	id, err := uuidV4()
	if err != nil {
		return err
	}
	passwordHash, err := hashPassword(request.Password)
	if err != nil {
		return err
	}
	createdAt := isoNow()
	if _, err := a.db.ExecContext(r.Context(), "INSERT INTO users(id, login, password_hash, created_at) VALUES(?,?,?,?)", id, request.Login, passwordHash, createdAt); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "login": request.Login, "createdAt": createdAt})
	return nil
}

func (a *App) login(w http.ResponseWriter, r *http.Request) error {
	var request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	row := a.db.QueryRowContext(r.Context(), "SELECT id, login, password_hash, created_at FROM users WHERE login=?", strings.TrimSpace(request.Login))
	var account user
	if err := row.Scan(&account.ID, &account.Login, &account.PasswordHash, &account.CreatedAt); err != nil || !verifyPassword(request.Password, account.PasswordHash) {
		return fail(http.StatusUnauthorized, "Неверный логин или пароль")
	}
	session, err := a.newSession(r, account)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, session)
	return nil
}

func (a *App) refresh(w http.ResponseWriter, r *http.Request) error {
	var request struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	digest := tokenDigest(request.RefreshToken)
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var account user
	var expiresAt string
	err = tx.QueryRowContext(r.Context(), `SELECT u.id, u.login, u.password_hash, u.created_at, rt.expires_at
FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id
WHERE rt.digest=? AND rt.revoked_at IS NULL`, digest).Scan(&account.ID, &account.Login, &account.PasswordHash, &account.CreatedAt, &expiresAt)
	if err != nil || isExpired(expiresAt) {
		return fail(http.StatusUnauthorized, "Refresh-токен недействителен")
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE refresh_tokens SET revoked_at=? WHERE digest=?", isoNow(), digest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	session, err := a.newSession(r, account)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, session)
	return nil
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) error {
	var request struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	if _, err := a.db.ExecContext(r.Context(), "UPDATE refresh_tokens SET revoked_at=? WHERE digest=?", isoNow(), tokenDigest(request.RefreshToken)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *App) newSession(r *http.Request, account user) (map[string]string, error) {
	access, expiresAt, err := a.issueAccessToken(account)
	if err != nil {
		return nil, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	refreshExpiry := time.Now().UTC().Add(a.refreshTTL).Format(time.RFC3339Nano)
	if _, err := a.db.ExecContext(r.Context(), "INSERT INTO refresh_tokens(digest,user_id,expires_at) VALUES(?,?,?)", tokenDigest(refresh), account.ID, refreshExpiry); err != nil {
		return nil, err
	}
	return map[string]string{"accessToken": access, "refreshToken": refresh, "expiresAt": expiresAt}, nil
}

func (a *App) createNote(w http.ResponseWriter, r *http.Request) error {
	identity, err := a.currentUser(r)
	if err != nil {
		return err
	}
	var request struct {
		Title        string `json:"title"`
		Markdown     string `json:"markdown"`
		LifetimeDays int    `json:"lifetimeDays"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	request.Title = strings.TrimSpace(request.Title)
	if request.LifetimeDays == 0 {
		request.LifetimeDays = 30
	}
	if request.Title == "" || len([]rune(request.Title)) > 200 {
		return fail(http.StatusUnprocessableEntity, "Название обязательно и не должно превышать 200 символов")
	}
	if len([]byte(request.Markdown)) > 1024*1024 {
		return fail(http.StatusRequestEntityTooLarge, "Markdown превышает 1 МБ")
	}
	if request.LifetimeDays != 7 && request.LifetimeDays != 30 && request.LifetimeDays != 90 {
		return fail(http.StatusUnprocessableEntity, "lifetimeDays должен быть равен 7, 30 или 90")
	}
	id, err := uuidV4()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	createdAt := now.Format(time.RFC3339Nano)
	n := note{ID: id, OwnerUserID: identity.Sub, Title: request.Title, Markdown: request.Markdown, Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt, ExpiredAt: now.AddDate(0, 0, request.LifetimeDays).Format(time.RFC3339Nano)}
	_, err = a.db.ExecContext(r.Context(), "INSERT INTO notes VALUES(?,?,?,?,?,?,?,?)", n.ID, n.OwnerUserID, n.Title, n.Markdown, n.Revision, n.CreatedAt, n.UpdatedAt, n.ExpiredAt)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, n)
	return nil
}

func (a *App) ownNote(w http.ResponseWriter, r *http.Request) error {
	identity, err := a.currentUser(r)
	if err != nil {
		return err
	}
	n, err := a.activeNote(r, r.PathValue("id"))
	if err != nil {
		return err
	}
	if n.OwnerUserID != identity.Sub {
		return fail(http.StatusForbidden, "Доступ запрещен")
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, n)
		return nil
	}
	updated, err := a.updateNote(r, n)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, updated)
	return nil
}

func (a *App) createShareToken(w http.ResponseWriter, r *http.Request) error {
	identity, err := a.currentUser(r)
	if err != nil {
		return err
	}
	var request struct {
		Type             string `json:"type"`
		ExpiresInMinutes *int   `json:"expiresInMinutes"`
	}
	if err := readJSON(r, &request); err != nil {
		return err
	}
	if request.Type != "READ" && request.Type != "WRITE" {
		return fail(http.StatusUnprocessableEntity, "type должен быть READ или WRITE")
	}
	if request.ExpiresInMinutes != nil && (*request.ExpiresInMinutes < 1 || *request.ExpiresInMinutes > 43200) {
		return fail(http.StatusUnprocessableEntity, "Некорректный срок действия токена")
	}
	n, err := a.activeNote(r, r.PathValue("id"))
	if err != nil {
		return err
	}
	if n.OwnerUserID != identity.Sub {
		return fail(http.StatusForbidden, "Только владелец может создавать токены")
	}
	token, err := randomToken(24)
	if err != nil {
		return err
	}
	var expiresAt *string
	if request.ExpiresInMinutes != nil {
		value := time.Now().UTC().Add(time.Duration(*request.ExpiresInMinutes) * time.Minute).Format(time.RFC3339Nano)
		expiresAt = &value
	}
	_, err = a.db.ExecContext(r.Context(), "INSERT INTO share_tokens VALUES(?,?,?,?,?)", tokenDigest(token), n.ID, request.Type, expiresAt, isoNow())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "type": request.Type, "expiresAt": expiresAt})
	return nil
}

func (a *App) sharedNote(w http.ResponseWriter, r *http.Request) error {
	var noteID, accessType string
	var expiresAt sql.NullString
	err := a.db.QueryRowContext(r.Context(), "SELECT note_id, type, expires_at FROM share_tokens WHERE digest=?", tokenDigest(r.PathValue("token"))).Scan(&noteID, &accessType, &expiresAt)
	if err != nil || (expiresAt.Valid && isExpired(expiresAt.String)) {
		return fail(http.StatusUnauthorized, "Токен недействителен или просрочен")
	}
	n, err := a.activeNote(r, noteID)
	if err != nil {
		return err
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, n)
		return nil
	}
	if accessType != "WRITE" {
		return fail(http.StatusForbidden, "Токен разрешает только чтение")
	}
	updated, err := a.updateNote(r, n)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, updated)
	return nil
}

func (a *App) activeNote(r *http.Request, id string) (note, error) {
	var n note
	err := a.db.QueryRowContext(r.Context(), "SELECT id, owner_user_id, title, markdown, revision, created_at, updated_at, expired_at FROM notes WHERE id=?", id).Scan(&n.ID, &n.OwnerUserID, &n.Title, &n.Markdown, &n.Revision, &n.CreatedAt, &n.UpdatedAt, &n.ExpiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return note{}, fail(http.StatusNotFound, "Заметка не найдена")
	}
	if err != nil {
		return note{}, err
	}
	if isExpired(n.ExpiredAt) {
		return note{}, fail(http.StatusGone, "Срок жизни заметки истек")
	}
	return n, nil
}

func (a *App) updateNote(r *http.Request, current note) (note, error) {
	var request struct {
		Title    *string `json:"title"`
		Markdown *string `json:"markdown"`
		Revision int     `json:"revision"`
	}
	if err := readJSON(r, &request); err != nil {
		return note{}, err
	}
	if request.Revision != current.Revision {
		return note{}, fail(http.StatusConflict, "Конфликт версий")
	}
	title, markdown := current.Title, current.Markdown
	if request.Title != nil {
		title = strings.TrimSpace(*request.Title)
	}
	if request.Markdown != nil {
		markdown = *request.Markdown
	}
	if title == "" || len([]rune(title)) > 200 {
		return note{}, fail(http.StatusUnprocessableEntity, "Некорректное название")
	}
	if len([]byte(markdown)) > 1024*1024 {
		return note{}, fail(http.StatusRequestEntityTooLarge, "Markdown превышает 1 МБ")
	}
	updatedAt := isoNow()
	result, err := a.db.ExecContext(r.Context(), "UPDATE notes SET title=?, markdown=?, revision=revision+1, updated_at=? WHERE id=? AND revision=?", title, markdown, updatedAt, current.ID, current.Revision)
	if err != nil {
		return note{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return note{}, err
	}
	if affected != 1 {
		return note{}, fail(http.StatusConflict, "Конфликт версий")
	}
	current.Title, current.Markdown, current.Revision, current.UpdatedAt = title, markdown, current.Revision+1, updatedAt
	return current, nil
}

func (a *App) currentUser(r *http.Request) (claims, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return claims{}, fail(http.StatusUnauthorized, "Требуется действующий access-токен")
	}
	identity, err := a.decodeAccessToken(strings.TrimPrefix(header, "Bearer "))
	if err != nil {
		return claims{}, fail(http.StatusUnauthorized, "Требуется действующий access-токен")
	}
	return identity, nil
}

func (a *App) issueAccessToken(account user) (string, string, error) {
	now := time.Now().UTC()
	payload := claims{Sub: account.ID, Login: account.Login, Iat: now.Unix(), Exp: now.Add(a.accessTTL).Unix()}
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(unsigned))
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token, time.Unix(payload.Exp, 0).UTC().Format(time.RFC3339Nano), nil
}

func (a *App) decodeAccessToken(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return claims{}, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, err
	}
	var identity claims
	if err := json.Unmarshal(payload, &identity); err != nil {
		return claims{}, err
	}
	if identity.Sub == "" || identity.Exp <= time.Now().Unix() {
		return claims{}, errors.New("expired token")
	}
	return identity, nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := pbkdf2SHA256([]byte(password), salt, 310000, 32)
	return base64.RawURLEncoding.EncodeToString(salt) + "." + base64.RawURLEncoding.EncodeToString(digest), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return false
	}
	salt, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	digest, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	candidate := pbkdf2SHA256([]byte(password), salt, 310000, len(digest))
	return subtle.ConstantTimeCompare(candidate, digest) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	result := make([]byte, 0, keyLength)
	for block := uint32(1); len(result) < keyLength; block++ {
		counter := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(counter)
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLength]
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func uuidV4() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func tokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func isoNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func isExpired(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err != nil || !parsed.After(time.Now().UTC())
}

func main() {
	app, err := newApp(defaultConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()
	address := envString("HOST", "0.0.0.0") + ":" + envString("PORT", "8080")
	server := &http.Server{Addr: address, Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Markdown Notes (Go) listening on http://%s", address)
	log.Fatal(server.ListenAndServe())
}

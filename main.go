package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    string `json:"created_at"`
}

type Ticket struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Store struct {
	mu           sync.Mutex
	path         string
	NextUserID   int      `json:"next_user_id"`
	NextTicketID int      `json:"next_ticket_id"`
	Users        []User   `json:"users"`
	Tickets      []Ticket `json:"tickets"`
}

type App struct {
	store     *Store
	jwtSecret []byte
}

type contextKey string

const userIDKey contextKey = "userID"

func main() {
	port := getenv("PORT", "8080")
	dataPath := getenv("DATA_FILE", "data.json")
	secret := getenv("JWT_SECRET", "change-me-in-production")

	store, err := LoadStore(dataPath)
	if err != nil {
		log.Fatal(err)
	}

	app := &App{store: store, jwtSecret: []byte(secret)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", app.root)
	mux.HandleFunc("GET /health", app.health)
	mux.HandleFunc("POST /auth/register", app.register)
	mux.HandleFunc("POST /auth/login", app.login)
	mux.HandleFunc("POST /tickets", app.auth(app.createTicket))
	mux.HandleFunc("GET /tickets", app.auth(app.listTickets))
	mux.HandleFunc("GET /tickets/{id}", app.auth(app.getTicket))
	mux.HandleFunc("PATCH /tickets/{id}/status", app.auth(app.updateTicketStatus))

	log.Printf("ticket system listening on :%s", port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, mux))
}

func (a *App) root(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "ticket-system",
		"status":  "ok",
	})
}

func LoadStore(path string) (*Store, error) {
	store := &Store{path: path, NextUserID: 1, NextTicketID: 1}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(content, store); err != nil {
		return nil, err
	}
	store.path = path
	if store.NextUserID == 0 {
		store.NextUserID = 1
	}
	if store.NextTicketID == 0 {
		store.NextTicketID = 1
	}
	return store, nil
}

func (s *Store) saveLocked() error {
	content, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, content, 0600)
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || len(req.Password) < 6 {
		writeError(w, http.StatusBadRequest, "email and password of at least 6 characters are required")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	for _, user := range a.store.Users {
		if user.Email == req.Email {
			writeError(w, http.StatusConflict, "email is already registered")
			return
		}
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	user := User{
		ID:           a.store.NextUserID,
		Email:        req.Email,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	a.store.NextUserID++
	a.store.Users = append(a.store.Users, user)
	if err := a.store.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save user")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	for _, user := range a.store.Users {
		if user.Email == req.Email && verifyPassword(req.Password, user.PasswordHash) {
			token, err := a.signJWT(user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not create token")
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"token": token})
			return
		}
	}
	writeError(w, http.StatusUnauthorized, "invalid email or password")
}

func (a *App) createTicket(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	ticket := Ticket{
		ID:          a.store.NextTicketID,
		UserID:      userID,
		Title:       req.Title,
		Description: req.Description,
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	a.store.NextTicketID++
	a.store.Tickets = append(a.store.Tickets, ticket)
	if err := a.store.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save ticket")
		return
	}
	writeJSON(w, http.StatusCreated, ticket)
}

func (a *App) listTickets(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	tickets := make([]Ticket, 0)
	for _, ticket := range a.store.Tickets {
		if ticket.UserID == userID {
			tickets = append(tickets, ticket)
		}
	}
	writeJSON(w, http.StatusOK, tickets)
}

func (a *App) getTicket(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	id, ok := parseID(w, r.PathValue("id"))
	if !ok {
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	for _, ticket := range a.store.Tickets {
		if ticket.ID == id && ticket.UserID == userID {
			writeJSON(w, http.StatusOK, ticket)
			return
		}
	}
	writeError(w, http.StatusNotFound, "ticket not found")
}

func (a *App) updateTicketStatus(w http.ResponseWriter, r *http.Request) {
	userID := mustUserID(r)
	id, ok := parseID(w, r.PathValue("id"))
	if !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Status = strings.TrimSpace(req.Status)
	if !validStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "status must be open, in_progress, or closed")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	for i, ticket := range a.store.Tickets {
		if ticket.ID != id || ticket.UserID != userID {
			continue
		}
		if !validTransition(ticket.Status, req.Status) {
			writeError(w, http.StatusBadRequest, "invalid status transition")
			return
		}
		a.store.Tickets[i].Status = req.Status
		a.store.Tickets[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := a.store.saveLocked(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not save ticket")
			return
		}
		writeJSON(w, http.StatusOK, a.store.Tickets[i])
		return
	}
	writeError(w, http.StatusNotFound, "ticket not found")
}

func validStatus(status string) bool {
	return status == "open" || status == "in_progress" || status == "closed"
}

func validTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "open":
		return to == "in_progress"
	case "in_progress":
		return to == "closed"
	case "closed":
		return false
	default:
		return false
	}
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		userID, err := a.verifyJWT(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), userIDKey, userID))
		next(w, r)
	}
}

func mustUserID(r *http.Request) int {
	id, _ := r.Context().Value(userIDKey).(int)
	return id
}

func (a *App) signJWT(userID int) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	payload := map[string]any{
		"sub": strconv.Itoa(userID),
		"exp": time.Now().UTC().Add(24 * time.Hour).Unix(),
		"iat": time.Now().UTC().Unix(),
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature := sign(unsigned, a.jwtSecret)
	return unsigned + "." + signature, nil
}

func (a *App) verifyJWT(token string) (int, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, errors.New("invalid token")
	}
	unsigned := parts[0] + "." + parts[1]
	expected := sign(unsigned, a.jwtSecret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return 0, errors.New("invalid signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}
	var payload struct {
		Subject string `json:"sub"`
		Expires int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return 0, err
	}
	if payload.Expires < time.Now().UTC().Unix() {
		return 0, errors.New("token expired")
	}
	return strconv.Atoi(payload.Subject)
}

func sign(input string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2([]byte(password), salt, 100000, 32)
	return "pbkdf2_sha256$100000$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(key), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	key := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		u := pbkdf2Block(password, salt, iterations, block)
		key = append(key, u...)
	}
	return key[:keyLen]
}

func pbkdf2Block(password, salt []byte, iterations, block int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac = hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func parseID(w http.ResponseWriter, raw string) (int, bool) {
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

func testApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	store, err := LoadStore(filepath.Join(t.TempDir(), "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{store: store, jwtSecret: []byte("test-secret")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.health)
	mux.HandleFunc("POST /auth/register", app.register)
	mux.HandleFunc("POST /auth/login", app.login)
	mux.HandleFunc("POST /tickets", app.auth(app.createTicket))
	mux.HandleFunc("GET /tickets", app.auth(app.listTickets))
	mux.HandleFunc("GET /tickets/{id}", app.auth(app.getTicket))
	mux.HandleFunc("PATCH /tickets/{id}/status", app.auth(app.updateTicketStatus))
	return app, mux
}

func request(t *testing.T, mux http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func registerAndLogin(t *testing.T, mux http.Handler, email string) string {
	t.Helper()
	body := map[string]string{"email": email, "password": "secret123"}
	rec := request(t, mux, http.MethodPost, "/auth/register", body, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = request(t, mux, http.MethodPost, "/auth/login", body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("expected login token")
	}
	return out.Token
}

func createTicket(t *testing.T, mux http.Handler, token string) Ticket {
	t.Helper()
	rec := request(t, mux, http.MethodPost, "/tickets", map[string]string{
		"title":       "Cannot login",
		"description": "Login fails on submit.",
	}, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ticket status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var ticket Ticket
	if err := json.Unmarshal(rec.Body.Bytes(), &ticket); err != nil {
		t.Fatal(err)
	}
	return ticket
}

func TestRegisterLoginAndCreateTicket(t *testing.T) {
	_, mux := testApp(t)
	token := registerAndLogin(t, mux, "user@example.com")
	ticket := createTicket(t, mux, token)
	if ticket.Status != "open" {
		t.Fatalf("new ticket status = %q, want open", ticket.Status)
	}
}

func TestInvalidLoginFails(t *testing.T) {
	_, mux := testApp(t)
	registerAndLogin(t, mux, "user@example.com")
	rec := request(t, mux, http.MethodPost, "/auth/login", map[string]string{
		"email":    "user@example.com",
		"password": "wrong-password",
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestProtectedTicketsRequireBearerToken(t *testing.T) {
	_, mux := testApp(t)
	rec := request(t, mux, http.MethodGet, "/tickets", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tickets status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUserCannotAccessAnotherUsersTicket(t *testing.T) {
	_, mux := testApp(t)
	tokenA := registerAndLogin(t, mux, "a@example.com")
	tokenB := registerAndLogin(t, mux, "b@example.com")
	ticket := createTicket(t, mux, tokenA)

	rec := request(t, mux, http.MethodGet, "/tickets/"+itoa(ticket.ID), nil, tokenB)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get other user's ticket status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	rec = request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "in_progress"}, tokenB)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update other user's ticket status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestTicketStatusFlowIsStrict(t *testing.T) {
	_, mux := testApp(t)
	token := registerAndLogin(t, mux, "user@example.com")
	ticket := createTicket(t, mux, token)

	rec := request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "open"}, token)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("same status update = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	rec = request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "closed"}, token)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("open to closed status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	rec = request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "in_progress"}, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("open to in_progress status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "closed"}, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("in_progress to closed status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = request(t, mux, http.MethodPatch, "/tickets/"+itoa(ticket.ID)+"/status", map[string]string{"status": "open"}, token)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("closed to open status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

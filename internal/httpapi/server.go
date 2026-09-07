package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/endr-i/ecosystem-accounts/internal/account"
	"github.com/endr-i/ecosystem-accounts/internal/authn"
)

type Server struct {
	accounts *account.Service
	verifier *authn.Verifier
	log      *slog.Logger
}

func NewServer(accounts *account.Service, verifier *authn.Verifier, log *slog.Logger) *Server {
	return &Server{accounts: accounts, verifier: verifier, log: log}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/accounts", s.requireAuth(http.HandlerFunc(s.handleCreateAccount)))
	mux.Handle("GET /api/v1/accounts", s.requireAuth(http.HandlerFunc(s.handleListAccounts)))
	mux.Handle("GET /api/v1/accounts/{account_id}", s.requireAuth(http.HandlerFunc(s.handleGetAccount)))
	mux.Handle("DELETE /api/v1/accounts/{account_id}", s.requireAuth(http.HandlerFunc(s.handleDeleteAccount)))
	mux.Handle("PUT /api/v1/accounts/{account_id}", s.requireAuth(http.HandlerFunc(s.handleUpdateAccount)))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.withLogging(mux)
}

type createAccountRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if !s.decode(w, r, &req) {
		return
	}
	userID := UserIDFromContext(r.Context())
	acc, err := s.accounts.Create(r.Context(), userID, req.Name, req.Slug)
	if err != nil {
		switch {
		case errors.Is(err, account.ErrValidation):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, account.ErrSlugTaken):
			s.writeError(w, http.StatusConflict, "slug already taken")
		default:
			s.internalError(w, r, err)
		}
		return
	}
	s.writeJSON(w, http.StatusCreated, acc)
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	limit := 20
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = n
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
		offset = n
	}

	memberships, total, err := s.accounts.List(r.Context(), userID, limit, offset)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": memberships, "total": total})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	accountID := r.PathValue("account_id")
	membership, err := s.accounts.GetById(r.Context(), userID, accountID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"item": membership})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	accountID := r.PathValue("account_id")
	err := s.accounts.Delete(r.Context(), userID, accountID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if !s.decode(w, r, &req) {
		return
	}
	userID := UserIDFromContext(r.Context())
	accountID := r.PathValue("account_id")
	membership, err := s.accounts.Update(r.Context(), userID, accountID, req.Name, req.Slug)
	if err != nil {
		switch {
		case errors.Is(err, account.ErrValidation):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, account.ErrSlugTaken):
			s.writeError(w, http.StatusConflict, "slug already taken")
		default:
			s.internalError(w, r, err)
		}
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"item": membership})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type ctxUserID struct{}

// UserIDFromContext returns the authenticated user ID attached by requireAuth.
func UserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxUserID{}).(string)
	return id
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		tokenStr, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || tokenStr == "" {
			s.writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		userID, err := s.verifier.VerifyAccessToken(r.Context(), tokenStr)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID{}, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	})
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	s.writeError(w, http.StatusInternalServerError, "internal server error")
}

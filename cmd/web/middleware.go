package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/justinas/nosurf"
)

func commonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com")
		resp.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		resp.Header().Set("X-Content-Type-Options", "nosniff")
		resp.Header().Set("X-Frame-Options", "deny")
		resp.Header().Set("X-XSS-Protection", "0")
		resp.Header().Set("Server", "Go")

		next.ServeHTTP(resp, req)
	})
}

func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		var (
			ip     = req.RemoteAddr
			proto  = req.Proto
			method = req.Method
			uri    = req.URL.RequestURI()
		)
		app.logger.Info("Received request", slog.String("ip", ip), slog.String("proto", proto), slog.String("method", method), slog.String("uri", uri))

		next.ServeHTTP(resp, req)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				resp.Header().Set("Connection", "close")
				app.serverError(resp, req, fmt.Errorf("%s", err))
			}
		}()

		next.ServeHTTP(resp, req)
	})
}

func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !app.isAuthenticated(req) {
			app.sessionManager.Put(req.Context(), "redirectPathAfterLogin", req.URL.Path)
			http.Redirect(resp, req, "/user/login", http.StatusSeeOther)
			return
		}

		resp.Header().Add("Cache-Control", "no-store")

		next.ServeHTTP(resp, req)
	})
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		id := app.sessionManager.GetInt(req.Context(), "authenticatedUserID")
		if id == 0 {
			next.ServeHTTP(resp, req)
			return
		}

		exists, err := app.users.Exists(id)
		if err != nil {
			app.serverError(resp, req, err)
			return
		}
		if exists {
			ctx := context.WithValue(req.Context(), isAuthenticatedContextKey, true)
			req = req.WithContext(ctx)
		}

		next.ServeHTTP(resp, req)
	})
}

func noCSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})

	return csrfHandler
}

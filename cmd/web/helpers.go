package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-playground/form/v4"
	"github.com/justinas/nosurf"
)

func (app *application) serverError(resp http.ResponseWriter, req *http.Request, err error) {
	var (
		method = req.Method
		uri    = req.URL.RequestURI()
		trace  = string(debug.Stack())
	)

	app.logger.Error(err.Error(), "method", method, "uri", uri, "trace", trace)
	http.Error(resp, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (app *application) clientError(resp http.ResponseWriter, status int) {
	http.Error(resp, http.StatusText(status), status)
}

func (app *application) render(resp http.ResponseWriter, req *http.Request, status int, page string, data templateData) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("The template %s does not exist.", page)
		app.serverError(resp, req, err)
		return
	}

	buf := new(bytes.Buffer)
	err := ts.ExecuteTemplate(buf, "base", data)
	if err != nil {
		app.serverError(resp, req, err)
		return
	}

	resp.WriteHeader(status)
	buf.WriteTo(resp)
}

func (app *application) newTemplateData(req *http.Request) templateData {
	return templateData{
		CurrentYear:     time.Now().Year(),
		Flash:           app.sessionManager.PopString(req.Context(), "flash"),
		IsAuthenticated: app.isAuthenticated(req),
		CSRFToken:       nosurf.Token(req),
	}
}

func (app *application) decodePostForm(req *http.Request, target any) error {
	err := req.ParseForm()
	if err != nil {
		return err
	}

	err = app.formDecoder.Decode(target, req.PostForm)
	if err != nil {
		var invalidDecoderError *form.InvalidDecoderError
		if errors.As(err, &invalidDecoderError) {
			panic(err)
		}
	}

	return err
}

func (app *application) isAuthenticated(req *http.Request) bool {
	isAuthenticated, ok := req.Context().Value(isAuthenticatedContextKey).(bool)
	if !ok {
		return false
	}

	return isAuthenticated
}

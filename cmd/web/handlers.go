package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"snippetbox.alexedwards.net/internal/models"
	"snippetbox.alexedwards.net/internal/validator"
)

type userSignupForm struct {
	Name                string `form:"name"`
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}

type userLoginForm struct {
	Email               string `form:"email"`
	Password            string `form:"password"`
	validator.Validator `form:"-"`
}

type snippetCreateForm struct {
	Title               string `form:"title"`
	Content             string `form:"content"`
	Expires             int    `form:"expires"`
	validator.Validator `form:"-"`
}

func (app *application) userSignup(resp http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = userSignupForm{}
	app.render(resp, req, http.StatusOK, "signup.tmpl.html", data)
}

func (app *application) userSingupPost(resp http.ResponseWriter, req *http.Request) {
	var form userSignupForm
	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(resp, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Name), "name", "Name field cannot be blank")
	form.CheckField(validator.NotBlank(form.Email), "email", "Email field cannot be blank")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "Email field must be a valid address")
	form.CheckField(validator.NotBlank(form.Password), "password", "Password field cannot be blank")
	form.CheckField(validator.MinChars(form.Password, 8), "password", "Password field must be at least 8 characters long")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(resp, req, http.StatusUnprocessableEntity, "signup.tmpl.html", data)
		return
	}

	err = app.users.Insert(form.Name, form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			form.AddFieldError("email", "Email address already in use")
			data := app.newTemplateData(req)
			data.Form = form
			app.render(resp, req, http.StatusUnprocessableEntity, "signup.tmpl.html", data)
		} else {
			app.serverError(resp, req, err)
		}
		return
	}

	app.sessionManager.Put(req.Context(), "flash", "Your signup was successful. Please log in.")
	http.Redirect(resp, req, "/user/login", http.StatusSeeOther)
}

func (app *application) userLogin(resp http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = userLoginForm{}
	app.render(resp, req, http.StatusOK, "login.tmpl.html", data)
}

func (app *application) userLoginPost(resp http.ResponseWriter, req *http.Request) {
	var form userLoginForm

	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(resp, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Email), "email", "Email field cannot be blank")
	form.CheckField(validator.Matches(form.Email, validator.EmailRX), "email", "This field must be a valid email address")
	form.CheckField(validator.NotBlank(form.Password), "password", "Password field cannot be blank")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(resp, req, http.StatusUnprocessableEntity, "login.tmpl.html", data)
		return
	}

	id, err := app.users.Authenticate(form.Email, form.Password)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.AddNonFieldError("Email or password is incorrect")
			data := app.newTemplateData(req)
			data.Form = form
			app.render(resp, req, http.StatusUnprocessableEntity, "login.tmpl.html", data)
		} else {
			app.serverError(resp, req, err)
		}
		return
	}

	err = app.sessionManager.RenewToken(req.Context())
	if err != nil {
		app.serverError(resp, req, err)
		return
	}

	app.sessionManager.Put(req.Context(), "authenticatedUserID", id)
	path := app.sessionManager.PopString(req.Context(), "redirectPathAfterLogin")
	if path != "" {
		http.Redirect(resp, req, path, http.StatusSeeOther)
		return
	}

	http.Redirect(resp, req, "/snippet/create", http.StatusSeeOther)
}

type accountPasswordUpdateForm struct {
	CurrentPassword         string `form:"currentPassword"`
	NewPassword             string `form:"newPassword"`
	NewPasswordConfirmation string `form:"newPasswordConfirmation"`
	validator.Validator     `form:"-"`
}

func (app *application) accountPasswordUpdate(resp http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = accountPasswordUpdateForm{}
	app.render(resp, req, http.StatusOK, "password.tmpl.html", data)
}
func (app *application) accountPasswordUpdatePost(resp http.ResponseWriter, req *http.Request) {
	var form accountPasswordUpdateForm
	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(resp, http.StatusBadRequest)
		return
	}
	form.CheckField(validator.NotBlank(form.CurrentPassword), "currentPassword", "This field cannot be blank")
	form.CheckField(validator.NotBlank(form.NewPassword), "newPassword", "This field cannot be blank")
	form.CheckField(validator.MinChars(form.NewPassword, 8), "newPassword", "This field must be at least 8 characters long")
	form.CheckField(validator.NotBlank(form.NewPasswordConfirmation), "newPasswordConfirmation", "This field cannot be blank")
	form.CheckField(form.NewPassword == form.NewPasswordConfirmation, "newPasswordConfirmation", "Passwords do not match")
	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(resp, req, http.StatusUnprocessableEntity, "password.tmpl.html", data)
		return
	}

	userID := app.sessionManager.GetInt(req.Context(), "authenticatedUserID")

	err = app.users.PasswordUpdate(userID, form.CurrentPassword, form.NewPassword)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.AddFieldError("currentPassword", "Current password is incorrect")
			data := app.newTemplateData(req)
			data.Form = form
			app.render(resp, req, http.StatusUnprocessableEntity, "password.tmpl", data)
		} else {
			app.serverError(resp, req, err)
		}
		return
	}

	app.sessionManager.Put(req.Context(), "flash", "Your password has been updated!")
	http.Redirect(resp, req, "/account/view", http.StatusSeeOther)
}

func (app *application) userLogoutPost(resp http.ResponseWriter, req *http.Request) {
	err := app.sessionManager.RenewToken(req.Context())
	if err != nil {
		app.serverError(resp, req, err)
		return
	}

	app.sessionManager.Remove(req.Context(), "authenticatedUserID")
	app.sessionManager.Put(req.Context(), "flash", "You've been logged out successfully!")
	http.Redirect(resp, req, "/", http.StatusSeeOther)
}

func (app *application) home(resp http.ResponseWriter, req *http.Request) {
	snippets, err := app.snippets.Latest()
	if err != nil {
		app.serverError(resp, req, err)
		return
	}

	data := app.newTemplateData(req)
	data.Snippets = snippets
	app.render(resp, req, http.StatusOK, "home.tmpl.html", data)
}

func (app *application) snippetView(resp http.ResponseWriter, req *http.Request) {
	id, err := strconv.Atoi(req.PathValue("id"))
	if err != nil || id < 1 {
		http.NotFound(resp, req)
		return
	}

	snippet, err := app.snippets.Get(id)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			http.NotFound(resp, req)
		} else {
			app.serverError(resp, req, err)
		}
		return
	}

	data := app.newTemplateData(req)
	data.Snippet = snippet
	app.render(resp, req, http.StatusOK, "view.tmpl.html", data)
}

func (app *application) snippetCreate(resp http.ResponseWriter, req *http.Request) {
	data := app.newTemplateData(req)
	data.Form = snippetCreateForm{
		Expires: 365,
	}

	app.render(resp, req, http.StatusOK, "create.tmpl.html", data)
}

func (app *application) snippetCreatePost(resp http.ResponseWriter, req *http.Request) {
	var form snippetCreateForm

	err := app.decodePostForm(req, &form)
	if err != nil {
		app.clientError(resp, http.StatusBadRequest)
		return
	}

	form.CheckField(validator.NotBlank(form.Title), "title", "Title field cannot be blank")
	form.CheckField(validator.MaxChars(form.Title, 100), "title", "Title field cannot be more than 100 characters long")
	form.CheckField(validator.NotBlank(form.Content), "content", "Content field cannot be blank")
	form.CheckField(validator.PermittedValue(form.Expires, 1, 7, 365), "expires", "Expires field must equal 1, 7 or 365")

	if !form.Valid() {
		data := app.newTemplateData(req)
		data.Form = form
		app.render(resp, req, http.StatusUnprocessableEntity, "create.tmpl.html", data)
		return
	}

	id, err := app.snippets.Insert(form.Title, form.Content, form.Expires)
	if err != nil {
		app.serverError(resp, req, err)
		return
	}

	app.sessionManager.Put(req.Context(), "flash", "Snippet created successfully!")
	http.Redirect(resp, req, fmt.Sprintf("/snippet/view/%d", id), http.StatusSeeOther)
}

func ping(resp http.ResponseWriter, req *http.Request) {
	resp.Write([]byte("OK"))
}

func (app *application) accountView(resp http.ResponseWriter, req *http.Request) {
	userID := app.sessionManager.GetInt(req.Context(), "authenticatedUserID")

	user, err := app.users.Get(userID)
	if err != nil {
		if errors.Is(err, models.ErrNoRecord) {
			http.Redirect(resp, req, "/user/login", http.StatusSeeOther)
		} else {
			app.serverError(resp, req, err)
		}
		return
	}

	data := app.newTemplateData(req)
	data.User = user
	app.render(resp, req, http.StatusOK, "account.tmpl.html", data)
}

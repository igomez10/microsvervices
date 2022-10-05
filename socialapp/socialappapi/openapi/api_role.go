/*
 * Socialapp
 *
 * Socialapp is a generic social network.
 *
 * API version: 1.0.0
 * Contact: ignacio.gomez.arboleda@gmail.com
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package openapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// RoleApiController binds http requests to an api service and writes the service results to the http response
type RoleApiController struct {
	service      RoleApiServicer
	errorHandler ErrorHandler
}

// RoleApiOption for how the controller is set up.
type RoleApiOption func(*RoleApiController)

// WithRoleApiErrorHandler inject ErrorHandler into controller
func WithRoleApiErrorHandler(h ErrorHandler) RoleApiOption {
	return func(c *RoleApiController) {
		c.errorHandler = h
	}
}

// NewRoleApiController creates a default api controller
func NewRoleApiController(s RoleApiServicer, opts ...RoleApiOption) Router {
	controller := &RoleApiController{
		service:      s,
		errorHandler: DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the RoleApiController
func (c *RoleApiController) Routes() Routes {
	return Routes{
		{
			"CreateRole",
			strings.ToUpper("Post"),
			"/roles",
			c.CreateRole,
		},
		{
			"DeleteRole",
			strings.ToUpper("Delete"),
			"/roles/{id}",
			c.DeleteRole,
		},
		{
			"GetRole",
			strings.ToUpper("Get"),
			"/roles/{id}",
			c.GetRole,
		},
		{
			"ListRoles",
			strings.ToUpper("Get"),
			"/roles",
			c.ListRoles,
		},
		{
			"UpdateRole",
			strings.ToUpper("Put"),
			"/roles/{id}",
			c.UpdateRole,
		},
	}
}

// CreateRole - Create a new role
func (c *RoleApiController) CreateRole(w http.ResponseWriter, r *http.Request) {
	roleParam := Role{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&roleParam); err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}
	if err := AssertRoleRequired(roleParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.CreateRole(r.Context(), roleParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	EncodeJSONResponse(result.Body, &result.Code, w)

}

// DeleteRole - Delete a role
func (c *RoleApiController) DeleteRole(w http.ResponseWriter, r *http.Request) {
	idParam, err := parseInt32Parameter(chi.URLParam(r, "id"), true)
	if err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}

	result, err := c.service.DeleteRole(r.Context(), idParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	EncodeJSONResponse(result.Body, &result.Code, w)

}

// GetRole - Returns a role
func (c *RoleApiController) GetRole(w http.ResponseWriter, r *http.Request) {
	idParam, err := parseInt32Parameter(chi.URLParam(r, "id"), true)
	if err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}

	result, err := c.service.GetRole(r.Context(), idParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	EncodeJSONResponse(result.Body, &result.Code, w)

}

// ListRoles - Returns a list of roles
func (c *RoleApiController) ListRoles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limitParam, err := parseInt32Parameter(query.Get("limit"), false)
	if err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}
	offsetParam, err := parseInt32Parameter(query.Get("offset"), false)
	if err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}
	result, err := c.service.ListRoles(r.Context(), limitParam, offsetParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	EncodeJSONResponse(result.Body, &result.Code, w)

}

// UpdateRole - Update a role
func (c *RoleApiController) UpdateRole(w http.ResponseWriter, r *http.Request) {
	idParam, err := parseInt32Parameter(chi.URLParam(r, "id"), true)
	if err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}

	roleParam := Role{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&roleParam); err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}
	if err := AssertRoleRequired(roleParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	result, err := c.service.UpdateRole(r.Context(), idParam, roleParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	EncodeJSONResponse(result.Body, &result.Code, w)

}

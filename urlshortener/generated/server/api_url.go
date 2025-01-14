// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

/*
 * URL Shortener
 *
 * URL Shortener is an API for managing short URLs
 *
 * API version: 1.0.0
 * Contact: ignacio.gomez.arboleda@gmail.com
 */

package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// URLAPIController binds http requests to an api service and writes the service results to the http response
type URLAPIController struct {
	service      URLAPIServicer
	errorHandler ErrorHandler
}

// URLAPIOption for how the controller is set up.
type URLAPIOption func(*URLAPIController)

// WithURLAPIErrorHandler inject ErrorHandler into controller
func WithURLAPIErrorHandler(h ErrorHandler) URLAPIOption {
	return func(c *URLAPIController) {
		c.errorHandler = h
	}
}

// NewURLAPIController creates a default api controller
func NewURLAPIController(s URLAPIServicer, opts ...URLAPIOption) *URLAPIController {
	controller := &URLAPIController{
		service:      s,
		errorHandler: DefaultErrorHandler,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all the api routes for the URLAPIController
func (c *URLAPIController) Routes() Routes {
	return Routes{
		"GetUrl": Route{
			strings.ToUpper("Get"),
			"/v1/urls/{alias}",
			c.GetUrl,
		},
		"DeleteUrl": Route{
			strings.ToUpper("Delete"),
			"/v1/urls/{alias}",
			c.DeleteUrl,
		},
		"GetUrlData": Route{
			strings.ToUpper("Get"),
			"/v1/urls/{alias}/data",
			c.GetUrlData,
		},
		"CreateUrl": Route{
			strings.ToUpper("Post"),
			"/v1/urls",
			c.CreateUrl,
		},
	}
}

// GetUrl - Get a url
func (c *URLAPIController) GetUrl(w http.ResponseWriter, r *http.Request) {
	aliasParam := chi.URLParam(r, "alias")
	if aliasParam == "" {
		c.errorHandler(w, r, &RequiredError{"alias"}, nil)
		return
	}
	xRequestIDParam := r.Header.Get("X-Request-ID")
	result, err := c.service.GetUrl(r.Context(), aliasParam, xRequestIDParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	_ = EncodeJSONResponse(result.Body, &result.Code, result.Headers, w)
}

// DeleteUrl - Delete a url
func (c *URLAPIController) DeleteUrl(w http.ResponseWriter, r *http.Request) {
	aliasParam := chi.URLParam(r, "alias")
	if aliasParam == "" {
		c.errorHandler(w, r, &RequiredError{"alias"}, nil)
		return
	}
	xRequestIDParam := r.Header.Get("X-Request-ID")
	result, err := c.service.DeleteUrl(r.Context(), aliasParam, xRequestIDParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	_ = EncodeJSONResponse(result.Body, &result.Code, result.Headers, w)
}

// GetUrlData - Returns a url metadata
func (c *URLAPIController) GetUrlData(w http.ResponseWriter, r *http.Request) {
	aliasParam := chi.URLParam(r, "alias")
	if aliasParam == "" {
		c.errorHandler(w, r, &RequiredError{"alias"}, nil)
		return
	}
	xRequestIDParam := r.Header.Get("X-Request-ID")
	result, err := c.service.GetUrlData(r.Context(), aliasParam, xRequestIDParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	_ = EncodeJSONResponse(result.Body, &result.Code, result.Headers, w)
}

// CreateUrl - Create a new url
func (c *URLAPIController) CreateUrl(w http.ResponseWriter, r *http.Request) {
	urlParam := Url{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&urlParam); err != nil {
		c.errorHandler(w, r, &ParsingError{Err: err}, nil)
		return
	}
	if err := AssertUrlRequired(urlParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	if err := AssertUrlConstraints(urlParam); err != nil {
		c.errorHandler(w, r, err, nil)
		return
	}
	xRequestIDParam := r.Header.Get("X-Request-ID")
	result, err := c.service.CreateUrl(r.Context(), urlParam, xRequestIDParam)
	// If an error occurred, encode the error with the status code
	if err != nil {
		c.errorHandler(w, r, err, &result)
		return
	}
	// If no error, encode the body and the result code
	_ = EncodeJSONResponse(result.Body, &result.Code, result.Headers, w)
}

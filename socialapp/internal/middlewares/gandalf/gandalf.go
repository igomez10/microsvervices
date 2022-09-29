package gandalf

import (
	"database/sql"
	"fmt"
	"net/http"
	"socialapp/internal/authorizationparser"
	"socialapp/internal/contexthelper"
	"socialapp/pkg/controller/user"
	"socialapp/pkg/db"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type Middleware struct {
	DB                  db.Querier
	DBConn              *sql.DB
	Authorizationparser authorizationparser.EndpointAuthorizations
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {

	allowlistedPaths := map[string]map[string]bool{
		"/users": {
			"POST": true,
		},
		"/metrics": {
			"GET": true,
		},
		"/apispec": {
			"GET": true,
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get token from header
		if allowlistedPaths[r.URL.Path] != nil && allowlistedPaths[r.URL.Path][r.Method] {
			r = contexthelper.SetRequestedScopesInContext(r, map[string]bool{})
			log.Info().Msg("Allowlisted path")
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			// check givenToken in DB
			givenToken := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := m.DB.GetToken(r.Context(), m.DBConn, givenToken)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get token")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if time.Now().After(token.ValidUntil) {
				log.Error().Err(err).Msg("Token expired")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			dbTokenScopes, err := m.DB.GetTokenScopes(r.Context(), m.DBConn, token.ID)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get token scopes")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			scopesMap := map[string]bool{}
			for i := range dbTokenScopes {
				scopesMap[dbTokenScopes[i].Name] = true
			}

			r = contexthelper.SetRequestedScopesInContext(r, scopesMap)

			usr, err := m.DB.GetUserByID(r.Context(), m.DBConn, token.UserID)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get user")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			r = contexthelper.SetUsernameInContext(r, usr.Username)
			next.ServeHTTP(w, r)
			return
		} else if strings.HasPrefix(authHeader, "Basic ") && r.URL.Path == "/oauth/token" {

			// check grant type is client_credentials
			username, password, ok := r.BasicAuth()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code": 401, "message": "Invalid basic auth format"}`))
				return
			}

			usr, err := m.DB.GetUserByUsername(r.Context(), m.DBConn, username)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code": 401, "message": "Username not found"}`))
				return
			}

			encryptedPassword := user.EncryptPassword(password, usr.Salt)
			if encryptedPassword != usr.HashedPassword {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code": 401, "message": "Invalid username or password"}`))
				return
			}

			// passed authentication
			r = contexthelper.SetUsernameInContext(r, usr.Username)

			// get requested scopes
			requestedScopes := strings.Split(r.FormValue("scope"), " ")
			// validate every requested scope exists in the DB

			// get user roles from DB
			roles, err := m.DB.GetUserRoles(r.Context(), m.DBConn, usr.ID)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get user roles")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			allowedScopes := map[string]db.Scope{}
			for i := range roles {
				// get role scopes from DB
				scopes, err := m.DB.GetRoleScopes(r.Context(), m.DBConn, roles[i].ID)
				if err != nil {
					log.Error().Err(err).Int64("role_id", roles[i].ID).Msg("Failed to get role scopes")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"code": 500, "message": "Internal server error"}`))
					return
				}
				for j := range scopes {
					allowedScopes[scopes[j].Name] = scopes[j]
				}
			}

			// remove duplicated scopes
			mapReqScopes := map[string]bool{}
			for _, scopeName := range requestedScopes {
				mapReqScopes[scopeName] = true
			}

			// verify requested scopes are allowed
			for i := range requestedScopes {
				if _, exist := allowedScopes[requestedScopes[i]]; !exist {
					log.Error().Str("scope", requestedScopes[i]).Msg("Scope not allowed")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(fmt.Sprintf(`{"code": 401, "message": "Scope %q not allowed"}`, requestedScopes[i])))
					return
				}
			}

			r = contexthelper.SetRequestedScopesInContext(r, mapReqScopes)
			next.ServeHTTP(w, r)
			return
		}

		// no token in header
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code": 401, "message": "Invalid Authorization header"}`))
	})

}

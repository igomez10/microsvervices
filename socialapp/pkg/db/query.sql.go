// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.15.0
// source: query.sql

package db

import (
	"context"
	"database/sql"
	"time"
)

const CreateComment = `-- name: CreateComment :one
INSERT INTO comments (
  user_id, content
) VALUES (
  $1, $2
)
RETURNING id, content, like_count, user_id, created_at, updated_at, deleted_at
`

type CreateCommentParams struct {
	UserID  int64  `json:"user_id"`
	Content string `json:"content"`
}

func (q *Queries) CreateComment(ctx context.Context, db DBTX, arg CreateCommentParams) (Comment, error) {
	row := db.QueryRowContext(ctx, CreateComment, arg.UserID, arg.Content)
	var i Comment
	err := row.Scan(
		&i.ID,
		&i.Content,
		&i.LikeCount,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateCommentForUser = `-- name: CreateCommentForUser :one
INSERT INTO comments (
  user_id, content
) VALUES (
  (SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL), $2
)
RETURNING id, content, like_count, user_id, created_at, updated_at, deleted_at
`

type CreateCommentForUserParams struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}

func (q *Queries) CreateCommentForUser(ctx context.Context, db DBTX, arg CreateCommentForUserParams) (Comment, error) {
	row := db.QueryRowContext(ctx, CreateCommentForUser, arg.Username, arg.Content)
	var i Comment
	err := row.Scan(
		&i.ID,
		&i.Content,
		&i.LikeCount,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateCredential = `-- name: CreateCredential :one
INSERT INTO credentials (
  user_id, public_key, description, name
) VALUES (
  $1, $2, $3, $4
)
RETURNING id, user_id, public_key, description, name, created_at, deleted_at
`

type CreateCredentialParams struct {
	UserID      int64  `json:"user_id"`
	PublicKey   string `json:"public_key"`
	Description string `json:"description"`
	Name        string `json:"name"`
}

func (q *Queries) CreateCredential(ctx context.Context, db DBTX, arg CreateCredentialParams) (Credential, error) {
	row := db.QueryRowContext(ctx, CreateCredential,
		arg.UserID,
		arg.PublicKey,
		arg.Description,
		arg.Name,
	)
	var i Credential
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.PublicKey,
		&i.Description,
		&i.Name,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateRole = `-- name: CreateRole :one
INSERT INTO roles (name, description) 
VALUES ($1, $2)
RETURNING id, name, description, created_at, deleted_at
`

type CreateRoleParams struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (q *Queries) CreateRole(ctx context.Context, db DBTX, arg CreateRoleParams) (Role, error) {
	row := db.QueryRowContext(ctx, CreateRole, arg.Name, arg.Description)
	var i Role
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateRoleScope = `-- name: CreateRoleScope :one
INSERT INTO roles_to_scopes (
	role_id, scope_id
) VALUES (
	$1, $2
)
RETURNING id, role_id, scope_id
`

type CreateRoleScopeParams struct {
	RoleID  int64 `json:"role_id"`
	ScopeID int64 `json:"scope_id"`
}

func (q *Queries) CreateRoleScope(ctx context.Context, db DBTX, arg CreateRoleScopeParams) (RolesToScope, error) {
	row := db.QueryRowContext(ctx, CreateRoleScope, arg.RoleID, arg.ScopeID)
	var i RolesToScope
	err := row.Scan(&i.ID, &i.RoleID, &i.ScopeID)
	return i, err
}

const CreateScope = `-- name: CreateScope :one
INSERT INTO scopes (
	  name, description
) VALUES (
	$1, $2
)
RETURNING id, name, description, created_at, deleted_at
`

type CreateScopeParams struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (q *Queries) CreateScope(ctx context.Context, db DBTX, arg CreateScopeParams) (Scope, error) {
	row := db.QueryRowContext(ctx, CreateScope, arg.Name, arg.Description)
	var i Scope
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateToken = `-- name: CreateToken :one
INSERT INTO tokens (
	token, user_id, valid_until
) VALUES (
	$1, $2, $3
)
RETURNING id, user_id, token, valid_from, valid_until
`

type CreateTokenParams struct {
	Token      string    `json:"token"`
	UserID     int64     `json:"user_id"`
	ValidUntil time.Time `json:"valid_until"`
}

func (q *Queries) CreateToken(ctx context.Context, db DBTX, arg CreateTokenParams) (Token, error) {
	row := db.QueryRowContext(ctx, CreateToken, arg.Token, arg.UserID, arg.ValidUntil)
	var i Token
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.ValidFrom,
		&i.ValidUntil,
	)
	return i, err
}

const CreateTokenToScope = `-- name: CreateTokenToScope :one
INSERT INTO tokens_to_scopes (
	token_id, scope_id
) VALUES (
  $1, $2
)
RETURNING id, token_id, scope_id
`

type CreateTokenToScopeParams struct {
	TokenID int64 `json:"token_id"`
	ScopeID int64 `json:"scope_id"`
}

func (q *Queries) CreateTokenToScope(ctx context.Context, db DBTX, arg CreateTokenToScopeParams) (TokensToScope, error) {
	row := db.QueryRowContext(ctx, CreateTokenToScope, arg.TokenID, arg.ScopeID)
	var i TokensToScope
	err := row.Scan(&i.ID, &i.TokenID, &i.ScopeID)
	return i, err
}

const CreateUser = `-- name: CreateUser :one
INSERT INTO users (
    username, hashed_password, salt, first_name, last_name, email, email_token, email_verified_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING id, username, hashed_password, hashed_password_expires_at, salt, first_name, last_name, email, email_token, email_verified_at, created_at, updated_at, deleted_at
`

type CreateUserParams struct {
	Username        string       `json:"username"`
	HashedPassword  string       `json:"hashed_password"`
	Salt            string       `json:"salt"`
	FirstName       string       `json:"first_name"`
	LastName        string       `json:"last_name"`
	Email           string       `json:"email"`
	EmailToken      string       `json:"email_token"`
	EmailVerifiedAt sql.NullTime `json:"email_verified_at"`
}

func (q *Queries) CreateUser(ctx context.Context, db DBTX, arg CreateUserParams) (User, error) {
	row := db.QueryRowContext(ctx, CreateUser,
		arg.Username,
		arg.HashedPassword,
		arg.Salt,
		arg.FirstName,
		arg.LastName,
		arg.Email,
		arg.EmailToken,
		arg.EmailVerifiedAt,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.HashedPassword,
		&i.HashedPasswordExpiresAt,
		&i.Salt,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.EmailToken,
		&i.EmailVerifiedAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const CreateUserToRole = `-- name: CreateUserToRole :one
INSERT INTO users_to_roles (
	user_id, role_id
) VALUES (
	$1, $2
)
RETURNING id, role_id, user_id
`

type CreateUserToRoleParams struct {
	UserID int64 `json:"user_id"`
	RoleID int64 `json:"role_id"`
}

func (q *Queries) CreateUserToRole(ctx context.Context, db DBTX, arg CreateUserToRoleParams) (UsersToRole, error) {
	row := db.QueryRowContext(ctx, CreateUserToRole, arg.UserID, arg.RoleID)
	var i UsersToRole
	err := row.Scan(&i.ID, &i.RoleID, &i.UserID)
	return i, err
}

const DeleteAllTokensForUser = `-- name: DeleteAllTokensForUser :exec
UPDATE tokens
SET valid_until = NOW()
WHERE user_id = $1 AND NOW() < valid_until
`

func (q *Queries) DeleteAllTokensForUser(ctx context.Context, db DBTX, userID int64) error {
	_, err := db.ExecContext(ctx, DeleteAllTokensForUser, userID)
	return err
}

const DeleteComment = `-- name: DeleteComment :exec
UPDATE comments
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteComment(ctx context.Context, db DBTX, id int64) error {
	_, err := db.ExecContext(ctx, DeleteComment, id)
	return err
}

const DeleteCredential = `-- name: DeleteCredential :exec
DELETE FROM credentials
WHERE id = $1
`

func (q *Queries) DeleteCredential(ctx context.Context, db DBTX, id int64) error {
	_, err := db.ExecContext(ctx, DeleteCredential, id)
	return err
}

const DeleteRole = `-- name: DeleteRole :exec
UPDATE roles 
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteRole(ctx context.Context, db DBTX, id int64) error {
	_, err := db.ExecContext(ctx, DeleteRole, id)
	return err
}

const DeleteRoleScope = `-- name: DeleteRoleScope :exec
DELETE FROM roles_to_scopes
WHERE role_id = $1 AND scope_id = $2
`

type DeleteRoleScopeParams struct {
	RoleID  int64 `json:"role_id"`
	ScopeID int64 `json:"scope_id"`
}

func (q *Queries) DeleteRoleScope(ctx context.Context, db DBTX, arg DeleteRoleScopeParams) error {
	_, err := db.ExecContext(ctx, DeleteRoleScope, arg.RoleID, arg.ScopeID)
	return err
}

const DeleteScope = `-- name: DeleteScope :exec
UPDATE scopes
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteScope(ctx context.Context, db DBTX, id int64) error {
	_, err := db.ExecContext(ctx, DeleteScope, id)
	return err
}

const DeleteToken = `-- name: DeleteToken :exec
UPDATE tokens
SET valid_until = NOW()
WHERE token = $1 AND NOW() < valid_until
`

func (q *Queries) DeleteToken(ctx context.Context, db DBTX, token string) error {
	_, err := db.ExecContext(ctx, DeleteToken, token)
	return err
}

const DeleteUser = `-- name: DeleteUser :exec
UPDATE users
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteUser(ctx context.Context, db DBTX, id int64) error {
	_, err := db.ExecContext(ctx, DeleteUser, id)
	return err
}

const DeleteUserByUsername = `-- name: DeleteUserByUsername :exec
UPDATE users
SET deleted_at = NOW()
WHERE username = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteUserByUsername(ctx context.Context, db DBTX, username string) error {
	_, err := db.ExecContext(ctx, DeleteUserByUsername, username)
	return err
}

const DeleteUserToRole = `-- name: DeleteUserToRole :exec
DELETE FROM users_to_roles
WHERE user_id = $1 AND role_id = $2
`

type DeleteUserToRoleParams struct {
	UserID int64 `json:"user_id"`
	RoleID int64 `json:"role_id"`
}

func (q *Queries) DeleteUserToRole(ctx context.Context, db DBTX, arg DeleteUserToRoleParams) error {
	_, err := db.ExecContext(ctx, DeleteUserToRole, arg.UserID, arg.RoleID)
	return err
}

const FollowUser = `-- name: FollowUser :exec
INSERT INTO followers (
  follower_id, followed_id
) VALUES (
  $1, $2
)
`

type FollowUserParams struct {
	FollowerID int64 `json:"follower_id"`
	FollowedID int64 `json:"followed_id"`
}

func (q *Queries) FollowUser(ctx context.Context, db DBTX, arg FollowUserParams) error {
	_, err := db.ExecContext(ctx, FollowUser, arg.FollowerID, arg.FollowedID)
	return err
}

const GetComment = `-- name: GetComment :one
SELECT id, content, like_count, user_id, created_at, updated_at, deleted_at FROM comments
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetComment(ctx context.Context, db DBTX, id int64) (Comment, error) {
	row := db.QueryRowContext(ctx, GetComment, id)
	var i Comment
	err := row.Scan(
		&i.ID,
		&i.Content,
		&i.LikeCount,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetCredential = `-- name: GetCredential :one
SELECT id, user_id, public_key, description, name, created_at, deleted_at FROM credentials
WHERE public_key = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetCredential(ctx context.Context, db DBTX, publicKey string) (Credential, error) {
	row := db.QueryRowContext(ctx, GetCredential, publicKey)
	var i Credential
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.PublicKey,
		&i.Description,
		&i.Name,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetFollowedUsers = `-- name: GetFollowedUsers :many
SELECT
	u.id, u.username, u.hashed_password, u.hashed_password_expires_at, u.salt, u.first_name, u.last_name, u.email, u.email_token, u.email_verified_at, u.created_at, u.updated_at, u.deleted_at
FROM
	users u,
	followers f
WHERE
	f.follower_id = $1
	AND f.followed_id = u.id
	AND u.deleted_at IS NULL
ORDER BY
	u.first_name
`

func (q *Queries) GetFollowedUsers(ctx context.Context, db DBTX, followerID int64) ([]User, error) {
	rows, err := db.QueryContext(ctx, GetFollowedUsers, followerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.Username,
			&i.HashedPassword,
			&i.HashedPasswordExpiresAt,
			&i.Salt,
			&i.FirstName,
			&i.LastName,
			&i.Email,
			&i.EmailToken,
			&i.EmailVerifiedAt,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const GetFollowers = `-- name: GetFollowers :many
SELECT
	u.id, u.username, u.hashed_password, u.hashed_password_expires_at, u.salt, u.first_name, u.last_name, u.email, u.email_token, u.email_verified_at, u.created_at, u.updated_at, u.deleted_at
FROM
	users u,
	followers f
WHERE
	f.followed_id = $1
	AND f.follower_id = u.id
	AND u.deleted_at IS NULL
ORDER BY
	u.first_name
`

func (q *Queries) GetFollowers(ctx context.Context, db DBTX, followedID int64) ([]User, error) {
	rows, err := db.QueryContext(ctx, GetFollowers, followedID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.Username,
			&i.HashedPassword,
			&i.HashedPasswordExpiresAt,
			&i.Salt,
			&i.FirstName,
			&i.LastName,
			&i.Email,
			&i.EmailToken,
			&i.EmailVerifiedAt,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const GetRole = `-- name: GetRole :one
SELECT id, name, description, created_at, deleted_at FROM roles
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetRole(ctx context.Context, db DBTX, id int64) (Role, error) {
	row := db.QueryRowContext(ctx, GetRole, id)
	var i Role
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetRoleByName = `-- name: GetRoleByName :one
SELECT id, name, description, created_at, deleted_at FROM roles
WHERE name = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetRoleByName(ctx context.Context, db DBTX, name string) (Role, error) {
	row := db.QueryRowContext(ctx, GetRoleByName, name)
	var i Role
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetScope = `-- name: GetScope :one
SELECT id, name, description, created_at, deleted_at FROM scopes
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetScope(ctx context.Context, db DBTX, id int64) (Scope, error) {
	row := db.QueryRowContext(ctx, GetScope, id)
	var i Scope
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetScopeByName = `-- name: GetScopeByName :one
SELECT id, name, description, created_at, deleted_at FROM scopes
WHERE name = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetScopeByName(ctx context.Context, db DBTX, name string) (Scope, error) {
	row := db.QueryRowContext(ctx, GetScopeByName, name)
	var i Scope
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Description,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetToken = `-- name: GetToken :one
SELECT id, user_id, token, valid_from, valid_until FROM tokens
WHERE token = $1 LIMIT 1
`

func (q *Queries) GetToken(ctx context.Context, db DBTX, token string) (Token, error) {
	row := db.QueryRowContext(ctx, GetToken, token)
	var i Token
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.ValidFrom,
		&i.ValidUntil,
	)
	return i, err
}

const GetTokenScopes = `-- name: GetTokenScopes :many
SELECT
	s.id, s.name, s.description, s.created_at, s.deleted_at
FROM
	scopes s
	INNER JOIN tokens_to_scopes ts ON ts.scope_id = s.id
	INNER JOIN tokens t ON t.id = ts.token_id
WHERE
	t.id = $1
	AND t.valid_until > NOW()
	AND s.deleted_at IS NULL
`

func (q *Queries) GetTokenScopes(ctx context.Context, db DBTX, id int64) ([]Scope, error) {
	rows, err := db.QueryContext(ctx, GetTokenScopes, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Scope
	for rows.Next() {
		var i Scope
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const GetUserByEmail = `-- name: GetUserByEmail :one
SELECT id, username, hashed_password, hashed_password_expires_at, salt, first_name, last_name, email, email_token, email_verified_at, created_at, updated_at, deleted_at FROM users
WHERE email = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, db DBTX, email string) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.HashedPassword,
		&i.HashedPasswordExpiresAt,
		&i.Salt,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.EmailToken,
		&i.EmailVerifiedAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserByID = `-- name: GetUserByID :one
SELECT id, username, hashed_password, hashed_password_expires_at, salt, first_name, last_name, email, email_token, email_verified_at, created_at, updated_at, deleted_at FROM users
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByID(ctx context.Context, db DBTX, id int64) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.HashedPassword,
		&i.HashedPasswordExpiresAt,
		&i.Salt,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.EmailToken,
		&i.EmailVerifiedAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserByUsername = `-- name: GetUserByUsername :one
SELECT id, username, hashed_password, hashed_password_expires_at, salt, first_name, last_name, email, email_token, email_verified_at, created_at, updated_at, deleted_at FROM users
WHERE username = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByUsername(ctx context.Context, db DBTX, username string) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByUsername, username)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.HashedPassword,
		&i.HashedPasswordExpiresAt,
		&i.Salt,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.EmailToken,
		&i.EmailVerifiedAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserComments = `-- name: GetUserComments :many
SELECT
	c.id, c.content, c.like_count, c.user_id, c.created_at, c.updated_at, c.deleted_at
FROM
	comments c JOIN users u
	ON c.user_id = u.id
WHERE
	u.username = $1
	AND c.deleted_at IS NULL
	AND u.deleted_at IS NULL
ORDER BY
	c.created_at DESC
LIMIT $2 OFFSET $3
`

type GetUserCommentsParams struct {
	Username string `json:"username"`
	Limit    int32  `json:"limit"`
	Offset   int32  `json:"offset"`
}

func (q *Queries) GetUserComments(ctx context.Context, db DBTX, arg GetUserCommentsParams) ([]Comment, error) {
	rows, err := db.QueryContext(ctx, GetUserComments, arg.Username, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Comment
	for rows.Next() {
		var i Comment
		if err := rows.Scan(
			&i.ID,
			&i.Content,
			&i.LikeCount,
			&i.UserID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const GetUserRoles = `-- name: GetUserRoles :many
SELECT
	r.id, r.name, r.description, r.created_at, r.deleted_at
FROM
	users u
	INNER JOIN users_to_roles ur ON ur.user_id = u.id
	INNER JOIN roles r ON r.id = ur.role_id
WHERE
	u.id = $1
	AND u.deleted_at IS NULL
	AND r.deleted_at IS NULL
`

func (q *Queries) GetUserRoles(ctx context.Context, db DBTX, id int64) ([]Role, error) {
	rows, err := db.QueryContext(ctx, GetUserRoles, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Role
	for rows.Next() {
		var i Role
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListComment = `-- name: ListComment :many
SELECT id, content, like_count, user_id, created_at, updated_at, deleted_at FROM comments
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1 OFFSET $2
`

type ListCommentParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListComment(ctx context.Context, db DBTX, arg ListCommentParams) ([]Comment, error) {
	rows, err := db.QueryContext(ctx, ListComment, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Comment
	for rows.Next() {
		var i Comment
		if err := rows.Scan(
			&i.ID,
			&i.Content,
			&i.LikeCount,
			&i.UserID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListRoleScopes = `-- name: ListRoleScopes :many
SELECT
	s.id, s.name, s.description, s.created_at, s.deleted_at
FROM
	scopes s
	INNER JOIN roles_to_scopes rs ON rs.scope_id = s.id
	INNER JOIN roles r ON r.id = rs.role_id
WHERE
	r.id = $1
	AND r.deleted_at IS NULL
	AND s.deleted_at IS NULL
ORDER BY
	s.name
LIMIT $2 OFFSET $3
`

type ListRoleScopesParams struct {
	ID     int64 `json:"id"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListRoleScopes(ctx context.Context, db DBTX, arg ListRoleScopesParams) ([]Scope, error) {
	rows, err := db.QueryContext(ctx, ListRoleScopes, arg.ID, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Scope
	for rows.Next() {
		var i Scope
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListRoles = `-- name: ListRoles :many
SELECT id, name, description, created_at, deleted_at FROM roles
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1 OFFSET $2
`

type ListRolesParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListRoles(ctx context.Context, db DBTX, arg ListRolesParams) ([]Role, error) {
	rows, err := db.QueryContext(ctx, ListRoles, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Role
	for rows.Next() {
		var i Role
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListScopes = `-- name: ListScopes :many
SELECT id, name, description, created_at, deleted_at FROM scopes
WHERE deleted_at IS NULL
LIMIT $1 OFFSET $2
`

type ListScopesParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListScopes(ctx context.Context, db DBTX, arg ListScopesParams) ([]Scope, error) {
	rows, err := db.QueryContext(ctx, ListScopes, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Scope
	for rows.Next() {
		var i Scope
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const ListUsers = `-- name: ListUsers :many
SELECT id, username, hashed_password, hashed_password_expires_at, salt, first_name, last_name, email, email_token, email_verified_at, created_at, updated_at, deleted_at FROM users
WHERE deleted_at IS NULL
ORDER BY created_at ASC
LIMIT $1 OFFSET $2
`

type ListUsersParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListUsers(ctx context.Context, db DBTX, arg ListUsersParams) ([]User, error) {
	rows, err := db.QueryContext(ctx, ListUsers, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.Username,
			&i.HashedPassword,
			&i.HashedPasswordExpiresAt,
			&i.Salt,
			&i.FirstName,
			&i.LastName,
			&i.Email,
			&i.EmailToken,
			&i.EmailVerifiedAt,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const UnfollowUser = `-- name: UnfollowUser :exec
DELETE FROM followers
WHERE follower_id = $1 AND followed_id = $2
`

type UnfollowUserParams struct {
	FollowerID int64 `json:"follower_id"`
	FollowedID int64 `json:"followed_id"`
}

func (q *Queries) UnfollowUser(ctx context.Context, db DBTX, arg UnfollowUserParams) error {
	_, err := db.ExecContext(ctx, UnfollowUser, arg.FollowerID, arg.FollowedID)
	return err
}

const UpdateRole = `-- name: UpdateRole :exec
UPDATE roles 
SET name = $1, description = $2
WHERE id = $3 AND deleted_at IS NULL
`

type UpdateRoleParams struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ID          int64  `json:"id"`
}

func (q *Queries) UpdateRole(ctx context.Context, db DBTX, arg UpdateRoleParams) error {
	_, err := db.ExecContext(ctx, UpdateRole, arg.Name, arg.Description, arg.ID)
	return err
}

const UpdateScope = `-- name: UpdateScope :execresult
UPDATE scopes
SET name = $1, description = $2
WHERE id = $3 AND deleted_at IS NULL
`

type UpdateScopeParams struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ID          int64  `json:"id"`
}

func (q *Queries) UpdateScope(ctx context.Context, db DBTX, arg UpdateScopeParams) (sql.Result, error) {
	return db.ExecContext(ctx, UpdateScope, arg.Name, arg.Description, arg.ID)
}

const UpdateUser = `-- name: UpdateUser :exec
UPDATE users 
SET username=$1, hashed_password=$2, hashed_password_expires_at=$3, salt=$4, first_name=$5, last_name=$6, email=$7, email_token=$8, email_verified_at=$9, updated_at=$10
WHERE id=$11 AND deleted_at IS NULL
`

type UpdateUserParams struct {
	Username                string       `json:"username"`
	HashedPassword          string       `json:"hashed_password"`
	HashedPasswordExpiresAt time.Time    `json:"hashed_password_expires_at"`
	Salt                    string       `json:"salt"`
	FirstName               string       `json:"first_name"`
	LastName                string       `json:"last_name"`
	Email                   string       `json:"email"`
	EmailToken              string       `json:"email_token"`
	EmailVerifiedAt         sql.NullTime `json:"email_verified_at"`
	UpdatedAt               time.Time    `json:"updated_at"`
	ID                      int64        `json:"id"`
}

func (q *Queries) UpdateUser(ctx context.Context, db DBTX, arg UpdateUserParams) error {
	_, err := db.ExecContext(ctx, UpdateUser,
		arg.Username,
		arg.HashedPassword,
		arg.HashedPasswordExpiresAt,
		arg.Salt,
		arg.FirstName,
		arg.LastName,
		arg.Email,
		arg.EmailToken,
		arg.EmailVerifiedAt,
		arg.UpdatedAt,
		arg.ID,
	)
	return err
}

const UpdateUserByUsername = `-- name: UpdateUserByUsername :exec
UPDATE users 
SET username = $10, hashed_password=$1, hashed_password_expires_at=$2, salt=$3, first_name=$4, last_name=$5, email=$6, email_token=$7, email_verified_at=$8, updated_at=$9
WHERE username = $11 AND deleted_at IS NULL
`

type UpdateUserByUsernameParams struct {
	HashedPassword          string       `json:"hashed_password"`
	HashedPasswordExpiresAt time.Time    `json:"hashed_password_expires_at"`
	Salt                    string       `json:"salt"`
	FirstName               string       `json:"first_name"`
	LastName                string       `json:"last_name"`
	Email                   string       `json:"email"`
	EmailToken              string       `json:"email_token"`
	EmailVerifiedAt         sql.NullTime `json:"email_verified_at"`
	UpdatedAt               time.Time    `json:"updated_at"`
	NewUsername             string       `json:"new_username"`
	OldUsername             string       `json:"old_username"`
}

func (q *Queries) UpdateUserByUsername(ctx context.Context, db DBTX, arg UpdateUserByUsernameParams) error {
	_, err := db.ExecContext(ctx, UpdateUserByUsername,
		arg.HashedPassword,
		arg.HashedPasswordExpiresAt,
		arg.Salt,
		arg.FirstName,
		arg.LastName,
		arg.Email,
		arg.EmailToken,
		arg.EmailVerifiedAt,
		arg.UpdatedAt,
		arg.NewUsername,
		arg.OldUsername,
	)
	return err
}

// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.15.0

package db

import (
	"database/sql"
	"time"
)

type Comment struct {
	ID        int64        `json:"id"`
	Content   string       `json:"content"`
	LikeCount int32        `json:"like_count"`
	UserID    int64        `json:"user_id"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	DeletedAt sql.NullTime `json:"deleted_at"`
}

type Credential struct {
	ID          int64        `json:"id"`
	UserID      int64        `json:"user_id"`
	PublicKey   string       `json:"public_key"`
	Description string       `json:"description"`
	Name        string       `json:"name"`
	CreatedAt   time.Time    `json:"created_at"`
	DeletedAt   sql.NullTime `json:"deleted_at"`
}

type Follower struct {
	ID         int64 `json:"id"`
	FollowerID int64 `json:"follower_id"`
	FollowedID int64 `json:"followed_id"`
}

type Role struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	CreatedAt   time.Time    `json:"created_at"`
	DeletedAt   sql.NullTime `json:"deleted_at"`
}

type RolesToScope struct {
	ID      int64 `json:"id"`
	RoleID  int64 `json:"role_id"`
	ScopeID int32 `json:"scope_id"`
}

type Scope struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	CreatedAt   time.Time    `json:"created_at"`
	DeletedAt   sql.NullTime `json:"deleted_at"`
}

type Token struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	Token      string    `json:"token"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

type TokensToScope struct {
	ID      int64 `json:"id"`
	TokenID int64 `json:"token_id"`
	ScopeID int64 `json:"scope_id"`
}

type User struct {
	ID                      int64        `json:"id"`
	Username                string       `json:"username"`
	HashedPassword          string       `json:"hashed_password"`
	HashedPasswordExpiresAt time.Time    `json:"hashed_password_expires_at"`
	Salt                    string       `json:"salt"`
	FirstName               string       `json:"first_name"`
	LastName                string       `json:"last_name"`
	Email                   string       `json:"email"`
	EmailToken              string       `json:"email_token"`
	EmailVerifiedAt         sql.NullTime `json:"email_verified_at"`
	CreatedAt               time.Time    `json:"created_at"`
	UpdatedAt               time.Time    `json:"updated_at"`
	DeletedAt               sql.NullTime `json:"deleted_at"`
}

type UsersToRole struct {
	ID     int64 `json:"id"`
	RoleID int64 `json:"role_id"`
	UserID int64 `json:"user_id"`
}

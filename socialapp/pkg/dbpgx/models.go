// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package dbpgx

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type Comment struct {
	ID        int64            `json:"id"`
	Content   string           `json:"content"`
	LikeCount int64            `json:"like_count"`
	UserID    int64            `json:"user_id"`
	CreatedAt pgtype.Timestamp `json:"created_at"`
	UpdatedAt pgtype.Timestamp `json:"updated_at"`
	DeletedAt pgtype.Timestamp `json:"deleted_at"`
}

type Credential struct {
	ID          int64            `json:"id"`
	UserID      int64            `json:"user_id"`
	PublicKey   string           `json:"public_key"`
	Description string           `json:"description"`
	Name        string           `json:"name"`
	CreatedAt   pgtype.Timestamp `json:"created_at"`
	DeletedAt   pgtype.Timestamp `json:"deleted_at"`
}

type Event struct {
	ID            int64            `json:"id"`
	AggregateID   int64            `json:"aggregate_id"`
	AggregateType string           `json:"aggregate_type"`
	Version       int64            `json:"version"`
	EventType     string           `json:"event_type"`
	Payload       []byte           `json:"payload"`
	CreatedAt     pgtype.Timestamp `json:"created_at"`
	DeletedAt     pgtype.Timestamp `json:"deleted_at"`
}

type Follower struct {
	ID         int64 `json:"id"`
	FollowerID int64 `json:"follower_id"`
	FollowedID int64 `json:"followed_id"`
}

type Role struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	CreatedAt   pgtype.Timestamp `json:"created_at"`
	DeletedAt   pgtype.Timestamp `json:"deleted_at"`
}

type RolesToScope struct {
	ID      int64 `json:"id"`
	RoleID  int64 `json:"role_id"`
	ScopeID int64 `json:"scope_id"`
}

type Scope struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	CreatedAt   pgtype.Timestamp `json:"created_at"`
	DeletedAt   pgtype.Timestamp `json:"deleted_at"`
}

type Token struct {
	ID         int64            `json:"id"`
	UserID     int64            `json:"user_id"`
	Token      string           `json:"token"`
	ValidFrom  pgtype.Timestamp `json:"valid_from"`
	ValidUntil pgtype.Timestamp `json:"valid_until"`
}

type TokensToScope struct {
	ID      int64 `json:"id"`
	TokenID int64 `json:"token_id"`
	ScopeID int64 `json:"scope_id"`
}

type Url struct {
	ID        int64            `json:"id"`
	Url       string           `json:"url"`
	Alias     string           `json:"alias"`
	CreatedAt pgtype.Timestamp `json:"created_at"`
	UpdatedAt pgtype.Timestamp `json:"updated_at"`
	DeletedAt pgtype.Timestamp `json:"deleted_at"`
}

type User struct {
	ID                      int64            `json:"id"`
	Username                string           `json:"username"`
	HashedPassword          string           `json:"hashed_password"`
	HashedPasswordExpiresAt pgtype.Timestamp `json:"hashed_password_expires_at"`
	Salt                    string           `json:"salt"`
	FirstName               string           `json:"first_name"`
	LastName                string           `json:"last_name"`
	Email                   string           `json:"email"`
	EmailToken              string           `json:"email_token"`
	EmailVerifiedAt         pgtype.Timestamp `json:"email_verified_at"`
	CreatedAt               pgtype.Timestamp `json:"created_at"`
	UpdatedAt               pgtype.Timestamp `json:"updated_at"`
	DeletedAt               pgtype.Timestamp `json:"deleted_at"`
}

type UsersToRole struct {
	ID     int64 `json:"id"`
	RoleID int64 `json:"role_id"`
	UserID int64 `json:"user_id"`
}

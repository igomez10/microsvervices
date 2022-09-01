// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.15.0
// source: query.sql

package db

import (
	"context"
)

const CreateComment = `-- name: CreateComment :one
INSERT INTO comments (
  user_id, content
) VALUES (
  $1, $2
)
RETURNING id, content, like_count, created_at, user_id, deleted_at
`

type CreateCommentParams struct {
	UserID  int32  `json:"user_id"`
	Content string `json:"content"`
}

func (q *Queries) CreateComment(ctx context.Context, db DBTX, arg CreateCommentParams) (Comment, error) {
	row := db.QueryRowContext(ctx, CreateComment, arg.UserID, arg.Content)
	var i Comment
	err := row.Scan(
		&i.ID,
		&i.Content,
		&i.LikeCount,
		&i.CreatedAt,
		&i.UserID,
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
RETURNING id, content, like_count, created_at, user_id, deleted_at
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
		&i.CreatedAt,
		&i.UserID,
		&i.DeletedAt,
	)
	return i, err
}

const CreateUser = `-- name: CreateUser :one
INSERT INTO users (
  username, first_name, last_name, email
) VALUES (
  $1, $2, $3, $4
)
RETURNING id, username, first_name, last_name, email, created_at, deleted_at
`

type CreateUserParams struct {
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

func (q *Queries) CreateUser(ctx context.Context, db DBTX, arg CreateUserParams) (User, error) {
	row := db.QueryRowContext(ctx, CreateUser,
		arg.Username,
		arg.FirstName,
		arg.LastName,
		arg.Email,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const DeleteUser = `-- name: DeleteUser :exec
UPDATE users
SET deleted_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
`

func (q *Queries) DeleteUser(ctx context.Context, db DBTX, id int32) error {
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

const FollowUser = `-- name: FollowUser :exec
INSERT INTO followers (
  follower_id, followed_id
) VALUES (
  $1, $2
)
`

type FollowUserParams struct {
	FollowerID int32 `json:"follower_id"`
	FollowedID int32 `json:"followed_id"`
}

func (q *Queries) FollowUser(ctx context.Context, db DBTX, arg FollowUserParams) error {
	_, err := db.ExecContext(ctx, FollowUser, arg.FollowerID, arg.FollowedID)
	return err
}

const GetComment = `-- name: GetComment :one
SELECT id, content, like_count, created_at, user_id, deleted_at FROM comments
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetComment(ctx context.Context, db DBTX, id int32) (Comment, error) {
	row := db.QueryRowContext(ctx, GetComment, id)
	var i Comment
	err := row.Scan(
		&i.ID,
		&i.Content,
		&i.LikeCount,
		&i.CreatedAt,
		&i.UserID,
		&i.DeletedAt,
	)
	return i, err
}

const GetFollowedUsers = `-- name: GetFollowedUsers :many
SELECT
	u.id, u.username, u.first_name, u.last_name, u.email, u.created_at, u.deleted_at
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

func (q *Queries) GetFollowedUsers(ctx context.Context, db DBTX, followerID int32) ([]User, error) {
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
			&i.FirstName,
			&i.LastName,
			&i.Email,
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

const GetFollowers = `-- name: GetFollowers :many
SELECT
	u.id, u.username, u.first_name, u.last_name, u.email, u.created_at, u.deleted_at
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

func (q *Queries) GetFollowers(ctx context.Context, db DBTX, followedID int32) ([]User, error) {
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
			&i.FirstName,
			&i.LastName,
			&i.Email,
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
SELECT id, username, first_name, last_name, email, created_at, deleted_at FROM users
WHERE email = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, db DBTX, email string) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserByID = `-- name: GetUserByID :one
SELECT id, username, first_name, last_name, email, created_at, deleted_at FROM users
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByID(ctx context.Context, db DBTX, id int32) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserByUsername = `-- name: GetUserByUsername :one
SELECT id, username, first_name, last_name, email, created_at, deleted_at FROM users
WHERE username = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetUserByUsername(ctx context.Context, db DBTX, username string) (User, error) {
	row := db.QueryRowContext(ctx, GetUserByUsername, username)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const GetUserComments = `-- name: GetUserComments :many
SELECT
	c.id, c.content, c.like_count, c.created_at, c.user_id, c.deleted_at
FROM
	comments c JOIN users u
	ON c.user_id = u.id
WHERE
	u.username = $1
	AND c.deleted_at IS NULL
	AND u.deleted_at IS NULL
ORDER BY
	c.created_at DESC
`

func (q *Queries) GetUserComments(ctx context.Context, db DBTX, username string) ([]Comment, error) {
	rows, err := db.QueryContext(ctx, GetUserComments, username)
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
			&i.CreatedAt,
			&i.UserID,
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
SELECT id, content, like_count, created_at, user_id, deleted_at FROM comments
WHERE deleted_at IS NULL
ORDER BY created_at DESC
`

func (q *Queries) ListComment(ctx context.Context, db DBTX) ([]Comment, error) {
	rows, err := db.QueryContext(ctx, ListComment)
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
			&i.CreatedAt,
			&i.UserID,
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
SELECT id, username, first_name, last_name, email, created_at, deleted_at FROM users
WHERE deleted_at IS NULL
ORDER BY first_name
`

func (q *Queries) ListUsers(ctx context.Context, db DBTX) ([]User, error) {
	rows, err := db.QueryContext(ctx, ListUsers)
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
			&i.FirstName,
			&i.LastName,
			&i.Email,
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

const UnfollowUser = `-- name: UnfollowUser :exec
DELETE FROM followers
WHERE follower_id = $1 AND followed_id = $2
`

type UnfollowUserParams struct {
	FollowerID int32 `json:"follower_id"`
	FollowedID int32 `json:"followed_id"`
}

func (q *Queries) UnfollowUser(ctx context.Context, db DBTX, arg UnfollowUserParams) error {
	_, err := db.ExecContext(ctx, UnfollowUser, arg.FollowerID, arg.FollowedID)
	return err
}

const UpdateUser = `-- name: UpdateUser :one
UPDATE users 
SET username = $2, first_name = $3, last_name=$4, email=$5
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, username, first_name, last_name, email, created_at, deleted_at
`

type UpdateUserParams struct {
	ID        int32  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

func (q *Queries) UpdateUser(ctx context.Context, db DBTX, arg UpdateUserParams) (User, error) {
	row := db.QueryRowContext(ctx, UpdateUser,
		arg.ID,
		arg.Username,
		arg.FirstName,
		arg.LastName,
		arg.Email,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const UpdateUserByUsername = `-- name: UpdateUserByUsername :one
UPDATE users 
SET username = $4::text, first_name = $1, last_name=$2, email=$3
WHERE username = $5::text AND deleted_at IS NULL
RETURNING id, username, first_name, last_name, email, created_at, deleted_at
`

type UpdateUserByUsernameParams struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
	NewUsername string `json:"new_username"`
	OldUsername string `json:"old_username"`
}

func (q *Queries) UpdateUserByUsername(ctx context.Context, db DBTX, arg UpdateUserByUsernameParams) (User, error) {
	row := db.QueryRowContext(ctx, UpdateUserByUsername,
		arg.FirstName,
		arg.LastName,
		arg.Email,
		arg.NewUsername,
		arg.OldUsername,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.CreatedAt,
		&i.DeletedAt,
	)
	return i, err
}

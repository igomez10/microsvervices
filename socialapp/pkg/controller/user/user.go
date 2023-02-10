package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/google/uuid"
	"github.com/igomez10/microservices/socialapp/internal/contexthelper"
	"github.com/igomez10/microservices/socialapp/internal/converter"
	"github.com/igomez10/microservices/socialapp/pkg/db"
	"github.com/igomez10/microservices/socialapp/socialappapi/openapi"
)

// implements the UserServicer interface
// s *UserApiService openapi.UserApiServicer
type UserApiService struct {
	DB            db.Querier
	DBConn        *sql.DB
	KafkaProducer *kafka.Producer
}

const DEFAULT_ROLE_NAME = "administrator"

func (s *UserApiService) CreateUser(ctx context.Context, user openapi.CreateUserRequest) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate we dont have a user with the same username that is not deleted
	// start transaction
	tx, err := s.DBConn.BeginTx(ctx, nil)
	defer tx.Rollback()

	if err != nil {
		log.Error().
			Err(err).
			Msg("Error starting transaction")
		return openapi.Response(http.StatusInternalServerError, nil), nil
	}

	if _, err := s.DB.GetUserByUsername(ctx, tx, user.Username); err == nil {
		log.Error().
			Err(err).
			Msg("Username already exists")
		return openapi.Response(http.StatusConflict, nil), nil
	}

	// validate we dont have a user with the same email that is not deleted
	if _, err := s.DB.GetUserByEmail(ctx, tx, user.Email); err == nil {
		log.Error().
			Err(err).
			Msg("Email already exists")
		return openapi.Response(http.StatusConflict, nil), nil
	}

	// generate a random salt
	saltUUID, err := uuid.NewRandom()
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error generating random string for salt")
		return openapi.Response(http.StatusInternalServerError, nil), nil
	}
	salt := base64.StdEncoding.EncodeToString([]byte(saltUUID.String()))

	hashedPasswordBase64 := EncryptPassword(user.Password, salt)
	//generate random email token confirmation
	// generate a random salt
	emailTokenUUID, err := uuid.NewRandom()
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error generating random string for salt")
		return openapi.Response(http.StatusInternalServerError, nil), nil
	}
	emailToken := base64.StdEncoding.EncodeToString([]byte(emailTokenUUID.String()))

	// create the user with an autogenerated password that already expired
	params := db.CreateUserParams{
		Username:       user.Username,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		HashedPassword: hashedPasswordBase64,
		EmailToken:     emailToken,
		Salt:           salt,
		EmailVerifiedAt: sql.NullTime{ // We will assume every email is confirmed for now
			Time:  time.Now(),
			Valid: true,
		},
	}

	// get the role id for "user"
	role, err := s.DB.GetRoleByName(ctx, tx, DEFAULT_ROLE_NAME)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting role id for user")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error getting role id for user",
			},
		}, nil
	}

	createdUser, err := s.DB.CreateUser(ctx, tx, params)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error creating user")
		return openapi.Response(http.StatusInternalServerError, nil), nil
	}

	// attach the default role to the user
	params2 := db.CreateUserToRoleParams{
		UserID: createdUser.ID,
		RoleID: role.ID,
	}
	if _, err := s.DB.CreateUserToRole(ctx, tx, params2); err != nil {
		log.Error().
			Err(err).
			Str("username", user.Username).
			Str("default_role", DEFAULT_ROLE_NAME).
			Msg("Error attaching role to user")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error attaching default role to user",
			},
		}, nil
	}

	// commit transaction
	if err := tx.Commit(); err != nil {
		log.Error().
			Err(err).
			Msg("Error committing transaction")

		return openapi.Response(http.StatusInternalServerError, nil), nil
	}

	apiUser := converter.FromDBUserToAPIUser(createdUser)

	return openapi.Response(http.StatusOK, apiUser), nil
}

func EncryptPassword(plaintextPassword string, salt string) string {
	saltedPassword := plaintextPassword + salt
	hashedPassword := sha256.Sum256([]byte(saltedPassword))
	hashedPasswordBase64 := base64.StdEncoding.EncodeToString(hashedPassword[:])
	return hashedPasswordBase64
}

// DeleteUser - Deletes a particular user
func (s *UserApiService) DeleteUser(ctx context.Context, username string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	if err := s.DB.DeleteUserByUsername(ctx, s.DBConn, username); err != nil {
		log.Error().Err(err).
			Msg("Error deleting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error deleting user",
			},
		}, nil
	}

	return openapi.Response(http.StatusOK, nil), nil
}

// GetUserByUsername - Get a particular user by username
func (s *UserApiService) GetUserByUsername(ctx context.Context, username string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	dbUser, err := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	apiUser := converter.FromDBUserToAPIUser(dbUser)
	return openapi.Response(http.StatusOK, apiUser), nil
}

// GetUserComments - Gets all comments for a user
func (s *UserApiService) GetUserComments(ctx context.Context, username string, limit int32, offset int32) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)

	limit = limit % 100
	if limit == 0 {
		limit = 100
	}
	commnet, err := s.DB.GetUserComments(ctx, s.DBConn, db.GetUserCommentsParams{
		Username: username,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user comments")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user comments",
			},
		}, nil
	}

	return openapi.Response(http.StatusOK, commnet), nil
}

// ListUsers - Returns all the users
func (s *UserApiService) ListUsers(ctx context.Context, limit, offset int32) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	limit = limit % 20
	if limit == 0 {
		limit = 20
	}
	dbUsers, err := s.DB.ListUsers(ctx, s.DBConn, db.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		log.Error().
			Stack().
			Err(err).
			Msg("Error listing users")

		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error listing users",
			},
		}, nil
	}

	apiUsers := make([]openapi.User, len(dbUsers))
	for i := range dbUsers {
		apiUsers[i] = converter.FromDBUserToAPIUser(dbUsers[i])
	}

	return openapi.Response(http.StatusOK, apiUsers), nil
}

func (s *UserApiService) UpdateUser(ctx context.Context, existingUsername string, newUserData openapi.User) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// begin transaction
	tx, err := s.DBConn.BeginTx(ctx, nil)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error starting transaction")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
		}, nil
	}

	// get the user to update
	existingUser, err := s.DB.GetUserByUsername(ctx, tx, existingUsername)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "User not found",
			},
		}, nil
	}

	if newUserData.Username != "" && newUserData.Username != existingUser.Username {
		// validate we dont have a user with the same username that is not deleted
		noCaseUsername := strings.ToLower(newUserData.Username)
		if _, err := s.DB.GetUserByUsername(ctx, tx, noCaseUsername); err == nil {
			log.Error().
				Err(err).
				Msg("Username already exists")

			return openapi.ImplResponse{
				Code: http.StatusConflict,
				Body: openapi.Error{
					Code:    http.StatusConflict,
					Message: "Username already exists",
				},
			}, nil
		}
		existingUser.Username = newUserData.Username
	}

	if newUserData.Email != "" && newUserData.Email != existingUser.Email {
		// validate we dont have a user with the same email that is not deleted
		noCaseEmail := strings.ToLower(newUserData.Email)
		if _, err := s.DB.GetUserByEmail(ctx, tx, noCaseEmail); err == nil {
			log.Error().
				Err(err).
				Msg("Email already exists")
			return openapi.ImplResponse{
				Code: http.StatusConflict,
				Body: openapi.Error{
					Code:    http.StatusConflict,
					Message: "Email already exists",
				},
			}, nil
		}
		existingUser.Email = newUserData.Email
	}

	if newUserData.FirstName != "" {
		existingUser.FirstName = newUserData.FirstName
	}
	if newUserData.LastName != "" {
		existingUser.LastName = newUserData.LastName
	}

	params := db.UpdateUserByUsernameParams{
		OldUsername: existingUsername,
		NewUsername: newUserData.Username,
		FirstName:   newUserData.FirstName,
		LastName:    newUserData.LastName,
		Email:       newUserData.Email,
	}

	log.Debug().Msgf("UpdateUserByUsernameParams: \n%+v\n", params)
	if err := s.DB.UpdateUserByUsername(ctx, tx, params); err != nil {
		log.Error().
			Err(err).
			Msg("Error updating user")

		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error updating user",
			},
		}, nil
	}

	// get the updated user
	updatedUser, err := s.DB.GetUserByUsername(ctx, tx, existingUser.Username)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user")

		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error getting user",
			},
		}, nil
	}

	apiUser := converter.FromDBUserToAPIUser(updatedUser)

	return openapi.Response(http.StatusOK, apiUser), nil
}

func (s *UserApiService) FollowUser(ctx context.Context, followedUsername string, followerUsername string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate the user exists
	followedUser, errGetFollowed := s.DB.GetUserByUsername(ctx, s.DBConn, followedUsername)
	if errGetFollowed != nil {
		log.Error().
			Err(errGetFollowed).
			Msg("Error getting followed user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting followed user",
			},
		}, nil
	}

	followerUser, errGetFollower := s.DB.GetUserByUsername(ctx, s.DBConn, followerUsername)
	if errGetFollower != nil {
		log.Error().
			Err(errGetFollower).
			Msg("Error getting follower user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting follower user",
			},
		}, nil
	}

	//  add follow connection
	err := s.DB.FollowUser(ctx, s.DBConn, db.FollowUserParams{
		FollowerID: followerUser.ID,
		FollowedID: followedUser.ID,
	})
	if err != nil {
		log.Error().
			Err(errGetFollower).
			Msg("Error following user")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error following user",
			},
		}, nil
	}

	return openapi.Response(http.StatusOK, nil), nil
}

func (s *UserApiService) GetUserFollowers(ctx context.Context, username string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate the user exists
	user, errGetUser := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if errGetUser != nil {
		log.Error().
			Err(errGetUser).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	dbFollowers, err := s.DB.GetFollowers(ctx, s.DBConn, user.ID)
	if err != nil {
		log.Error().
			Err(err).
			Int64("user_id", user.ID).
			Msg("Error getting followers")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error getting followers",
			},
		}, nil
	}

	apiFollowers := make([]openapi.User, len(dbFollowers))
	for i := range dbFollowers {
		apiFollowers[i] = converter.FromDBUserToAPIUser(dbFollowers[i])
	}

	return openapi.Response(http.StatusOK, apiFollowers), nil
}

func (s *UserApiService) UnfollowUser(ctx context.Context, followedUsername string, followerUsername string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate the user exists
	followedUser, errGetFollowed := s.DB.GetUserByUsername(ctx, s.DBConn, followedUsername)
	if errGetFollowed != nil {
		log.Error().
			Err(errGetFollowed).
			Msg("Error getting followed user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting followed user",
			},
		}, nil
	}

	followerUser, errGetFollower := s.DB.GetUserByUsername(ctx, s.DBConn, followerUsername)
	if errGetFollower != nil {
		log.Error().
			Err(errGetFollower).
			Msg("Error getting follower user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting follower user",
			},
		}, nil
	}

	//  add follow connection
	err := s.DB.UnfollowUser(ctx, s.DBConn, db.UnfollowUserParams{
		FollowerID: followerUser.ID,
		FollowedID: followedUser.ID,
	})
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error unfollowing user")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error unfollowing user",
			},
		}, nil
	}

	return openapi.Response(http.StatusOK, nil), nil
}

func (s *UserApiService) GetFollowingUsers(ctx context.Context, username string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate the user exists
	user, errGetUser := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if errGetUser != nil {
		log.Error().
			Err(errGetUser).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	dbFollowing, err := s.DB.GetFollowedUsers(ctx, s.DBConn, user.ID)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting followed users")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting followed users",
			},
		}, nil
	}

	apiFollowing := make([]openapi.User, len(dbFollowing))
	for i := range dbFollowing {
		apiFollowing[i] = converter.FromDBUserToAPIUser(dbFollowing[i])
	}

	return openapi.Response(http.StatusOK, apiFollowing), nil
}

func (s *UserApiService) ChangePassword(ctx context.Context, req openapi.ChangePasswordRequest) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// get user from request context
	username, ok := ctx.Value("username").(string)
	if !ok {
		log.Error().
			Msg("Error getting user from context")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error getting user from context",
			},
		}, nil
	}

	// validate the user exists
	user, errGetUser := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if errGetUser != nil {
		log.Error().
			Err(errGetUser).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	// validate the old password is correct
	encryptedHashedOldPassword := EncryptPassword(req.OldPassword, user.Salt)
	if encryptedHashedOldPassword != user.HashedPassword {
		log.Error().
			Msg("Error validating old password")

		return openapi.ImplResponse{
			Code: http.StatusUnauthorized,
			Body: openapi.Error{
				Code:    http.StatusUnauthorized,
				Message: "Error validating old password",
			},
		}, nil
	}

	// hash the new password but keep the same salt
	encryptedHashedNewPassword := EncryptPassword(req.NewPassword, user.Salt)

	// update the password
	params := db.UpdateUserParams{
		ID:                      user.ID,
		HashedPassword:          string(encryptedHashedNewPassword),
		Username:                user.Username,
		FirstName:               user.FirstName,
		LastName:                user.LastName,
		Email:                   user.Email,
		Salt:                    user.Salt,
		HashedPasswordExpiresAt: user.HashedPasswordExpiresAt,
		EmailToken:              user.EmailToken,
		EmailVerifiedAt:         user.EmailVerifiedAt,
	}

	if err := s.DB.UpdateUser(ctx, s.DBConn, params); err != nil {
		log.Error().
			Err(err).
			Msg("Error updating password")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error updating password",
			},
		}, nil
	}

	// invalidate existing tokens
	if err := s.DB.DeleteAllTokensForUser(ctx, s.DBConn, user.ID); err != nil {
		log.Error().
			Err(err).
			Msg("Error deleting existing tokens")
		return openapi.ImplResponse{
			Code: http.StatusInternalServerError,
			Body: openapi.Error{
				Code:    http.StatusInternalServerError,
				Message: "Error deleting existing tokens",
			},
		}, nil
	}

	apiUser := converter.FromDBUserToAPIUser(user)
	return openapi.Response(http.StatusOK, apiUser), nil
}

func (s *UserApiService) ResetPassword(_ context.Context, _ openapi.ResetPasswordRequest) (openapi.ImplResponse, error) {
	// log := contexthelper.GetLoggerInContext(ctx)
	panic("not implemented") // TODO: Implement
}

func (s *UserApiService) GetRolesForUser(ctx context.Context, username string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// validate user exists
	user, errGetUser := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if errGetUser != nil {
		log.Error().
			Err(errGetUser).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	// get user roles
	dbRoles, err := s.DB.GetUserRoles(ctx, s.DBConn, user.ID)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user roles")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user roles",
			},
		}, nil
	}

	// convert to api response
	apiRoles := make([]openapi.Role, len(dbRoles))
	for i := range dbRoles {
		apiRoles[i] = converter.FromDBRoleToAPIRole(dbRoles[i])
	}

	return openapi.Response(http.StatusOK, apiRoles), nil
}

func (s *UserApiService) UpdateRolesForUser(ctx context.Context, username string, roles []string) (openapi.ImplResponse, error) {
	log := contexthelper.GetLoggerInContext(ctx)
	// verify the user exists
	user, errGetUser := s.DB.GetUserByUsername(ctx, s.DBConn, username)
	if errGetUser != nil {
		log.Error().
			Err(errGetUser).
			Msg("Error getting user")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user",
			},
		}, nil
	}

	// verify all the roles exist
	dbRoles := make([]db.Role, len(roles))
	for i := range roles {
		dbRole, err := s.DB.GetRoleByName(ctx, s.DBConn, roles[i])
		if err != nil {
			log.Error().
				Err(err).
				Msg("Error getting role")
			return openapi.ImplResponse{
				Code: http.StatusNotFound,
				Body: openapi.Error{
					Code:    http.StatusNotFound,
					Message: "Error getting role",
				},
			}, nil
		}
		dbRoles[i] = dbRole
	}

	// get all existing roles
	existingRoles, err := s.DB.GetUserRoles(ctx, s.DBConn, user.ID)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Error getting user roles")
		return openapi.ImplResponse{
			Code: http.StatusNotFound,
			Body: openapi.Error{
				Code:    http.StatusNotFound,
				Message: "Error getting user roles",
			},
		}, nil
	}

	newRoles := map[string]db.Role{}
	for _, role := range dbRoles {
		newRoles[role.Name] = role
	}

	oldRoles := map[string]db.Role{}
	for _, role := range existingRoles {
		oldRoles[role.Name] = role
	}

	// roles to add
	rolesToAdd := []string{}

	for i := range newRoles {
		if _, ok := oldRoles[i]; !ok {
			rolesToAdd = append(rolesToAdd, i)
		}
	}

	// roles to remove
	rolesToRemove := []string{}
	for i := range oldRoles {
		if _, ok := newRoles[i]; !ok {
			rolesToRemove = append(rolesToRemove, i)
		}
	}

	// add new roles
	for _, roleNameToAdd := range rolesToAdd {
		roleID := newRoles[roleNameToAdd].ID
		_, err := s.DB.CreateUserToRole(ctx, s.DBConn, db.CreateUserToRoleParams{
			UserID: user.ID,
			RoleID: roleID,
		})
		if err != nil {
			log.Error().
				Err(err).
				Str("role", roleNameToAdd).
				Msg("Error adding role to user")
			return openapi.ImplResponse{
				Code: http.StatusInternalServerError,
				Body: openapi.Error{
					Code:    http.StatusInternalServerError,
					Message: "Error adding role to user",
				},
			}, nil
		}
	}

	// remove old roles
	for _, roleNameToRemove := range rolesToRemove {
		roleID := oldRoles[roleNameToRemove].ID
		err := s.DB.DeleteUserToRole(ctx, s.DBConn, db.DeleteUserToRoleParams{
			UserID: user.ID,
			RoleID: roleID,
		})
		if err != nil {
			log.Error().
				Err(err).
				Str("role", roleNameToRemove).
				Msg("Error removing role from user")
			return openapi.ImplResponse{
				Code: http.StatusInternalServerError,
				Body: openapi.Error{
					Code:    http.StatusInternalServerError,
					Message: "Error removing role from user",
				},
			}, nil
		}
	}

	return openapi.Response(http.StatusOK, nil), nil
}

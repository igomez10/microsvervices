package integration_tests

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"socialapp/client"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var apiClient *client.APIClient
var ENDPOINT_OAUTH_TOKEN string = "http://localhost:8085/oauth/token"

var (
	RENDER_SERVER_URL          = 0
	LOCALHOST_SERVER_URL       = 1
	LOCALHOST_DEBUG_SERVER_URL = 2

	CONTEXT_SERVER = LOCALHOST_DEBUG_SERVER_URL
)

func getOuath2Context(initialContext context.Context, config clientcredentials.Config) (context.Context, error) {
	tokenSource := config.TokenSource(initialContext)
	initialContext = context.WithValue(initialContext, client.ContextOAuth2, tokenSource)

	return initialContext, nil
}

func TestListUsers(t *testing.T) {
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient

	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)

	username1 := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	password := fmt.Sprintf("Password-%d1", time.Now().UnixNano())
	apiClient = client.NewAPIClient(configuration)
	func() {
		createUsrReq := client.NewCreateUserRequest(username1, password, "FirstName_example", "LastName_example", username1)
		_, _, err := apiClient.UserApi.CreateUser(proxyCtx).CreateUserRequest(*createUsrReq).Execute()
		if err != nil {
			t.Fatalf("Error creating user: %v", err)
		}
	}()

	conf := clientcredentials.Config{
		ClientID:     username1,
		ClientSecret: password,
		Scopes:       []string{"socialapp.users.list"},
		TokenURL:     ENDPOINT_OAUTH_TOKEN,
	}
	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)
	if err != nil {
		t.Fatalf("Error getting oauth2 context: %v", err)
	}
	openAPICtx := context.WithValue(oauth2Ctx, client.ContextServerIndex, CONTEXT_SERVER)

	// List users

	_, r, err := apiClient.UserApi.ListUsers(openAPICtx).Limit(10).Offset(0).Execute()
	if err != nil {
		t.Errorf("Error when calling `UserApi.ListUsers``: %v\n", err)
		t.Errorf("Full HTTP response: %v\n", r)
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, r.StatusCode)
	}
}

func TestCreateUser(t *testing.T) {
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	noAuthCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	noAuthCtx = context.WithValue(noAuthCtx, client.ContextServerIndex, CONTEXT_SERVER)

	apiClient = client.NewAPIClient(configuration)

	username := fmt.Sprintf("Test-%d", time.Now().UnixNano())
	password := "password"
	email := fmt.Sprintf("Test-%d-@social.com", time.Now().UnixNano())
	user := *client.NewCreateUserRequest(username, "password", "FirstName_example", "LastName_example", email) // User | Create a new user

	func() {
		_, r, err := apiClient.UserApi.CreateUser(noAuthCtx).
			CreateUserRequest(user).
			Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.CreateUser`: %v\n %+v\n", err, r)
		}
		if r.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, r.StatusCode)
		}
	}()

	func() {
		conf := clientcredentials.Config{
			ClientID:     username,
			ClientSecret: password,
			Scopes:       []string{"socialapp.users.read"},
			TokenURL:     ENDPOINT_OAUTH_TOKEN,
		}
		oauth2Ctx, err := getOuath2Context(noAuthCtx, conf)
		if err != nil {
			t.Fatalf("Error getting oauth2 context: %v", err)
		}

		resp, r, err := apiClient.UserApi.GetUserByUsername(oauth2Ctx, username).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.GetUserByUsername`: %v\n %+v\n", err, r)
		}
		if r.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, r.StatusCode)
		}
		if resp.Username != user.Username {
			t.Errorf("Expected username %s, got %s", user.Username, resp.Username)
		}
		if resp.Email != user.Email {
			t.Errorf("Expected email %s, got %s", user.Email, resp.Email)
		}
		if resp.FirstName != user.FirstName {
			t.Errorf("Expected first name %q, got %q", user.FirstName, resp.FirstName)
		}
		if resp.LastName != user.LastName {
			t.Errorf("Expected last name %q, got %q", user.LastName, resp.LastName)
		}
	}()
}

func TestFollowCycle(t *testing.T) {
	// create two users
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)

	apiClient = client.NewAPIClient(configuration)

	username1 := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	email1 := fmt.Sprintf("Test-%d-1@social.com", time.Now().UnixNano())
	user1 := *client.NewCreateUserRequest(username1, "password", "FirstName_example", "LastName_example", email1) // User | Create a new user

	username2 := fmt.Sprintf("Test-%d2", time.Now().UnixNano())
	email2 := fmt.Sprintf("Test-%d-2@social.com", time.Now().UnixNano())
	user2 := *client.NewCreateUserRequest(username2, "secretPassword", "FirstName_example", "LastName_example", email2) // User | Create a new user

	// create users
	func() {
		_, r1, err1 := apiClient.UserApi.CreateUser(proxyCtx).
			CreateUserRequest(user1).
			Execute()
		if err1 != nil {
			t.Errorf("Error when calling `UserApi.CreateUser`: %v\n %+v\n", err1, r1)
		}

		_, r2, err2 := apiClient.UserApi.CreateUser(proxyCtx).
			CreateUserRequest(user2).
			Execute()
		if err2 != nil {
			t.Errorf("Error when calling `UserApi.CreateUser`: %v\n %+v\n", err2, r2)
		}
	}()

	conf := clientcredentials.Config{
		ClientID:     username1,
		ClientSecret: "password",
		Scopes: []string{
			"socialapp.users.read",
			"socialapp.follower.create",
			"socialapp.follower.read",
			"socialapp.follower.delete",
		},
		TokenURL: ENDPOINT_OAUTH_TOKEN,
	}

	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)

	// user 1 follows user 2
	func() {

		if err != nil {
			t.Fatalf("Error getting oauth2 context: %v", err)
		}
		r, err := apiClient.UserApi.FollowUser(oauth2Ctx, username2, username1).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.FollowUser`: %v\n %+v\n", err, r)
		}
	}()

	// validate user 1 follows user 2
	func() {
		followers, r, err := apiClient.UserApi.GetUserFollowers(oauth2Ctx, username2).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.FollowUser`: %v\n %+v\n", err, r)
		}
		if len(followers) != 1 {
			t.Errorf("Expected 1 follower, got %d", len(followers))
		}
		if followers[0].Username != username1 {
			t.Errorf("Expected follower %s, got %s", username1, followers[0].Username)
		}
	}()

	// user 1 unfollows user 2
	func() {
		r, err := apiClient.UserApi.UnfollowUser(oauth2Ctx, username2, username1).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.FollowUser`: %v\n %+v\n", err, r)
		}
	}()

	// validate user 1 unfollows user 2
	func() {
		followers, r, err := apiClient.UserApi.GetUserFollowers(oauth2Ctx, username2).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.FollowUser`: %v\n %+v\n", err, r)
		}

		if len(followers) != 0 {
			t.Errorf("Expected 0 followers, got %d", len(followers))
		}
	}()
}

func TestGetExpectedFeed(t *testing.T) {
	// create two users
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)

	apiClient = client.NewAPIClient(configuration)

	username1 := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	email1 := fmt.Sprintf("Test-%d-1@social.com", time.Now().UnixNano())
	user1 := *client.NewCreateUserRequest(username1, "password", "FirstName_example", "LastName_example", email1) // User | Create a new user

	username2 := fmt.Sprintf("Test-%d2", time.Now().UnixNano())
	email2 := fmt.Sprintf("Test-%d-2@social.com", time.Now().UnixNano())
	user2 := *client.NewCreateUserRequest(username2, "secretPassword", "FirstName_example", "LastName_example", email2) // User | Create a new user

	// create users
	func() {
		_, r1, err1 := apiClient.UserApi.
			CreateUser(proxyCtx).
			CreateUserRequest(user1).
			Execute()
		if err1 != nil {
			t.Errorf("Error when calling `UserApi.CreateUser`: %v\n %+v\n", err1, r1)
		}

		_, r2, err2 := apiClient.UserApi.
			CreateUser(proxyCtx).
			CreateUserRequest(user2).
			Execute()
		if err2 != nil {
			t.Errorf("Error when calling `UserApi.CreateUser`: %v\n %+v\n", err2, r2)
		}
	}()

	conf := clientcredentials.Config{
		ClientID:     username1,
		ClientSecret: "password",
		Scopes: []string{
			"socialapp.users.read",
			"socialapp.follower.create",
			"socialapp.follower.read",
			"socialapp.follower.delete",
			"socialapp.comments.create",
			"socialapp.feed.read",
		},
		TokenURL: ENDPOINT_OAUTH_TOKEN,
	}

	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)
	if err != nil {
		t.Fatalf("Error getting oauth2 context: %v", err)
	}

	func() {
		r, err := apiClient.UserApi.FollowUser(
			oauth2Ctx,
			username2,
			username1).
			Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.FollowUser`: %v\n %+v\n", err, r)
		}
	}()

	// user 2 posts a comment
	func() {
		comment := *client.NewComment("Test comment", username2)
		_, r, err := apiClient.CommentApi.
			CreateComment(oauth2Ctx).
			Comment(comment).
			Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.PostComment`: %v\n %+v\n", err, r)
		}
	}()

	// validate feed in user 1's feed
	func() {
		feed, r, err := apiClient.CommentApi.
			GetUserFeed(oauth2Ctx, username1).
			Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.GetUserFeed`: %v\n %+v\n", err, r)
		}
		if len(feed) != 1 {
			t.Errorf("Expected 1 post in feed, got %d", len(feed))
		}
		if feed[0].Username != username2 {
			t.Errorf("Expected post from %s, got %s", username2, feed[0].Username)
		}
	}()

}

func TestGetAccessToken(t *testing.T) {
	// create two users
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)

	apiClient = client.NewAPIClient(configuration)

	username1 := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	password := fmt.Sprintf("Password-%d1", time.Now().UnixNano())
	createUsrReq := client.NewCreateUserRequest(username1, password, "FirstName_example", "LastName_example", username1)
	func() {
		_, _, err := apiClient.UserApi.CreateUser(proxyCtx).CreateUserRequest(*createUsrReq).Execute()
		if err != nil {
			t.Fatalf("Error creating user: %v", err)
		}
	}()
	scopes := []string{
		"socialapp.users.read",
		"socialapp.follower.create",
		"socialapp.follower.read",
		"socialapp.follower.delete",
		"socialapp.comments.create",
		"socialapp.feed.read",
	}
	conf := clientcredentials.Config{
		ClientID:     username1,
		ClientSecret: password,
		Scopes:       scopes,
		TokenURL:     ENDPOINT_OAUTH_TOKEN,
	}
	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)
	if err != nil {
		t.Fatalf("Error getting oauth2 context: %v", err)
	}

	token, res, err := apiClient.AuthenticationApi.GetAccessToken(oauth2Ctx).Execute()
	if err != nil {
		t.Errorf("Error when calling `AuthenticationApi.GetAccessToken`: %v", err)
	}
	// assert scopes are correct
	if res.Status != "200 OK" {
		t.Errorf("Expected status 200, got %s", res.Status)
	}

	if len(token.Scopes) != len(scopes) {
		t.Errorf("Expected %d scopes, got %d", len(scopes), len(token.Scopes))
		t.Log(cmp.Diff(scopes, token.Scopes))
	}
}

func TestRegisterUserFlow(t *testing.T) {
	// create two users
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)

	apiClient = client.NewAPIClient(configuration)

	username1 := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	password := fmt.Sprintf("Password-%d1", time.Now().UnixNano())
	createUsrReq := client.NewCreateUserRequest(username1, password, "FirstName_example", "LastName_example", username1)

	// create a user, no auth needed
	// POST /user
	// {user}
	_, res, err := apiClient.UserApi.CreateUser(proxyCtx).CreateUserRequest(*createUsrReq).Execute()
	if err != nil {
		t.Errorf("Error when calling `UserApi.CreateUser`: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 201, got %d", res.StatusCode)
	}

	scopes := []string{
		"socialapp.users.read",
	}
	conf := clientcredentials.Config{
		ClientID:     username1,
		ClientSecret: password,
		Scopes:       scopes,
		TokenURL:     ENDPOINT_OAUTH_TOKEN,
	}
	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)
	if err != nil {
		t.Fatalf("Error getting oauth2 context: %v", err)
	}

	// Get user by using oauath2 token
	func() {
		_, res, err := apiClient.UserApi.GetUserByUsername(oauth2Ctx, username1).Execute()
		if err != nil {
			t.Errorf("Error when calling `UserApi.GetUsers`: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status code 200, got %d", res.StatusCode)
		}
	}()

	// validate 401 if no auth is provided
	func() {
		user, res, err := apiClient.UserApi.GetUserByUsername(proxyCtx, username1).Execute()
		if err == nil {
			t.Errorf("Error when calling `UserApi.GetUsers`: %v", err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status code 401, got %d", res.StatusCode)
		}
		if user != nil {
			t.Errorf("Expected nil user, got %v", user)
		}
	}()
}

func TestChangePassword(t *testing.T) {
	// create two users
	os.Setenv("HTTP_PROXY", "http://localhost:9091")
	os.Setenv("HTTPS_PROXY", "http://localhost:9091")

	configuration := client.NewConfiguration()
	proxyStr := "http://localhost:9091"
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		log.Println(err)
	}

	// Setup http client with proxy to capture traffic
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	configuration.HTTPClient = httpClient
	proxyCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	proxyCtx = context.WithValue(proxyCtx, client.ContextServerIndex, CONTEXT_SERVER)
	scopes := []string{
		"socialapp.users.read",
		"socialapp.users.update",
	}

	// openAPICtx := context.WithValue(oauth2Ctx, client.ContextServerIndex, CONTEXT_SERVER)
	apiClient = client.NewAPIClient(configuration)

	username := fmt.Sprintf("Test-%d1", time.Now().UnixNano())
	password := fmt.Sprintf("Password-%d1", time.Now().UnixNano())
	createUsrReq := client.NewCreateUserRequest(username, password, "FirstName_example", "LastName_example", username)

	// create a user, no auth needed
	_, res, err := apiClient.UserApi.CreateUser(proxyCtx).CreateUserRequest(*createUsrReq).Execute()
	if err != nil {
		t.Errorf("Error when calling `UserApi.CreateUser`: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 201, got %d", res.StatusCode)
	}

	conf := clientcredentials.Config{
		ClientID:     username,
		ClientSecret: password,
		Scopes:       scopes,
		TokenURL:     ENDPOINT_OAUTH_TOKEN,
	}
	oauth2Ctx, err := getOuath2Context(proxyCtx, conf)
	if err != nil {
		t.Fatalf("Error getting oauth2 context: %v", err)
	}

	newPassword := password + "new"
	func() {
		changePwdReq := client.NewChangePasswordRequest(password, newPassword)
		_, res, err := apiClient.UserApi.ChangePassword(oauth2Ctx).ChangePasswordRequest(*changePwdReq).Execute()
		if err != nil {
			t.Fatalf("Error when calling `UserApi.ChangePassword`: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected status code 200, got %d", res.StatusCode)
		}
	}()

	// attempt to get token with old password, expect 401
	func() {
		token, res, err := apiClient.AuthenticationApi.GetAccessToken(oauth2Ctx).Execute()
		if err == nil {
			t.Errorf("Error when calling `AuthenticationApi.GetAccessToken`: %v", err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status code 401, got %d", res.StatusCode)
		}
		if token != nil {
			t.Errorf("Expected nil user, got %v", token)
		}
	}()

	// attempt to get token with new password, expect 200
	func() {
		newPwdConf := clientcredentials.Config{
			ClientID:     username,
			ClientSecret: newPassword,
			Scopes:       scopes,
			TokenURL:     ENDPOINT_OAUTH_TOKEN,
		}
		newPwdOauth2Ctx, err := getOuath2Context(proxyCtx, newPwdConf)
		if err != nil {
			t.Fatalf("Error getting oauth2 context: %v", err)
		}
		token, res, err := apiClient.AuthenticationApi.GetAccessToken(newPwdOauth2Ctx).Execute()
		if err != nil {
			t.Errorf("Error when calling `AuthenticationApi.GetAccessToken`: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected status code 200, got %d", res.StatusCode)
		}
		if token == nil {
			t.Errorf("Expected token, got nil")
		}
	}()
}

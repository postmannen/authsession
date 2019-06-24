package authsession

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"crypto/rand"

	"github.com/gorilla/sessions"
)

//createRandomKey will create a random []byte with the size taken as input.
func createRandomKey(size int) ([]byte, error) {
	b := make([]byte, size)

	//rand.Read() will read random values from the crypto package,
	// and read them into the []byte b.
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

//Auth is used for the authentication handlers, and hold all the
// values needed for authentication.
type Auth struct {
	googleOauthConfig *oauth2.Config
	oauthStateString  string
	store             *sessions.CookieStore
}

//NewAuth will return *auth, with a prepared OauthConfig and CookieStore set.
// proto, is either http or https,
// host, is the name of your sever, like example.com or localhost or...,
// port, for example :8080,
// cookieStoreKey, is the secret key used for the cookie storage,
// clientIDKey, is the Client ID key found in the google developer console for your oauth app,
// clientSecret, is the client secret found in the google developer console for your oauth app.
func NewAuth(proto string, host string, port string, cookieStoreKey string, clientIDKey string, clientSecret string) *Auth {
	return &Auth{
		googleOauthConfig: newOauthConfig(proto, host, port, clientIDKey, clientSecret),
		store:             sessions.NewCookieStore([]byte(cookieStoreKey)),
	}
}

//Run will start the auth, which basically is to run the HandleFunc's needed.
func (a *Auth) Run() {
	http.HandleFunc("/login", a.login)
	http.HandleFunc("/logout", a.logout)
	http.HandleFunc("/callback", a.handleGoogleCallback)
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	//The idea here is to generate a new state string for each user
	// who choose to login to the page.
	// NB: There should be no reason to set this value to zero after
	// an authentication process is attemped, since the the only place
	// this value is used is in the //callback handler. All other places
	// where the tokenString might be needed after a user is logged in
	// should get it's value from the session token.
	stateStringRAW, err := createRandomKey(16)
	if err != nil {
		log.Println("error: failed to create state string: ", err)
	}

	a.oauthStateString = base64.URLEncoding.EncodeToString(stateStringRAW)

	// Authentication goes here
	// ...
	url := a.googleOauthConfig.AuthCodeURL(a.oauthStateString)
	//??? Will redirect to / if authentication fails
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

//logout will logout the user, and invalidate the session cookie
// by setting the 'authenticated' key to false.
func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	var err error
	session, err := a.store.Get(r, "cookie-name")
	if err != nil {
		log.Println("error: store.Get in /logout: ", err)
	}

	// Revoke users authentication
	session.Values["authenticated"] = false

	err = session.Save(r, w)
	if err != nil {
		log.Println("error: session.Save on /logout: ", err)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

//IsAuthenticated is a wrapper to put around handlers you want
// to protect with an authenticated user.
func (a *Auth) IsAuthenticated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.store.Get(r, "cookie-name")
		email, _ := session.Values["email"]
		log.Printf("\n--- Authenticated user accessing page is : %v ---\n", email)

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		h(w, r)
	}
}

//newOauthConfig will return a *oauth2.Config with callback url
// and ID & Secret from environment variables.
func newOauthConfig(proto string, host string, port string, clientIDKey string, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  proto + "://" + host + port + "/callback",
		ClientID:     clientIDKey,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint: google.Endpoint,
	}
}

//handleGoogleCallback is the handler used when google wants to tell if
// the authentication of the user was ok or not.
// If the authentication is ok, the token.Valid() is set to true, and
// we can then create a cookie with the value "authenticated" for the user.
// We can then check later if that value is present in the cookie to grant
// access to handlers.
func (a *Auth) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")

	token, err := a.googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Println("code exchange failed: ", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	fmt.Println("--- state : ", state)
	fmt.Println("--- code : ", code)

	if !token.Valid() {
		log.Println("error: token not valid in callback function. Token value = ", token.Valid())
		return
	}

	//Get information from Google about user logged in.
	rawUserInfo, err := a.getUserInfo(state, token)
	if err != nil {
		log.Println("error: getUserInfo failed: ", err)
	}

	userInfo := struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Picture       string `json:"picture"`
		FullName      string `json:"name"`
		FirstName     string `json:"given_name"`
		LastName      string `json:"family_name"`
	}{}

	if err := json.Unmarshal(rawUserInfo, &userInfo); err != nil {
		log.Println("error: marshall of the userInfo failed: ", err)
	}
	fmt.Printf("%#v\n", userInfo)

	//If all  checks above were ok, we know the the authentication went ok,
	// and we can create a session cookie to use from here.
	session, err := a.store.Get(r, "cookie-name")
	if err != nil {
		log.Println("error: store.Get in /login failed: ", err)
	}

	//set the session values to put into the cookie.
	session.Values["authenticated"] = true
	session.Values["id"] = userInfo.ID
	session.Values["fullname"] = userInfo.FullName
	session.Values["email"] = userInfo.Email
	session.Values["state"] = state

	//set token expire to 8 hours.
	session.Options = &sessions.Options{MaxAge: 60 * 60 * 8}
	err = session.Save(r, w)
	if err != nil {
		log.Println("error: session.Save on /login: ", err)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

}

//getUserInfo will get the information defined in 'scopes',
// and return the values as a []byte.
func (a *Auth) getUserInfo(state string, token *oauth2.Token) ([]byte, error) {
	if state != a.oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	fmt.Println("Token expire, ", token.Expiry)

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}

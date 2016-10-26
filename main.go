// Copy/paste from:
// http://skarlso.github.io/2016/06/12/google-signin-with-go/
// https://github.com/tstranex/u2f/blob/master/u2fdemo/main.go
//
// Note:
// Set up a stunnel for HTTPS termination (to match AppID)
// [test]
// client = no
// accept = 127.0.0.1:3483
// connect = 127.0.0.1:9090
// cert = /etc/ssl/certs/ssl-cert-snakeoil.pem 
// key = /etc/ssl/private/ssl-cert-snakeoil.key
//
// To test: visit https://127.0.0.1:3483/login?r=https://127.0.0.1:3483/login
// The r= is to allow for the first call to register to re-call the login
// service. When using in nginx r= should be the original URL the user tried
// to access.

package main

import (
  "crypto/rand"
  "encoding/base64"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "log"
  "os"
  "net/http"

  "github.com/gin-gonic/contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/tstranex/u2f"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/google"
)

// Credentials which stores google ids.
type Credentials struct {
  Cid   string `json:"cid"`
  Csecret string `json:"csecret"`
}

// User is a retrieved and authentiacted user.
type User struct {
  Sub string `json:"sub"`
  Name string `json:"name"`
  GivenName string `json:"given_name"`
  FamilyName string `json:"family_name"`
  Profile string `json:"profile"`
  Picture string `json:"picture"`
  Email string `json:"email"`
  EmailVerified string `json:"email_verified"`
  Gender string `json:"gender"`
}

// U2F Authentication request.
type AuthenticateRequest struct {
  SignRequests []u2f.SignRequest `json:"signRequests"`
}

var conf *oauth2.Config

const appID = "https://127.0.0.1:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registration []u2f.Registration
var counter uint32

func randToken() string {
  b := make([]byte, 32)
  rand.Read(b)
  return base64.StdEncoding.EncodeToString(b)
}

func newUserToken(user string) string {
  // TODO: Kind of silly token but for PoC it works
  return user
}

func validateUserToken(token string) bool {
  // TODO: All tokens are fine for the PoC
  return true
}

func init() {
  file, err := ioutil.ReadFile("./creds.json")
  if err != nil {
    log.Printf("File error: %v\n", err)
    os.Exit(1)
  }
  var cred Credentials
  json.Unmarshal(file, &cred)

  conf = &oauth2.Config{
    ClientID:   cred.Cid,
    ClientSecret: cred.Csecret,
    RedirectURL:  "https://127.0.0.1:3483/oauth2/callback",
    Scopes: []string{
      "https://www.googleapis.com/auth/userinfo.email",
    },
    Endpoint: google.Endpoint,
  }
}

func oauthCallbackHandler(c *gin.Context) {
  // Basic CSRF protection. Read more on
  // http://www.twobotechnologies.com/blog/2014/02/importance-of-state-in-oauth2.html
  session := sessions.Default(c)
  retrievedState := session.Get("state")
  if retrievedState != c.Query("state") {
    c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
    return
  }

  tok, err := conf.Exchange(oauth2.NoContext, c.Query("code"))
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, err)
    return
  }

  client := conf.Client(oauth2.NoContext, tok)
  email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, err)
    return
  }
  defer email.Body.Close()
  data, _ := ioutil.ReadAll(email.Body)
  var user User
  json.Unmarshal(data, &user)

  // Save authentication data to use after U2F flow is complete
  session.Set("user", user.Email)
  log.Printf("U2F started for %s", user.Email)
  session.Save()

  tmpl := "u2f-sign.tmpl"
  if registration == nil {
    tmpl = "u2f-registration.tmpl"
  }
  c.HTML(http.StatusOK, tmpl, gin.H{
    "name": user.Name,
  })
}

func loginHandler(c *gin.Context) {
  state := randToken()
  session := sessions.Default(c)
  session.Clear()
  session.Set("state", state)
  session.Set("redirect", c.Query("r"))
  session.Save()
  c.Redirect(http.StatusFound, conf.AuthCodeURL(state))
}

func u2fRegisterRequestHandler(c *gin.Context) {
  chal, err := u2f.NewChallenge(appID, trustedFacets)
  if err != nil {
    log.Printf("u2f.NewChallenge error: %v", err)
    c.String(http.StatusInternalServerError, "error")
    return
  }
  challenge = chal
  req := chal.RegisterRequest()

  log.Printf("u2fRegisterRequestHandler: %+v", req)
  c.JSON(http.StatusOK, req)
}

func u2fRegisterResponseHandler(c *gin.Context) {
  var regResp u2f.RegisterResponse
  if err := c.BindJSON(&regResp); err != nil {
    c.String(http.StatusBadRequest, "invalid response: %s", err.Error())
    return
  }

  if challenge == nil {
    c.String(http.StatusBadRequest, "challenge not found")
    return
  }

  reg, err := u2f.Register(regResp, *challenge, nil)
  if err != nil {
    log.Printf("u2f.Register error: %v", err)
    c.String(http.StatusInternalServerError, "error verifying response")
    return
  }

  registration = append(registration, *reg)
  counter = 0

  log.Printf("Registration success: %+v", reg)

  // Retry the authentication flow. It will fail again, but now the user is
  // already OAuth2 authenticated and we have a U2F registration.
  // We cannot simply refresh as the OAuth2 token is already used.
  session := sessions.Default(c)
  redirect := session.Get("redirect").(string)
  if redirect != "" {
    c.String(http.StatusOK, redirect)
  } else {
    c.String(http.StatusOK, "/success")
  }
}

func u2fSignRequestHandler(c *gin.Context) {
  if registration == nil {
    c.String(http.StatusBadRequest, "registration missing")
    return
  }

  chal, err := u2f.NewChallenge(appID, trustedFacets)
  if err != nil {
    log.Printf("u2f.NewChallenge error: %v", err)
    c.String(http.StatusInternalServerError, "registration missing")
    return
  }
  challenge = chal

  var req AuthenticateRequest
  for _, reg := range registration {
    sr := chal.SignRequest(reg)
    req.SignRequests = append(req.SignRequests, *sr)
  }

  log.Printf("authenitcateRequest: %+v", req)
  c.JSON(http.StatusOK, req)
}

func u2fSignResponseHandler(c *gin.Context) {
  var signResp u2f.SignResponse
  if err := c.BindJSON(&signResp); err != nil {
    c.String(http.StatusBadRequest, "invalid response: %s", err.Error())
    return
  }

  log.Printf("signResponse: %+v", signResp)

  if challenge == nil {
    c.String(http.StatusBadRequest, "challenge missing")
    return
  }
  if registration == nil {
    c.String(http.StatusBadRequest, "registration missing")
    return
  }

  var err error
  for _, reg := range registration {
    newCounter, err := reg.Authenticate(signResp, *challenge, counter)
    if err == nil {
      log.Printf("newCounter: %d", newCounter)
      counter = newCounter

      session := sessions.Default(c)
      user := session.Get("user").(string)

      session.Set("token", newUserToken(user))
      session.Save()

      log.Printf("User %s got token", user)

      // Success, return user to where they need to go
      redirect := session.Get("redirect").(string)
      if redirect != "" {
        c.String(http.StatusOK, redirect)
      } else {
        c.String(http.StatusOK, "/success")
      }
      return
    }
  }

  log.Printf("VerifySignResponse error: %v", err)
  c.String(http.StatusInternalServerError, "error verifying response")
}

func authHandler(c *gin.Context) {
  session := sessions.Default(c)
  if validateUserToken(session.Get("token").(string)) {
    c.String(http.StatusOK, "success")
  } else {
    c.String(http.StatusUnauthorized, "no token")
  }
}

func successHandler(c *gin.Context) {
  // Handler used if we are unable to figure out where to redirect the user
  // after authentication.
  c.HTML(http.StatusOK, "success-no-redirect.tmpl", gin.H{})
}

func main() {
  store := sessions.NewCookieStore([]byte("secret"))
  router := gin.Default()
  router.Use(sessions.Sessions("goquestsession", store))
  router.Static("/css", "./static/css")
  router.Static("/img", "./static/img")
  router.LoadHTMLGlob("templates/*")

  router.GET("/auth", authHandler)
  router.GET("/login", loginHandler)
  router.GET("/success", successHandler)
  router.GET("/oauth2/callback", oauthCallbackHandler)
  router.GET("/u2f/register/request", u2fRegisterRequestHandler)
  router.POST("/u2f/register/response", u2fRegisterResponseHandler)
  router.GET("/u2f/sign/request", u2fSignRequestHandler)
  router.POST("/u2f/sign/response", u2fSignResponseHandler)

  router.Run("127.0.0.1:9090")
}

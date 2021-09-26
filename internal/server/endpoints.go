package server

import (
	h "github.com/nuigcompsoc/api/internal/helpers"
	"github.com/nuigcompsoc/api/internal/services/oauth"
	"github.com/nuigcompsoc/api/internal/services/jwt"
	"github.com/nuigcompsoc/api/internal/services/ldap"
	log "github.com/sirupsen/logrus"
	"github.com/gin-gonic/gin"
	golangjwt "github.com/golang-jwt/jwt"
	"encoding/json"
	"errors"
	"strings"
	"net/url"
	"io/ioutil"
	"time"
	"regexp"
)

func (s *Server) RootGet(c *gin.Context) {
	h.RespondWithString(c, 200, "Homepage that won't be hosted by api")
}

/***************************
 *
 * === AUTH V1 ENDPOINTS ===
 *
 ***************************/

func (s *Server) AuthV1Get(c *gin.Context) {
	h.RespondWithString(c, 200, "Pong!")
}

func (s *Server) AuthV1RegisterPost(c *gin.Context) {
	var data map[string]interface{}
    body, _ := ioutil.ReadAll(c.Request.Body)
    err := json.Unmarshal(body, &data)
	if err != nil {
		h.RespondWithError(c, 400, errors.New("invalid json"))
		return
	}

	preferredUsername, ok := data["preferred_username"].(string)
	if !ok || preferredUsername == "" || len(preferredUsername) < 3 {
		h.RespondWithError(c, 400, errors.New("preferred_username is empty or less than 3 characters long"))
		return
	}
	memberID, ok := data["member_id"].(string)
	if !ok || len(memberID) == 0 {
		h.RespondWithError(c, 400, errors.New("member_id is empty"))
		return
	}

	// Check our ldap to see if their preferred username is already taken
	l := ldap.NewClient(&s.config)
	exists, ok := l.CheckUIDExists(preferredUsername)
	if !ok {
		h.RespondWithError(c, 500, errors.New("could not connect to LDAP"))
		return
	}

	// Check socs portal to see if they are in the society
	if !exists {
		res, ok := s.CheckSocietyPortalForMember(memberID)
		if !ok {
			h.RespondWithError(c, 500, errors.New("could not connect to society portal"))
			return
		}

		if res["MemberID"].(string) == memberID {
			claims := &golangjwt.MapClaims{
				"exp": time.Now().Add(10 * time.Minute).Unix(),
				"uid":   preferredUsername,
				"member_id": res["MemberID"].(string),
			}

			token, ok := jwt.GenerateAPIToken(&s.config, *claims)
			if !ok {
				h.RespondWithError(c, 500, errors.New("could not generate token"))
				return
			}
			link := s.config.FormHomeURL() + "/v1/auth/register/" + token
			ok = s.SendMail(s.config.SMTP.AccountAddress, []string{res["Email"].(string)}, "test, " + link)
			if !ok {
				h.RespondWithError(c, 500, errors.New("could not send email"))
				return 
			}
			h.RespondWithString(c, 200, "check your email within the next 10 minutes for a register link to complete the process")
			return
		} else {
			// user not in society, tell them to
			h.RespondWithString(c, 400, "register on yourspace")
			return
		}
	} else {
		// uid exists, choose another username
		h.RespondWithString(c, 400, "preferred_username is already taken, try again")
		return
	}
}

func (s *Server) AuthV1RegisterVerifyGet(c *gin.Context) {
	tokenString := c.Param("token")
	if tokenString == "" {
		h.RedirectWithError(c, errors.New("expected path parameter token"))
		return
	}

	token, ok := jwt.VerifyToken(&s.config, tokenString)
	if !ok {
		h.RedirectWithError(c, errors.New("token is invalid"))
		return
	}

	uid, ok := jwt.ExtractClaims(token)["uid"].(string)
	memberID, ok := jwt.ExtractClaims(token)["member_id"].(string)
	if !ok {
		h.RedirectWithError(c, errors.New("token is invalid for this route"))
		return
	}

	info, ok := s.CheckSocietyPortalForMember(memberID)
	if !ok {
		h.RedirectWithError(c, errors.New("cannot connect to society portal"))
		return
	}
	l := ldap.NewClient(&s.config)
	ok = l.RegisterUser(uid, "aaabbbccc", info)
	if !ok {
		h.RedirectWithError(c, errors.New("could not register you"))
		return
	}

	claims := &golangjwt.MapClaims{
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"uid": uid,
	}
	tokenString, ok = jwt.GenerateAPIToken(&s.config, *claims)
	if !ok {
		h.RedirectWithError(c, errors.New("could not generate token"))
		return
	}
	h.RedirectWithToken(c, tokenString)
}

func (s *Server) AuthV1OpenIDGet(c *gin.Context) {
	link := s.config.CompSocSSO.AuthURL + "?"
	params := url.Values{}
	params.Add("redirect_uri", s.config.FormHomeURL() + "/v1/auth/openid/callback")
	params.Add("response_type", "code")
	params.Add("client_id", s.config.CompSocSSO.ClientID)
	c.Header("Location", link + params.Encode())
	c.Status(308)
}

func (s *Server) AuthV1GoogleGet(c *gin.Context) {
	link := s.config.GoogleSSO.AuthURL + "?"
	params := url.Values{}
	params.Add("redirect_uri", s.config.FormHomeURL() + "/v1/auth/google/callback")
	params.Add("prompt", "consent")
	params.Add("response_type", "code")
	params.Add("client_id", s.config.GoogleSSO.ClientID)
	params.Add("scope", s.config.GoogleSSO.Scope)
	params.Add("access_type", "offline")
	c.Header("Location", link + params.Encode())
	c.Status(308)
}

func (s *Server) AuthV1OpenIDCallbackGet(c *gin.Context) {
	code, ok := c.GetQuery("code")
	if !ok || code == "" {
		h.RespondWithError(c, 400, errors.New("expected query: code"))
		return
	}

	idToken, ok := oauth.GetOpenIDIDToken(code, s.config)
	if !ok {
		h.RedirectWithError(c, errors.New("could not resolve keycloak api"))
		return
	}

	idClaims, ok := jwt.ExtractUnverifiedTokenPayload(idToken)
	if !ok {
		h.RedirectWithError(c, errors.New("could not extract claims from token"))
		return
	}

	claims := &golangjwt.MapClaims{
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"uid":   idClaims["preferred_username"].(string),
	}
	token, ok := jwt.GenerateAPIToken(&s.config, *claims)
	if !ok {
		h.RedirectWithError(c, errors.New("could not generate token"))
		return
	}

	h.RespondWithToken(c, token)
}

func (s *Server) AuthV1GoogleCallbackGet(c *gin.Context) {
	code, ok := c.GetQuery("code")
	if !ok || code == "" {
		h.RespondWithError(c, 400, errors.New("expected query: code"))
		return
	}

	idToken, ok := oauth.GetGoogleIDToken(code, s.config)
	if !ok {
		h.RedirectWithError(c, errors.New("could not resolve google api"))
		return
	}

	claims, ok := jwt.ExtractUnverifiedTokenPayload(idToken)
	if !ok {
		h.RedirectWithError(c, errors.New("could not extract claims from token"))
		return
	}

	l := ldap.NewClient(&s.config)
	uid := strings.Split(claims["email"].(string), "@")[0]
	if exists, ok := l.CheckUIDExists(uid); !ok {
		h.RedirectWithError(c, errors.New("server error"))
		return
	} else if !exists {
		if ok = l.RegisterSociety(claims); !ok {
			h.RedirectWithError(c, errors.New("could not register, please contact us"))
			return
		}
	}

	newClaims := &golangjwt.MapClaims{
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"uid": uid,
	}
	token, ok := jwt.GenerateAPIToken(&s.config, *newClaims)
	if !ok {
		h.RedirectWithError(c, errors.New("could not generate token"))
		return
	}

	h.RespondWithToken(c, token)
}

/***************************
 *
 * == GROUPS V1 ENDPOINTS ==
 *
 **************************/

func (s *Server) GroupsV1Get(c *gin.Context) {
	l := ldap.NewClient(&s.config)
	groups, ok := l.GetAllGroups()
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	}
	h.RespondWithJSON(c, 200, groups)
}

func (s *Server) GroupsV1NameGet(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}

	l := ldap.NewClient(&s.config)
	members, ok := l.GetGroup(name)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (len(members) < 1) {
		h.RespondWithString(c, 200, "group does not exist")
		return
	}
	h.RespondWithJSON(c, 200, members)
}

/***************************
 *
 * === USER V1 ENDPOINTS ===
 *
 ***************************/

func (s *Server) UsersV1Get(c *gin.Context) {
	l := ldap.NewClient(&s.config)
	users, ok := l.GetUsers()
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (len(users) < 1) {
		h.RespondWithString(c, 200, "user does not exist")
		return
	}
	h.RespondWithJSON(c, 200, users)
}

func (s *Server) UsersV1NameGet(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}

	l := ldap.NewClient(&s.config)
	user, ok := l.GetUser(name)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (user == nil) {
		h.RespondWithString(c, 200, "user does not exist")
		return
	}
	h.RespondWithJSON(c, 200, user)
}

func (s *Server) UsersV1NamePatch(c *gin.Context) {
	token, _ := c.Get("token")
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}

	var data map[string]interface{}
    body, _ := ioutil.ReadAll(c.Request.Body)
    err := json.Unmarshal(body, &data)
	if err != nil {
		h.RespondWithError(c, 400, errors.New("invalid json"))
		return
	}

	uid, _ := token.(*golangjwt.Token).Claims.(golangjwt.MapClaims)["uid"].(string)
	firstName, _ := data["first_name"].(string)
	lastName, _ := data["last_name"].(string)
	mail, _ := data["mail"].(string)

	isAlpha := regexp.MustCompile(`^[A-Za-z  *]+$`).MatchString
	isMail := regexp.MustCompile(`^\S+@\S+\.\S+$`).MatchString
	if firstName == "" || !isAlpha(firstName) {
		h.RespondWithError(c, 400, errors.New("first name is invalid"))
		return
	}
	if lastName == "" || !isAlpha(lastName) {
		h.RespondWithError(c, 400, errors.New("last name is invalid"))
		return
	}
	if mail == "" || !isMail(mail) {
		h.RespondWithError(c, 400, errors.New("mail is invalid"))
		return
	}

	l := ldap.NewClient(&s.config)
	ok := l.ModifyUser(uid, firstName, lastName, mail)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	}

	h.Respond(c, 204)
}

func (s *Server) UsersV1NameDelete(c *gin.Context) {
	token, _ := c.Get("token")
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}

	l := ldap.NewClient(&s.config)

	// If an admin, just allow them to delete it, else email the user asking for confirmation
	if IsAdmin(token.(*golangjwt.Token)) {
		if name == token.(*golangjwt.Token).Claims.(golangjwt.MapClaims)["uid"].(string) {
			h.RespondWithError(c, 400, errors.New("can not delete yourself"))
			return
		}
		ok := l.DeleteUser(name)
		if !ok {
			h.RespondWithError(c, 500, errors.New("could not delete user"))
			return
		}
		h.Respond(c, 204)
		return
	}
	
	claims := &golangjwt.MapClaims{
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"uid": name,
	}

	tokenString, ok := jwt.GenerateAPIToken(&s.config, *claims)
	if !ok {
		h.RespondWithError(c, 500, errors.New("could not generate token"))
		return
	}
	user, ok := l.GetUser(name)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (user == nil) {
		h.RespondWithError(c, 500, errors.New("user does not exist"))
		return
	}
	link := s.config.FormHomeURL() + "/v1/users/" + name + "/" + tokenString
	ok = s.SendMail(s.config.SMTP.AccountAddress, user.Mail, "test, " + link)
	if !ok {
		h.RespondWithError(c, 500, errors.New("could not send email"))
		return 
	}
	h.RespondWithString(c, 200, "check your email within the next 10 minutes for a link to complete the process")
}

func (s *Server) UsersV1NameVerifyGet(c *gin.Context) {
	tokenString := c.Param("token")
	if tokenString == "" {
		h.RedirectWithError(c, errors.New("expected paramater: token"))
		return
	}
	token, ok := jwt.VerifyToken(&s.config, tokenString)
	if !ok {
		h.RedirectWithError(c, errors.New("token is invalid"))
		return
	}

	// tokens should always have uid, no need to verify
	uid, _ := jwt.ExtractClaims(token)["uid"].(string)

	l := ldap.NewClient(&s.config)
	ok = l.DeleteUser(uid)
	if !ok {
		h.RedirectWithError(c, errors.New("server error"))
		return
	}

	log.WithFields(log.Fields{
		"message": "successfully deleted user",
		"uid": uid,
	}).Info("ldap")
	h.RedirectWithString(c, "successfully deleted your account")
}

/***************************
 *
 * = SOCIETY V1 ENDPOINTS =
 *
 ***************************/

/*
 * An admin can request a list of all societies
 */
 func (s *Server) SocietiesV1Get(c *gin.Context) {
	l := ldap.NewClient(&s.config)
	societies, ok := l.GetSocieties()
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (len(societies) < 1) {
		h.RespondWithString(c, 200, "society does not exist")
		return
	}
	h.RespondWithJSON(c, 200, societies)
}

/*
 * The society can request it's profile information
 */
func (s *Server) SocietiesV1NameGet(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}

	l := ldap.NewClient(&s.config)
	society, ok := l.GetSociety(name)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (society == nil) {
		h.RespondWithString(c, 200, "society does not exist")
		return
	}
	h.RespondWithJSON(c, 200, society)
}

/*
 * If this route is enacted by an admin then the society will be deleted
 * along with all containers and data, else it will let the admins know
 * that the society has interest in being deleted.
 */
func (s *Server) SocietiesV1NameDelete(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		h.RespondWithError(c, 400, errors.New("expected paramater: name"))
		return
	}
	
	claims := &golangjwt.MapClaims{
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"uid": name,
	}

	tokenString, ok := jwt.GenerateAPIToken(&s.config, *claims)
	if !ok {
		h.RespondWithError(c, 500, errors.New("could not generate token"))
		return
	}
	l := ldap.NewClient(&s.config)
	society, ok := l.GetUser(name)
	if !ok {
		h.RespondWithError(c, 500, errors.New("server error"))
		return
	} else if (society == nil) {
		h.RespondWithError(c, 500, errors.New("society does not exist"))
		return
	}
	link := s.config.FormHomeURL() + "/v1/societies/" + name + "/" + tokenString
	ok = s.SendMail(s.config.SMTP.AccountAddress, society.Mail, "test, " + link)
	if !ok {
		h.RespondWithError(c, 500, errors.New("could not send email"))
		return 
	}
	h.RespondWithString(c, 200, "check your email within the next 10 minutes for a link to complete the process")
}

func (s *Server) SocietiesV1NameVerifyGet(c *gin.Context) {
	tokenString := c.Param("token")
	if tokenString == "" {
		h.RedirectWithError(c, errors.New("expected paramater: token"))
		return
	}
	token, ok := jwt.VerifyToken(&s.config, tokenString)
	if !ok {
		h.RedirectWithError(c, errors.New("token is invalid"))
		return
	}

	// tokens should always have uid, no need to verify
	uid, _ := jwt.ExtractClaims(token)["uid"].(string)

	l := ldap.NewClient(&s.config)
	ok = l.DeleteSociety(uid)
	if !ok {
		h.RedirectWithError(c, errors.New("server error"))
		return
	}

	log.WithFields(log.Fields{
		"message": "successfully deleted society",
		"uid": uid,
	}).Info("ldap")
	h.RedirectWithString(c, "successfully deleted your account")
}

/***************************
 *
 * === MISC V1 ENDPOINTS ===
 *
 ***************************/

 func (s *Server) MiscV1BrewGet(c *gin.Context) {
	h.RespondWithError(c, 418, errors.New("I refuse to brew coffee because I am, permanently, a teapot."))
	return
}

func (s *Server) MiscV1PingGet(c *gin.Context) {
	h.RespondWithString(c, 200, "Pong!")
	return
}
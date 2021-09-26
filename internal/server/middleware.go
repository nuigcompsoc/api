package server

import (
	"github.com/gin-gonic/gin"
	"github.com/nuigcompsoc/api/internal/services/jwt"
	golangjwt "github.com/golang-jwt/jwt"
	h "github.com/nuigcompsoc/api/internal/helpers"
	log "github.com/sirupsen/logrus"
	"time"
	"errors"
)

/* 
 * Does any random things to the context we want done before reaching the endpoint func
 */
func (s *Server) MiscMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.config.HTTP.Secure {
			c.Request.URL.Scheme = "https"
		} else {
			c.Request.URL.Scheme = "http"
		}
		c.Next()
	}
}

/*
 * This middleware logs primarily the request path, method, response status and completion latency
 * If the user sends up a token, we try to validate it and log it's attributes and add it to the context
 */
func (s *Server) LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		logFields := log.Fields{
			"method": c.Request.Method,
			"path": c.Request.URL.Path,
			"ip": c.ClientIP(),
		}

		tokenString := jwt.ExtractToken(c.Request)
		if tokenString != "" {
			token, ok := jwt.VerifyToken(&s.config, tokenString)
			if ok {
				c.Set("token", token)
				uid, _ := token.Claims.(golangjwt.MapClaims)["uid"].(string)
				isAdmin, _ := token.Claims.(golangjwt.MapClaims)["is_admin"].(bool)
				isCommittee, _ := token.Claims.(golangjwt.MapClaims)["is_committee"].(bool)
				logFields["user"] = map[string]interface{} {
					"uid": uid,
					"is_admin": isAdmin,
					"is_committee": isCommittee,
				}
			}
		}

		c.Next()

		logFields["latency_ns"] = time.Since(start).Nanoseconds()
		logFields["status"] = c.Writer.Status()
		log.WithFields(logFields).Info("request")
	}
}

/*
 * This middleware prints a panic in JSON to the log and redirects
 * the user to an error page with a get parameter containing the error message
 */
func RecoveryMiddlware(c *gin.Context, recovered interface{}) {
	message, ok := recovered.(string)
	if !ok {
		h.RedirectWithError(c, errors.New("unknown error"))
		return
	}
	h.RedirectWithError(c, errors.New(message))
	return
}

/*
 * Checks that user is either using their own username as a path
 * parameter or is using 'self'. It also checks if they're an 
 * admin who can specify any user via the path parameter.
 * As is probably apparent, the user must be authenticated
 * for us to be able to tell what self is or if they own the
 * username they specify.
 */
func IsMyUsernameOrSelfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tmp, ok := c.Get("token")
		if !ok {
			h.RespondWithError(c, 401, errors.New("valid token required"))
			return
		}
		token := tmp.(*golangjwt.Token)

		if IsMyUsernameOrSelf(token, c.Param("name")) {
			c.Next()
			return
		}
		h.RespondWithError(c, 403, errors.New("name specified is not your own"))
	}
}

func IsMyUsernameOrSelf(token *golangjwt.Token, usernameParameter string) bool {
	return usernameParameter == jwt.ExtractClaims(token)["uid"] || IsAdmin(token)
}

/*
 * Checks the user is sending up a bearer token which is not
 * expired and valid.
 */
func IsAuthenticatedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, ok := c.Get("token")
		if !ok {
			h.RespondWithError(c, 401, errors.New("valid token required"))
			return
		}
		c.Next()
	}
}

func IsAuthenticated(token *golangjwt.Token) bool {
	return token.Valid
}

/*
 * Checks the user is on committee so they can access this route.
 */
 func IsCommitteeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tmp, ok := c.Get("token")
		if !ok {
			h.RespondWithError(c, 401, errors.New("valid token required"))
			return
		}
		token := tmp.(*golangjwt.Token)

		if IsCommittee(token) {
			c.Next()
			return
		}
		h.RespondWithError(c, 403, errors.New("committee only route"))
	}
}

func IsCommittee(token *golangjwt.Token) bool {
	return token.Claims.(golangjwt.MapClaims)["is_committee"].(bool) || IsAdmin(token)
}

/*
 * Checks the user is an admin so they can access this route.
 */
func IsAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tmp, ok := c.Get("token")
		if !ok {
			h.RespondWithError(c, 401, errors.New("token required"))
			return
		}
		token := tmp.(*golangjwt.Token)

		if IsAdmin(token) {
			c.Next()
			return
		}
		h.RespondWithError(c, 403, errors.New("admin only route"))
	}
}

func IsAdmin(token *golangjwt.Token) bool {
	return token.Claims.(golangjwt.MapClaims)["is_admin"].(bool)
}
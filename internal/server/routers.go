package server

import (
	"github.com/gin-gonic/gin"
)

// Returns the routes associated with /v1 
func (s *Server) v1Router(r *gin.RouterGroup) {

	r.Use(s.MiscMiddleware())
	r.Use(s.LoggingMiddleware())
	r.GET("/", s.RootGet)
	r.GET("ping", s.MiscV1PingGet)
	r.GET("brew", s.MiscV1BrewGet)
	r.GET("auth", s.AuthV1Get)
	r.GET("groups", s.GroupsV1Get)

	// ROOT route only committee
	rCommittee := r.Group("/", IsCommitteeMiddleware())
	rCommittee.GET("societies", s.SocietiesV1Get)
	rCommittee.GET("users", s.UsersV1Get)
	
	// AUTH route
	a := r.Group("/auth")
	a.POST("register", s.AuthV1RegisterPost)
	a.GET("register/:token", s.AuthV1RegisterVerifyGet)
	a.GET("openid", s.AuthV1OpenIDGet)
	a.GET("google", s.AuthV1GoogleGet)
	a.GET("openid/callback", s.AuthV1OpenIDCallbackGet)
	a.GET("google/callback", s.AuthV1GoogleCallbackGet)

	// SOCIETY route
	soc := r.Group("/societies")
	socAuth := r.Group("/societies", IsMyUsernameOrSelfMiddleware())
	socAuth.GET(":name", s.SocietiesV1NameGet)
	socAuth.DELETE(":name", s.SocietiesV1NameDelete)
	soc.GET(":name/:token", s.SocietiesV1NameVerifyGet)

	// USER route
	u := r.Group("/users")
	uAuth := r.Group("/users", IsMyUsernameOrSelfMiddleware())
	uAuth.GET(":name", s.UsersV1NameGet)
	uAuth.PATCH(":name", s.UsersV1NamePatch)
	uAuth.DELETE(":name", s.UsersV1NameDelete)
	u.GET(":name/:token", s.UsersV1NameVerifyGet)

	// GROUPS route
	g := r.Group("/groups")
	g.GET(":name", s.GroupsV1NameGet)
	
	/*
	 * ADMIN route
	 * Some actions we want users to be able to express interest
	 * in but not execute themselves, such as deleteing a society
	 * account or creating machines, these actions must be
	 * reviewed/followed up with. This route allows for admins
	 * to access the actual route to create machines/delete data.
	 */
	//admin := r.Group("/admin", IsAdminMiddleware())
	//admin.DELETE("society/:name")
}

// SetupRouter function will perform all route operations
func SetupRouter() *gin.Engine {

	// We are now relying on our own logging middleware to log all paths accessed to stdout
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.CustomRecovery(RecoveryMiddlware))

	r.Use(func(c *gin.Context) {
		// add header Access-Control-Allow-Origin
		c.Writer.Header().Set("Content-Type", "application/json")
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, UPDATE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, AuthV1orization, X-Max")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
		} else {
			c.Next()
		}
	})
	
	return r
}
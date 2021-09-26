package helpers

import (
	"github.com/gin-gonic/gin"
	"encoding/json"
	"time"
	"net/http"
)

//Respind with status
func Respond(c *gin.Context, code int) {
	c.Status(code)
}

//Respond returns basic status and message
func RespondWithString(c *gin.Context, code int, data string) {
	c.JSON(code, gin.H{"status": code, "data": data})
}

//Respond returns status and json
func RespondWithJSON(c *gin.Context, code int, data interface{}) {
	c.JSON(code, gin.H{"status": code, "data": data})
}

//Respond with error, aborts rest of request
func RespondWithError(c *gin.Context, code int, data error) {
	c.AbortWithStatusJSON(code, gin.H{"status": code, "data": data.Error()})
}

func RespondWithToken(c *gin.Context, token string) {
	c.Header("Set-Cookie", "data=" + token)
	c.SetCookie(c.Request.Host, token, int((24 * time.Hour).Seconds()), "/", c.Request.Host, false, true)
	c.Redirect(http.StatusTemporaryRedirect, c.Request.URL.Scheme + "://" + c.Request.Host)
}

func RedirectWithToken(c *gin.Context, token string) {
	c.Header("Set-Cookie", "data=" + token)
	c.SetCookie(c.Request.Host, token, int((24 * time.Hour).Seconds()), "/", c.Request.Host, false, true)
	c.Redirect(http.StatusTemporaryRedirect, c.Request.URL.Scheme + "://" + c.Request.Host)
}

func RedirectWithString(c *gin.Context, message string) {
	c.Redirect(http.StatusTemporaryRedirect, c.Request.URL.Scheme + "://" + c.Request.Host + "?message=" + message)
}

func RedirectWithError(c *gin.Context, err error) {
	c.Redirect(http.StatusTemporaryRedirect, c.Request.URL.Scheme + "://" + c.Request.Host + "?error=" + err.Error())
}

func StringToJSON(s string) map[string]interface{} {
	var sJSON map[string]interface{}
	json.Unmarshal([]byte(s), &sJSON)
	return sJSON
}
package oauth

import (
	"github.com/nuigcompsoc/api/internal/utils"
	"github.com/nuigcompsoc/api/internal/config"
	log "github.com/sirupsen/logrus"
	"net/url"
)

func GetGoogleIDToken(code string, c config.Config) (string, bool) {
	link := c.GoogleSSO.TokenURL + "?"
	params := url.Values{}
	params.Add("redirect_uri", c.FormHomeURL() + "/v1/auth/google/callback")
	params.Add("client_id", c.GoogleSSO.ClientID)
	params.Add("client_secret", c.GoogleSSO.ClientSecret)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	
	resp, ok := utils.PostUrlEncoded(link, &params)
	if !ok {
		return "", false
	}
	
	idToken, ok := resp["id_token"].(string)
	if !ok || idToken == "" {
		log.WithFields(log.Fields{
			"message": "could not find id_token in response from google",
			"body": resp,
		}).Error("http-utils")
        return "", false
	}

	return idToken, true
}

func GetOpenIDIDToken(code string, c config.Config) (string, bool) {
	link := c.CompSocSSO.TokenURL + "?"
	params := url.Values{}
	params.Add("redirect_uri", c.FormHomeURL() + "/v1/auth/openid/callback")
	params.Add("client_id", c.CompSocSSO.ClientID)
	params.Add("client_secret", c.CompSocSSO.ClientSecret)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	
	resp, ok := utils.PostUrlEncoded(link, &params)
	if !ok {
		return "", false
	}

	accessToken, ok := resp["access_token"].(string)
	if !ok || accessToken == "" {
		log.WithFields(log.Fields{
			"message": "could not find access_token in response from keycloak",
			"body": resp,
		}).Error("http-utils")
        return "", false
	}

	return accessToken, true
}
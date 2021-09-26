package jwt

import (
	"crypto/x509"
	"crypto/rsa"
    "encoding/pem"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
    "strings"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
    utils "github.com/nuigcompsoc/api/internal/utils"
    jwt "github.com/golang-jwt/jwt"
	ldap "github.com/nuigcompsoc/api/internal/services/ldap"
	"github.com/nuigcompsoc/api/internal/config"
)

// Extracts the Bearer Token from a HTTP request
func ExtractToken(r *http.Request) string {
    bearerToken := r.Header.Get("Authorization")
	// Normally Authorization the_token_xxx
    strArr := strings.Split(bearerToken, " ")
    if len(strArr) == 2 {
        return strArr[1]
    }
    return ""
}

func LoadRSAKey(c *config.Config) (*rsa.PrivateKey, bool) {
	priv, err := ioutil.ReadFile(c.JWT.PrivateKeyPath)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not read in private key",
			"error": err.Error(),
		}).Error("jwt")
		return nil, false
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		log.WithFields(log.Fields{
			"message": "rsa private key is of the wrong type",
			"error": err.Error(),
		}).Error("jwt")
		return nil, false
	}

	if c.JWT.PrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(c.JWT.PrivateKeyPassword))
	} else {
		privPemBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		log.WithFields(log.Fields{
			"message": "unable to parse RSA private key",
			"error": err.Error(),
		}).Error("jwt")
		return nil, false
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.WithFields(log.Fields{
			"message": "unable to parse RSA private key",
		}).Error("jwt")
		return nil, false
	}
	return privateKey, true
}

func GenerateAPIToken(c *config.Config, claims jwt.MapClaims) (string, bool) {
	claims["aud"] = c.FormHomeURL()
	claims["iss"] = c.FormHomeURL()
	l := ldap.NewClient(c)
	isAdmin, ok := l.CheckUserIsAdmin(claims["uid"].(string))
	isCommittee, ok := l.CheckUserIsCommittee(claims["uid"].(string))
	if !ok {
		log.WithFields(log.Fields{
			"message": "error generating token because of ldap group check",
			"claims": claims,
		}).Error("jwt")
		return "", false
	}

	claims["is_admin"] = isAdmin
	claims["is_committee"] = isCommittee

	privKey, ok := LoadRSAKey(c)
	if !ok {
		return "", false
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "error generating token because golang-jwt signing issue",
			"claims": claims,
			"error": err.Error(),
		}).Error("jwt")
		return "", false
	}
	return tokenString, true
}

// Verifies that the token is authorised and not expired
func VerifyToken(c *config.Config, tokenString string) (*jwt.Token, bool) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		var publicKey string
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("couldn't get claims from token")
		}

		switch (claims["iss"]) {
		case "https://accounts.google.com":
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				log.WithFields(log.Fields{
					"message": "expecting JWT header to have string kid",
				}).Info("jwt")
				return nil, errors.New("expecting JWT header to have string kid")
			}

			json, ok := utils.GetJson("https://www.googleapis.com/oauth2/v1/certs")
			if !ok {
				return nil, errors.New("error getting json public key from google api")
			}
			publicKey = json[keyID].(string)
		case "https://sso.compsoc.ie/auth/realms/base":
			json, ok := utils.GetJson("https://sso.compsoc.ie/auth/realms/base")
			if !ok {
				return nil, errors.New("error getting json public key from keycloak")
			}
			publicKey = json["public_key"].(string)
		case c.FormHomeURL():
			privateKey, ok := LoadRSAKey(c)
			if !ok {
				return nil, errors.New("could not load private key for jwt")
			}
		
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				return nil, errors.New("could not marshal dashboard public key")
			}
			pubKeyPem := pem.EncodeToMemory(
					&pem.Block{
							Type:  "RSA PUBLIC KEY",
							Bytes: pubKeyBytes,
					},
			)

			publicKey = string(pubKeyPem)
		}

		strings.TrimSuffix(publicKey, "\n")
		block, _ := pem.Decode([]byte(publicKey))
        if block == nil {
			return nil, errors.New("failed to parse PEM block containing the public key")
        }

		if claims["iss"] == "https://accounts.google.com" {
			cert, _ := x509.ParseCertificate(block.Bytes)
			rsaPub := cert.PublicKey
			return rsaPub, nil
		}

		rsaPub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("failed to parse DER encoded public key")
		}
		return rsaPub, nil
	})

	// User sent a bogus token
	if err != nil {
		log.WithFields(log.Fields{
			"message": "issue verifying token",
			"error": err.Error(),
		}).Info("jwt")
		return nil, false
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, true
	}
	log.WithFields(log.Fields{
		"message": "could not cast token claims to MapClaims",
	}).Error("jwt")
	return nil, false
}

/*
 * This should only be used for grabbing information from a trusted token
 * as this does not verify the token.
 */
 func ExtractUnverifiedTokenPayload(tokenString string) (map[string]interface{}, bool) {
	tokenStringArr := strings.Split(tokenString, ".")
	// RawStdEncoding as this JWT does not contain padding at the end of the string
	tokenStringDecoded, _ := b64.RawStdEncoding.DecodeString(tokenStringArr[1])

	var token map[string]interface{}
	err := json.Unmarshal(tokenStringDecoded, &token)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not unmarshal tokenString into map",
			"token": err.Error(),
		}).Error("jwt")
		return nil, false
	}
	return token, true
}

func ExtractUnverifiedTokenHeader(tokenString string) (map[string]interface{}, bool) {
	tokenStringArr := strings.Split(tokenString, ".")
	// RawStdEncoding as this JWT does not contain padding at the end of the string
	tokenStringDecoded, _ := b64.RawStdEncoding.DecodeString(tokenStringArr[0])

	var token map[string]interface{}
	err := json.Unmarshal(tokenStringDecoded, &token)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not unmarshal tokenString into map",
			"token": err.Error(),
		}).Error("jwt")
		return nil, false
	}
	return token, true
}

func ExtractClaims(token *jwt.Token) (map[string]interface{}) {
	claims, _ := token.Claims.(jwt.MapClaims)
	return claims
}
package server

import (
	"encoding/base64"
	"net/url"
	"net/smtp"
	"github.com/nuigcompsoc/api/internal/utils"
	log "github.com/sirupsen/logrus"
)

func (s *Server) CheckSocietyPortalForMember(memberID string) (map[string]interface{}, bool) {
	link := s.config.SocsPortal.URL + "?"
	params := url.Values{}
	params.Add("method", base64.StdEncoding.EncodeToString([]byte(s.config.SocsPortal.SingleMethod)))
	params.Add("username", base64.StdEncoding.EncodeToString([]byte(s.config.SocsPortal.Username)))
	params.Add("password", base64.StdEncoding.EncodeToString([]byte(s.config.SocsPortal.Password)))
	params.Add("searchByOption", base64.StdEncoding.EncodeToString([]byte(s.config.SocsPortal.SearchByOption)))
	params.Add("searchValue", base64.StdEncoding.EncodeToString([]byte(memberID)))
	params.Add("encodeOutput", base64.StdEncoding.EncodeToString([]byte("true")))
	res, ok := utils.PostUrlEncoded(link, &params)
	if !ok {
		return nil, false
	}
	log.WithFields(log.Fields{
		"message": "successfully pinged societies portal membership API",
		"memberID": memberID,
	}).Info("mail")
	return res["Response"].(map[string]interface{})["data"].(map[string]interface{}), true
}

func (s *Server) SendMail(fromAddress string, toAddresses []string, message string) (bool) {
	auth := smtp.PlainAuth("", s.config.SMTP.Username, s.config.SMTP.Password, s.config.SMTP.Host)
	err := smtp.SendMail(s.config.SMTP.Host + ":" + s.config.SMTP.Port, auth, fromAddress, toAddresses, []byte(message))
	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not send mail",
			"email": toAddresses,
			"error": err.Error(),
		}).Error("mail")
		return false
	}

	log.WithFields(log.Fields{
		"message": "successfully sent mail",
		"sender": fromAddress,
		"recipient": toAddresses,
	}).Info("mail")
	return true
}
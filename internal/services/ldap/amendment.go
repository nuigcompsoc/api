package ldap

import (
	log "github.com/sirupsen/logrus"
	"github.com/go-ldap/ldap/v3"
	"strings"
	"strconv"
)

/*
 * Account Utils
 */

func (c *Client) ModifyUser(uid string, firstName string, lastName string, mail string) bool {
	ou, ok := c.IsUserOrIsSociety(uid)
	if !ok {
		return false
	}

	modifyReq := ldap.NewModifyRequest(c.generateDNString(uid, ou), nil)
	modifyReq.Replace("givenname", []string{firstName})
	modifyReq.Replace("sn", []string{lastName})
	modifyReq.Replace("cn", []string{firstName + " " + lastName})
	modifyReq.Replace("mail", []string{mail})

	l := c.bind()
	err := l.Modify(modifyReq)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not modify user",
			"changes": map[string]string{
				"dn": c.generateDNString(uid, ou),
				"firstName": firstName,
				"lastName": lastName,
				"mail": mail,
			},
			"error": err.Error(),
		}).Error("ldap")
		return false
	}

	return true
}

func (c *Client) DeleteUser(uid string) bool {
	deleteReq := ldap.NewDelRequest(c.generateDNString(uid, "people"), nil)

	l := c.bind()
	err := l.Del(deleteReq)

	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not delete user",
			"changes": map[string]string{
				"dn": c.generateDNString(uid, "people"),
			},
			"error": err.Error(),
		}).Error("ldap")
		return false
	}

	return true
}

func (c *Client) DeleteSociety(uid string) bool {
	deleteReq := ldap.NewDelRequest(c.generateDNString(uid, "societies"), nil)

	l := c.bind()
	err := l.Del(deleteReq)

	if err != nil {
		log.WithFields(log.Fields{
			"message": "could not delete society",
			"changes": map[string]string{
				"dn": c.generateDNString(uid, "societies"),
			},
			"error": err.Error(),
		}).Error("ldap")
		return false
	}

	return true
}

func (c *Client) getNextUIDNumber() (int, bool) {
	entries, ok := c.search(c.DN, "(|(uid=*))", []string{"uidNumber"})
	if !ok {
		log.WithFields(log.Fields{
			"message": "error while searching: expected results for getNextUIDNumber",
		}).Error("ldap")
		return 0, false
	}

	highestUID := 0
	for _, e := range entries {
		uidNumber, _ := strconv.Atoi(e.GetAttributeValue("uidNumber"))
		if highestUID < uidNumber {
			highestUID = uidNumber
		}
	}

	return highestUID + 1, true
}

func (c *Client) RegisterSociety(claims map[string]interface{}) bool {
	l := c.bind()
	uid := strings.Split(claims["email"].(string), "@")[0]

	addReq := ldap.NewAddRequest("uid=" + uid + ",ou=societies," + c.DN, nil)
	addReq.Attribute("cn", []string{claims["given_name"].(string) + " " + claims["family_name"].(string)})
	addReq.Attribute("givenname", []string{claims["given_name"].(string)})
	addReq.Attribute("sn", []string{claims["family_name"].(string)})
	addReq.Attribute("mail", []string{claims["email"].(string)})
	addReq.Attribute("uid", []string{uid})
	addReq.Attribute("objectclass", []string{"inetOrgPerson", "top"})

	err := l.Add(addReq)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "error adding society to ldap",
			"error": err.Error(),
		}).Error("ldap")
		return false
	}
	return true
}

func (c *Client) RegisterUser(uid string, password string, info map[string]interface{}) bool {
	l := c.bind()

	nextUIDNumber, ok := c.getNextUIDNumber()
	if !ok {
		return false
	}
	nextUID := strconv.Itoa(nextUIDNumber)

	addReq := ldap.NewAddRequest("uid=" + uid + ",ou=people," + c.DN, nil)
	addReq.Attribute("cn", []string{info["FirstName"].(string) + " " + info["LastName"].(string)})
	addReq.Attribute("givenname", []string{info["FirstName"].(string)})
	addReq.Attribute("sn", []string{info["LastName"].(string)})
	addReq.Attribute("employeenumber", []string{info["MemberID"].(string)})
	addReq.Attribute("mail", []string{info["Email"].(string)})
	addReq.Attribute("uid", []string{uid})
	addReq.Attribute("objectclass", []string{"inetOrgPerson", "posixAccount", "top"})
	addReq.Attribute("loginshell", []string{"/bin/bash"})
	addReq.Attribute("homedirectory", []string{"/home/users/" + uid})
	addReq.Attribute("gidnumber", []string{"100"})
	addReq.Attribute("userpassword", []string{password})
	addReq.Attribute("uidnumber", []string{nextUID})
	addReq.Attribute("gecos", []string{info["FirstName"].(string) + " " + info["LastName"].(string)})

	err := l.Add(addReq)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "error adding user to ldap",
			"error": err.Error(),
		}).Error("ldap")
		return false
	}
	return true
}
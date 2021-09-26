package ldap

import (
	log "github.com/sirupsen/logrus"
	"github.com/go-ldap/ldap/v3"
	"strings"
	"strconv"
)

/*
 * LDAP Utils
 */

func entriesToSocietyMap(entries []*ldap.Entry) (map[string]*Society) {
	societies := make(map[string]*Society, len(entries))
	for _, entry := range entries {
		uid := entry.GetAttributeValue("uid")
		societies[uid] = entryToSociety(entry)
	}
	return societies
}

func entryToSociety(entry *ldap.Entry) *Society {
	uidNumber, _ := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
	Society := Society{}
	Society.FullName = entry.GetAttributeValue("cn")
	Society.FirstName = entry.GetAttributeValue("givenName")
	Society.Surname = entry.GetAttributeValue("sn")
	Society.Mail = entry.GetAttributeValues("mail")
	Society.UID = entry.GetAttributeValue("uid")
	Society.ObjectClass = entry.GetAttributeValues("objectClass")
	Society.Shell = entry.GetAttributeValue("loginShell")
	Society.Home = entry.GetAttributeValue("homeDirectory")
	Society.UIDNumber = uidNumber
	return &Society
}

func entriesToUserMap(entries []*ldap.Entry) (map[string]*User) {
	users := make(map[string]*User, len(entries))
	for _, entry := range entries {
		uid := entry.GetAttributeValue("uid")
		users[uid] = entryToUser(entry)
	}
	return users
}

func entryToUser(entry *ldap.Entry) *User {
	uidNumber, _ := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
	user := User{}
	user.FullName = entry.GetAttributeValue("cn")
	user.FirstName = entry.GetAttributeValue("givenName")
	user.Surname = entry.GetAttributeValue("sn")
	user.MemberID = entry.GetAttributeValue("employeeNumber")
	user.Mail = entry.GetAttributeValues("mail")
	user.UID = entry.GetAttributeValue("uid")
	user.ObjectClass = entry.GetAttributeValues("objectClass")
	user.Shell = entry.GetAttributeValue("loginShell")
	user.Home = entry.GetAttributeValue("homeDirectory")
	user.UIDNumber = uidNumber
	return &user
}
 
/*
 * Account Search Utils
 */

func (c *Client) search(searchBase string, filter string, attributes []string) ([]*ldap.Entry, bool) {
	l := c.bind()
	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.WithFields(log.Fields{
			"message": "error while searching",
			"error": err.Error(),
		}).Error("ldap")
		return nil, false
	}
	
	return sr.Entries, true
}

func (c *Client) GetUser(uid string) (*User, bool) {
	entries, ok := c.search("ou=" + c.UserOU + "," + c.DN, "(|(uid=" + uid + "))", c.UserAttributes)
	if len(entries) < 1 {
		log.WithFields(log.Fields{
			"message": "ldap search successful but search resulted in 0 results",
		}).Info("ldap")
		return nil, true
	} else if !ok {
		return nil, false
	} 
	return entryToUser(entries[0]), true
}

func (c *Client) GetUsers() (map[string]*User, bool) {
	entries, ok := c.search("ou=" + c.UserOU + "," + c.DN, "(|(uid=*))", c.UserAttributes)
	if len(entries) < 1 {
		log.WithFields(log.Fields{
			"message": "ldap search successful but search resulted in 0 results",
		}).Info("ldap")
		return nil, true
	} else if !ok {
		return nil, false
	} 
	return entriesToUserMap(entries), true
}

func (c *Client) GetSociety(uid string) (*Society, bool) {
	entries, ok := c.search("ou=" + c.SocietyOU + "," + c.DN, "(|(uid=" + uid + "))", c.SocietyAttributes)
	if len(entries) < 1 {
		log.WithFields(log.Fields{
			"message": "ldap search successful but search resulted in 0 results",
		}).Info("ldap")
		return nil, true
	} else if !ok {
		return nil, false
	} 
	return entryToSociety(entries[0]), true
}

func (c *Client) GetSocieties() (map[string]*Society, bool) {
	entries, ok := c.search("ou=" + c.SocietyOU + "," + c.DN, "(|(uid=*))", c.SocietyAttributes)
	if len(entries) < 1 {
		log.WithFields(log.Fields{
			"message": "ldap search successful but search resulted in 0 results",
		}).Info("ldap")
		return nil, true
	} else if !ok {
		return nil, false
	} 
	return entriesToSocietyMap(entries), true
}

func (c *Client) GetGroup(group string) (map[string]map[string][]string, bool) {
	entries, ok := c.search("ou=groups," + c.DN, "(|(cn=" + group + "))", c.GroupAttributes)
	if len(entries) < 1 {
		log.WithFields(log.Fields{
			"message": "ldap search successful but search resulted in 0 results",
		}).Error("ldap")
		return nil, true
	} else if !ok {
		return nil, false
	} 
	arr := make(map[string]map[string][]string, len(entries))
	for _, entry := range entries {
		arr[entry.GetAttributeValue("cn")] = make(map[string][]string, 1)
		for _, m := range entry.GetAttributeValues("member") {
			arr[entry.GetAttributeValue("cn")]["members"] = append(arr[entry.GetAttributeValue("cn")]["members"], strings.Split(string(m), ",")[0])
		}
	}
	return arr, true
}

func (c *Client) GetAllGroups() (map[string]map[string][]string, bool) {
	return c.GetGroup("*")
}
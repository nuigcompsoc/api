package ldap

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/nuigcompsoc/api/internal/config"
)

type Entry struct {
	FullName 	string
	FirstName	string
	Surname		string
	Mail		[]string
	UID			string
	ObjectClass	[]string
	Shell		string
	Home		string
	UIDNumber	int
}

type User struct {
	Entry
	MemberID	string
}

type Society struct {
	Entry
}

type Client struct {
	URL	string
	DN	string
	BindUser	string
	BindSecret	string
	UserAttributes	[]string
	SocietyAttributes	[]string
	GroupAttributes	[]string
	UserOU	string
	SocietyOU string
}

func NewClient(c *config.Config) *Client {
	return &Client{
		URL: c.LDAP.URL,
		DN: c.LDAP.DN,
		BindUser: c.LDAP.BindUser,
		BindSecret: c.LDAP.BindSecret,
		UserAttributes: c.LDAP.UserAttributes,
		SocietyAttributes: c.LDAP.SocietyAttributes,
		GroupAttributes: c.LDAP.GroupAttributes,
		UserOU: c.LDAP.UserOU,
		SocietyOU: c.LDAP.SocietyOU,
	}
}

func (c *Client) bind() (*ldap.Conn) {
	l, err := ldap.DialURL(c.URL)
	if err != nil {
		return nil
	}

	err = l.Bind(c.BindUser, c.BindSecret)
	if err != nil {
		return nil
	}
	return l
}
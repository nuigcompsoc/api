package ldap

import (
	//"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	"github.com/nuigcompsoc/api/internal/config"
	"strings"
)

func generateDNString(c *config.Config, uid string, ou string) string {
	return "uid=" + uid + ",ou=" + ou + "," + c.LDAP.DN
}

func IsUserOrIsSociety(c *config.Config, uid string) (string, bool) {
	entries, ok := search(c, c.LDAP.DN, "(|(uid=" + uid + "))", []string{"dn"})
	if len(entries) == 0 {
		log.WithFields(log.Fields{
			"message": "could find uid",
			"uid": uid,
		}).Info("ldap")
		return "", false
	} else if !ok {
		return "", false
	}

	afterOU := strings.Split(entries[0].DN, "ou=")[1]
	ou := strings.Split(afterOU, ",")[0]
	return ou, true
}

// bool1: uidexists, bool2: operation was ok
func CheckUIDExists(cfg *config.Config, uid string) (bool, bool) {
	entries, ok := search(cfg, cfg.LDAP.DN, "(|(uid=" + uid + "))", []string{"uid"})
	if !ok {
		return false, false
	}

	for _, e := range entries {
		if uid == e.GetAttributeValue("uid") {
			return true, true
		}
	}

	return false, true
}

// bool1: uid is in group, bool2: operation was ok
func checkUserIsInGroup(cfg *config.Config, uid string, group string) (bool, bool) {
	entries, ok := search(cfg, "ou=groups," + cfg.LDAP.DN, "(|(cn=" + group + "))", []string{"member"})
	if !ok {
		return false, false
	}

	// LDAP should only return one entry (the group you've specified)
	// We then check if our UID is listed in the collection
	for _, e := range entries {
		for _, m := range e.GetAttributeValues("member") {
			ldapUID := strings.Split(string(m), ",")[0]
			if strings.Contains(ldapUID, uid) == true {
				return true, true
			}
		}
	}

	return false, true
}

func CheckUserIsAdmin(cfg *config.Config, uid string) (bool, bool) {
	return checkUserIsInGroup(cfg, uid, "admin")
}

func CheckUserIsCommittee(cfg *config.Config, uid string) (bool, bool) {
	return checkUserIsInGroup(cfg, uid, "committee")
}
package main

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var errInvalidCredentials = errors.New("invalid username or password")

type ldapUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Mail        string `json:"mail"`
}

type authenticator interface {
	Authenticate(username, password string) (ldapUser, error)
}

// ldapAuthenticator implements search-then-bind: bind as the readonly service
// account, find the user's DN by uid, then bind as that DN with the password
// the user typed.
type ldapAuthenticator struct {
	url     string
	bindDN  string
	usersDN string
	secrets *secretsFile // LDAP_BIND_PASSWORD, rotated by secret-rotator
}

func (a *ldapAuthenticator) Authenticate(username, password string) (ldapUser, error) {
	// An empty password would be an "unauthenticated bind", which LDAP servers
	// may treat as success.
	if username == "" || password == "" {
		return ldapUser{}, errInvalidCredentials
	}

	conn, err := ldap.DialURL(a.url)
	if err != nil {
		return ldapUser{}, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	if err := a.serviceBind(conn); err != nil {
		return ldapUser{}, err
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		a.usersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"uid", "displayName", "cn", "mail"},
		nil,
	))
	if err != nil {
		return ldapUser{}, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) != 1 {
		return ldapUser{}, errInvalidCredentials
	}
	entry := res.Entries[0]

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return ldapUser{}, errInvalidCredentials
		}
		return ldapUser{}, fmt.Errorf("ldap user bind: %w", err)
	}

	display := entry.GetAttributeValue("displayName")
	if display == "" {
		display = entry.GetAttributeValue("cn")
	}
	return ldapUser{
		Username:    entry.GetAttributeValue("uid"),
		DisplayName: display,
		Mail:        entry.GetAttributeValue("mail"),
	}, nil
}

// serviceBind binds with the current LDAP_BIND_PASSWORD. If LDAP rejects it,
// the rotator may have just changed it, so re-read the file and retry once.
func (a *ldapAuthenticator) serviceBind(conn *ldap.Conn) error {
	err := conn.Bind(a.bindDN, a.secrets.Get("LDAP_BIND_PASSWORD"))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		a.secrets.Reload()
		err = conn.Bind(a.bindDN, a.secrets.Get("LDAP_BIND_PASSWORD"))
	}
	if err != nil {
		return fmt.Errorf("ldap service bind: %w", err)
	}
	return nil
}

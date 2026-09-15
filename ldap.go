package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var (
	errInvalidCredentials = errors.New("invalid username or password")
	errUserExists         = errors.New("username already exists")
)

type ldapUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Mail        string `json:"mail"`
}

// newUser is an already-validated registration (see validateRegistration).
type newUser struct {
	Username  string
	Password  string
	GivenName string
	Surname   string
	Mail      string
}

type authenticator interface {
	Authenticate(username, password string) (ldapUser, error)
	Register(u newUser) (ldapUser, error)
}

// ldapAuthenticator talks to OpenLDAP with two service accounts:
//   - readonly (LDAP_BIND_DN): search-then-bind login.
//   - registrar (LDAP_REGISTRAR_DN): add-only ACL on ou=users, used to register.
//
// Both passwords are rotated by secret-rotator and read from the secrets file.
type ldapAuthenticator struct {
	url         string
	bindDN      string
	registrarDN string
	usersDN     string
	secrets     *secretsFile // LDAP_BIND_PASSWORD, LDAP_REGISTRAR_PASSWORD
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

	if err := a.serviceBind(conn, a.bindDN, "LDAP_BIND_PASSWORD"); err != nil {
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

// Register creates uid=<username> under usersDN bound as the registrar account.
// LDAP itself enforces uniqueness: an existing uid returns entryAlreadyExists.
func (a *ldapAuthenticator) Register(u newUser) (ldapUser, error) {
	hash, err := sshaHash(u.Password)
	if err != nil {
		return ldapUser{}, err
	}

	conn, err := ldap.DialURL(a.url)
	if err != nil {
		return ldapUser{}, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	if err := a.serviceBind(conn, a.registrarDN, "LDAP_REGISTRAR_PASSWORD"); err != nil {
		return ldapUser{}, err
	}

	display := u.GivenName + " " + u.Surname
	req := ldap.NewAddRequest(fmt.Sprintf("uid=%s,%s", ldap.EscapeDN(u.Username), a.usersDN), nil)
	req.Attribute("objectClass", []string{"inetOrgPerson"})
	req.Attribute("uid", []string{u.Username})
	req.Attribute("cn", []string{display})
	req.Attribute("sn", []string{u.Surname})
	req.Attribute("givenName", []string{u.GivenName})
	req.Attribute("displayName", []string{display})
	req.Attribute("mail", []string{u.Mail})
	req.Attribute("userPassword", []string{hash})

	if err := conn.Add(req); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return ldapUser{}, errUserExists
		}
		return ldapUser{}, fmt.Errorf("ldap add: %w", err)
	}
	return ldapUser{Username: u.Username, DisplayName: display, Mail: u.Mail}, nil
}

// sshaHash returns an OpenLDAP {SSHA} password so the plaintext is never stored.
func sshaHash(password string) (string, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := sha1.Sum(append([]byte(password), salt...))
	return "{SSHA}" + base64.StdEncoding.EncodeToString(append(sum[:], salt...)), nil
}

// serviceBind binds dn with the current value of passwordKey. If LDAP rejects
// it, the rotator may have just changed it, so re-read the file and retry once.
func (a *ldapAuthenticator) serviceBind(conn *ldap.Conn, dn, passwordKey string) error {
	err := conn.Bind(dn, a.secrets.Get(passwordKey))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		a.secrets.Reload()
		err = conn.Bind(dn, a.secrets.Get(passwordKey))
	}
	if err != nil {
		return fmt.Errorf("ldap bind %s: %w", dn, err)
	}
	return nil
}

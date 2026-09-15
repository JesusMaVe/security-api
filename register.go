package main

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type registerBody struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	GivenName string `json:"givenName"`
	Surname   string `json:"sn"`
	Mail      string `json:"mail"`
}

// Lowercase, starts with a letter; only DN- and filter-safe characters.
var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

// validateRegistration normalizes the body and returns a user-facing error
// message, or "" when it is valid.
func validateRegistration(b registerBody) (newUser, string) {
	u := newUser{
		Username:  strings.ToLower(strings.TrimSpace(b.Username)),
		Password:  b.Password,
		GivenName: strings.TrimSpace(b.GivenName),
		Surname:   strings.TrimSpace(b.Surname),
		Mail:      strings.TrimSpace(b.Mail),
	}
	switch {
	case !usernamePattern.MatchString(u.Username):
		return u, "username must be 3-32 chars: lowercase letters, digits, '.', '_' or '-', starting with a letter"
	case utf8.RuneCountInString(u.Password) < 8 || len(u.Password) > 128:
		return u, "password must be 8-128 characters"
	case !validName(u.GivenName):
		return u, "first name is required (max 64 characters)"
	case !validName(u.Surname):
		return u, "last name is required (max 64 characters)"
	case !validMail(u.Mail):
		return u, "a valid email is required"
	}
	return u, ""
}

func validName(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 64 {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func validMail(s string) bool {
	if len(s) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == s
}

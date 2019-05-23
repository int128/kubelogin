package authserver

import (
	"testing"
	"text/template"
)

func parseTemplates(t *testing.T) templates {
	tpl, err := template.ParseFiles(
		"authserver/testdata/oidc-discovery.json",
		"authserver/testdata/oidc-token.json",
		"authserver/testdata/oidc-jwks.json",
	)
	if err != nil {
		t.Fatalf("could not read the templates: %s", err)
	}
	return templates{
		discovery: tpl.Lookup("oidc-discovery.json"),
		token:     tpl.Lookup("oidc-token.json"),
		jwks:      tpl.Lookup("oidc-jwks.json"),
	}
}

type templates struct {
	discovery *template.Template
	token     *template.Template
	jwks      *template.Template
}

type templateValues struct {
	Issuer       string
	IDToken      string
	RefreshToken string
	PrivateKey   struct{ N, E string }
}

// Package setup provides the use case of setting up environment.
package setup

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	_ "embed"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

var Set = wire.NewSet(
	wire.Struct(new(Setup), "*"),
	wire.Bind(new(Interface), new(*Setup)),
)

type Interface interface {
	Do(ctx context.Context, in Input) error
}

type Setup struct {
	Authentication authentication.Interface
	Logger         logger.Interface
}

//go:embed setup.md
var setupMarkdown string

var setupTemplate = template.Must(template.New("setup.md").Funcs(template.FuncMap{
	"quote": strconv.Quote,
}).Parse(setupMarkdown))

type Input struct {
	IssuerURL       string
	ClientID        string
	ClientSecret    string
	ExtraScopes     []string
	UseAccessToken  bool
	PKCEMethod      oidc.PKCEMethod
	GrantOptionSet  authentication.GrantOptionSet
	TLSClientConfig tlsclientconfig.Config
	ChangedFlags    []string
}

func (u Setup) Do(ctx context.Context, in Input) error {
	u.Logger.Printf("Authentication in progress...")
	out, err := u.Authentication.Do(ctx, authentication.Input{
		Provider: oidc.Provider{
			IssuerURL:      in.IssuerURL,
			ClientID:       in.ClientID,
			ClientSecret:   in.ClientSecret,
			ExtraScopes:    in.ExtraScopes,
			PKCEMethod:     in.PKCEMethod,
			UseAccessToken: in.UseAccessToken,
		},
		GrantOptionSet:  in.GrantOptionSet,
		TLSClientConfig: in.TLSClientConfig,
	})
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	idTokenClaims, err := out.TokenSet.DecodeWithoutVerify()
	if err != nil {
		return fmt.Errorf("you got an invalid token: %w", err)
	}

	var b strings.Builder
	if err := setupTemplate.Execute(&b, map[string]any{
		"IDTokenPrettyJSON": idTokenClaims.Pretty,
		"Flags":             in.ChangedFlags,
	}); err != nil {
		return fmt.Errorf("render the template: %w", err)
	}
	u.Logger.Printf(b.String())
	return nil
}

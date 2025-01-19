package cmd

import (
	"fmt"
	"strings"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/spf13/pflag"
)

var allPKCEMethods = strings.Join([]string{"auto", "no", "S256"}, "|")

type pkceOptions struct {
	UsePKCE    bool
	PKCEMethod string
}

func (o *pkceOptions) addFlags(f *pflag.FlagSet) {
	f.BoolVar(&o.UsePKCE, "oidc-use-pkce", false, "Force PKCE S256 code challenge method")
	if err := f.MarkDeprecated("oidc-use-pkce", "use --oidc-pkce-method instead. For the most providers, you don't need to set the flag."); err != nil {
		panic(err)
	}
	f.StringVar(&o.PKCEMethod, "oidc-pkce-method", "auto", fmt.Sprintf("PKCE code challenge method. Automatically determined by default. One of (%s)", allPKCEMethods))
}

func (o *pkceOptions) pkceMethod() (oidc.PKCEMethod, error) {
	if o.UsePKCE {
		return oidc.PKCEMethodS256, nil
	}
	switch o.PKCEMethod {
	case "auto":
		return oidc.PKCEMethodAuto, nil
	case "no":
		return oidc.PKCEMethodNo, nil
	case "S256":
		return oidc.PKCEMethodS256, nil
	default:
		return 0, fmt.Errorf("oidc-pkce-method must be one of (%s)", allPKCEMethods)
	}
}

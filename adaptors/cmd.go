package adaptors

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"go.uber.org/dig"
)

func NewCmd(i Cmd) adaptors.Cmd {
	return &i
}

type Cmd struct {
	dig.In
	Login  usecases.Login
	Logger adaptors.Logger
}

func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	var o cmdOptions
	parser := flags.NewParser(&o, flags.HelpFlag)
	parser.LongDescription = fmt.Sprintf(`Version %s
		This updates the kubeconfig for Kubernetes OpenID Connect (OIDC) authentication.`,
		version)
	args, err := parser.ParseArgs(args[1:])
	if err != nil {
		cmd.Logger.Logf("Error: %s", err)
		return 1
	}
	if len(args) > 0 {
		cmd.Logger.Logf("Error: too many arguments")
		return 1
	}
	kubeConfig, err := o.ExpandKubeConfig()
	if err != nil {
		cmd.Logger.Logf("Error: invalid option: %s", err)
		return 1
	}

	in := usecases.LoginIn{
		KubeConfig:      kubeConfig,
		ListenPort:      o.ListenPort,
		SkipTLSVerify:   o.SkipTLSVerify,
		SkipOpenBrowser: o.SkipOpenBrowser,
	}
	if err := cmd.Login.Do(ctx, in); err != nil {
		cmd.Logger.Logf("Error: %s", err)
		return 1
	}
	return 0
}

type cmdOptions struct {
	KubeConfig      string `long:"kubeconfig" default:"~/.kube/config" env:"KUBECONFIG" description:"Path to the kubeconfig file"`
	ListenPort      int    `long:"listen-port" default:"8000" env:"KUBELOGIN_LISTEN_PORT" description:"Port used by kubelogin to bind its webserver"`
	SkipTLSVerify   bool   `long:"insecure-skip-tls-verify" env:"KUBELOGIN_INSECURE_SKIP_TLS_VERIFY" description:"If set, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure"`
	SkipOpenBrowser bool   `long:"skip-open-browser" env:"KUBELOGIN_SKIP_OPEN_BROWSER" description:"If set, it does not open the browser on authentication."`
}

// ExpandKubeConfig returns an expanded KubeConfig path.
func (c *cmdOptions) ExpandKubeConfig() (string, error) {
	d, err := homedir.Expand(c.KubeConfig)
	if err != nil {
		return "", errors.Wrapf(err, "could not expand %s", c.KubeConfig)
	}
	return d, nil
}

package cmd

import (
	"context"
	"path/filepath"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

// Set provides an implementation and interface for Cmd.
var Set = wire.NewSet(
	wire.Struct(new(Cmd), "*"),
	wire.Bind(new(adaptors.Cmd), new(*Cmd)),
	wire.Struct(new(Root), "*"),
	wire.Struct(new(GetToken), "*"),
)

const examples = `  # Login to the provider using the authorization code flow.
  %[1]s

  # Login to the provider using the resource owner password credentials flow.
  %[1]s --username USERNAME --password PASSWORD

  # Run as a credential plugin.
  %[1]s get-token --oidc-issuer-url=https://issuer.example.com`

var defaultListenPort = []int{8000, 18000}
var defaultTokenCacheDir = homedir.HomeDir() + "/.kube/cache/oidc-login"

// Cmd provides interaction with command line interface (CLI).
type Cmd struct {
	Root     *Root
	GetToken *GetToken
	Logger   logger.Interface
}

// Run parses the command line arguments and executes the specified use-case.
// It returns an exit code, that is 0 on success or 1 on error.
func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	executable := filepath.Base(args[0])

	rootCmd := cmd.Root.New(ctx, executable)
	rootCmd.Version = version
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	getTokenCmd := cmd.GetToken.New(ctx)
	rootCmd.AddCommand(getTokenCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			cmd.Logger.Printf("%s version %s", executable, version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	rootCmd.SetArgs(args[1:])
	if err := rootCmd.Execute(); err != nil {
		cmd.Logger.Printf("error: %s", err)
		cmd.Logger.V(1).Infof("stacktrace: %+v", err)
		return 1
	}
	return 0
}

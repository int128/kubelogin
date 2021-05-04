package cmd

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/spf13/cobra"
)

// Set provides an implementation and interface for Cmd.
var Set = wire.NewSet(
	wire.Struct(new(Cmd), "*"),
	wire.Bind(new(Interface), new(*Cmd)),
	wire.Struct(new(Root), "*"),
	wire.Struct(new(GetToken), "*"),
	wire.Struct(new(Setup), "*"),
)

type Interface interface {
	Run(ctx context.Context, args []string, version string) int
}

var defaultListenAddress = []string{"127.0.0.1:8000", "127.0.0.1:18000"}
var defaultTokenCacheDir = filepath.Join("~", ".kube", "cache", "oidc-login")

const defaultAuthenticationTimeoutSec = 180

// Cmd provides interaction with command line interface (CLI).
type Cmd struct {
	Root     *Root
	GetToken *GetToken
	Setup    *Setup
	Logger   logger.Interface
}

// Run parses the command line arguments and executes the specified use-case.
// It returns an exit code, that is 0 on success or 1 on error.
func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	rootCmd := cmd.Root.New()
	rootCmd.Version = version
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	getTokenCmd := cmd.GetToken.New()
	rootCmd.AddCommand(getTokenCmd)

	setupCmd := cmd.Setup.New()
	rootCmd.AddCommand(setupCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			cmd.Logger.Printf("kubelogin version %s (%s %s_%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
	rootCmd.AddCommand(versionCmd)

	rootCmd.SetArgs(args[1:])
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		cmd.Logger.Printf("error: %s", err)
		cmd.Logger.V(1).Infof("stacktrace: %+v", err)
		return 1
	}
	return 0
}

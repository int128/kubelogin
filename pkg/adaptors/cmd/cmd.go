package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
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

var defaultListenPort = []int{8000, 18000}
var defaultTokenCacheDir = homedir.HomeDir() + "/.kube/cache/oidc-login"

func translateListenPortToBindAddress(ports []int) (address []string) {
	for _, p := range ports {
		address = append(address, fmt.Sprintf("127.0.0.1:%d", p))
	}
	return
}

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
	executable := filepath.Base(args[0])

	rootCmd := cmd.Root.New(ctx, executable)
	rootCmd.Version = version
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	getTokenCmd := cmd.GetToken.New(ctx)
	rootCmd.AddCommand(getTokenCmd)

	setupCmd := cmd.Setup.New(ctx)
	rootCmd.AddCommand(setupCmd)

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

package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

// Set provides an implementation and interface for Cmd.
var Set = wire.NewSet(
	Cmd{},
	wire.Bind((*adaptors.Cmd)(nil), (*Cmd)(nil)),
)

const examples = `  # Login to the provider using authorization code grant.
  %[1]s

  # Login to the provider using resource owner password credentials grant.
  %[1]s --username USERNAME --password PASSWORD

  # Wrap kubectl and login transparently
  alias kubectl='%[1]s exec -- kubectl'`

var defaultListenPort = []int{8000, 18000}

type Cmd struct {
	Login        usecases.Login
	LoginAndExec usecases.LoginAndExec
	Logger       adaptors.Logger
}

func (cmd *Cmd) Run(ctx context.Context, args []string, version string) int {
	var exitCode int
	executable := filepath.Base(args[0])
	var o struct {
		kubectlOptions
		kubeloginOptions
	}
	rootCmd := cobra.Command{
		Use:     executable,
		Short:   "Login to the OpenID Connect provider and update the kubeconfig",
		Example: fmt.Sprintf(examples, executable),
		Args:    cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			cmd.Logger.SetLevel(adaptors.LogLevel(o.Verbose))
			in := usecases.LoginIn{
				KubeconfigFilename: o.Kubeconfig,
				KubeconfigContext:  kubeconfig.ContextName(o.Context),
				KubeconfigUser:     kubeconfig.UserName(o.User),
				CACertFilename:     o.CertificateAuthority,
				SkipTLSVerify:      o.SkipTLSVerify,
				ListenPort:         o.ListenPort,
				SkipOpenBrowser:    o.SkipOpenBrowser,
				Username:           o.Username,
				Password:           o.Password,
			}
			if err := cmd.Login.Do(ctx, in); err != nil {
				cmd.Logger.Printf("error: %s", err)
				exitCode = 1
				return
			}
		},
	}
	o.kubectlOptions.register(rootCmd.Flags())
	o.kubeloginOptions.register(rootCmd.Flags())

	execCmd := cobra.Command{
		Use:   "exec [flags] -- kubectl [args]",
		Short: "Login transparently and execute the kubectl command",
		Args: func(execCmd *cobra.Command, args []string) error {
			if execCmd.ArgsLenAtDash() == -1 {
				return xerrors.Errorf("double dash is missing, please run as %s exec -- kubectl", executable)
			}
			if len(args) < 1 {
				return xerrors.New("too few arguments")
			}
			return nil
		},
		Run: func(execCmd *cobra.Command, args []string) {
			// parse the extra args and override the kubectl options
			f := pflag.NewFlagSet(execCmd.Name(), pflag.ContinueOnError)
			o.kubectlOptions.register(f)
			// ignore unknown flags and help flags (-h/--help)
			f.ParseErrorsWhitelist.UnknownFlags = true
			f.BoolP("help", "h", false, "ignore help flags")
			if err := f.Parse(args); err != nil {
				cmd.Logger.Debugf(1, "error while parsing the extra arguments: %s", err)
			}
			cmd.Logger.SetLevel(adaptors.LogLevel(o.Verbose))
			in := usecases.LoginAndExecIn{
				LoginIn: usecases.LoginIn{
					KubeconfigFilename: o.Kubeconfig,
					KubeconfigContext:  kubeconfig.ContextName(o.Context),
					KubeconfigUser:     kubeconfig.UserName(o.User),
					CACertFilename:     o.CertificateAuthority,
					SkipTLSVerify:      o.SkipTLSVerify,
					ListenPort:         o.ListenPort,
					SkipOpenBrowser:    o.SkipOpenBrowser,
					Username:           o.Username,
					Password:           o.Password,
				},
				Executable: args[0],
				Args:       args[1:],
			}
			out, err := cmd.LoginAndExec.Do(ctx, in)
			if err != nil {
				cmd.Logger.Printf("error: %s", err)
				exitCode = 1
				return
			}
			exitCode = out.ExitCode
		},
	}
	o.kubeloginOptions.register(execCmd.Flags())
	rootCmd.AddCommand(&execCmd)

	versionCmd := cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			cmd.Logger.Printf("%s version %s", executable, version)
		},
	}
	rootCmd.AddCommand(&versionCmd)

	rootCmd.SetArgs(args[1:])
	if err := rootCmd.Execute(); err != nil {
		cmd.Logger.Debugf(1, "error while parsing the arguments: %s", err)
		return 1
	}
	return exitCode
}

type kubectlOptions struct {
	Kubeconfig           string
	Context              string
	User                 string
	CertificateAuthority string
	SkipTLSVerify        bool
	Verbose              int
}

func (o *kubectlOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.StringVar(&o.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	f.StringVar(&o.Context, "context", "", "The name of the kubeconfig context to use")
	f.StringVar(&o.User, "user", "", "The name of the kubeconfig user to use. Prior to --context")
	f.StringVar(&o.CertificateAuthority, "certificate-authority", "", "Path to a cert file for the certificate authority")
	f.BoolVar(&o.SkipTLSVerify, "insecure-skip-tls-verify", false, "If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure")
	f.IntVarP(&o.Verbose, "v", "v", 0, "If set to 1 or greater, it shows debug log")
}

type kubeloginOptions struct {
	ListenPort      []int
	SkipOpenBrowser bool
	Username        string
	Password        string
}

func (o *kubeloginOptions) register(f *pflag.FlagSet) {
	f.SortFlags = false
	f.IntSliceVar(&o.ListenPort, "listen-port", defaultListenPort, "Port to bind to the local server. If multiple ports are given, it will try the ports in order")
	f.BoolVar(&o.SkipOpenBrowser, "skip-open-browser", false, "If true, it does not open the browser on authentication")
	f.StringVar(&o.Username, "username", "", "If set, perform the resource owner password credentials grant")
	f.StringVar(&o.Password, "password", "", "If set, use the password instead of asking it")
}

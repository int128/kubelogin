package cmd

import (
	"fmt"

	"github.com/int128/kubelogin/pkg/usecases/clean"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type cleanOptions struct {
	TokenCacheDir string
}

func (o *cleanOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", getDefaultTokenCacheDir(), "Path to a directory of the token cache")
}

type Clean struct {
	Clean clean.Interface
}

func (cmd *Clean) New() *cobra.Command {
	var o cleanOptions
	c := &cobra.Command{
		Use:   "clean [flags]",
		Short: "Delete the token cache",
		Long: `Delete the token cache.

This deletes the token cache directory from both the file system and the keyring.
`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			o.TokenCacheDir = expandHomedir(o.TokenCacheDir)
			in := clean.Input{
				TokenCacheDir: o.TokenCacheDir,
			}
			if err := cmd.Clean.Do(c.Context(), in); err != nil {
				return fmt.Errorf("clean: %w", err)
			}
			return nil
		},
	}
	c.Flags().SortFlags = false
	o.addFlags(c.Flags())
	return c
}

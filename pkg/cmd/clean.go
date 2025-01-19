package cmd

import (
	"fmt"

	"github.com/int128/kubelogin/pkg/usecases/clean"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type cleanOptions struct {
	tokenCacheOptions tokenCacheOptions
}

func (o *cleanOptions) addFlags(f *pflag.FlagSet) {
	o.tokenCacheOptions.addFlags(f)
}

func (o *cleanOptions) expandHomedir() {
	o.tokenCacheOptions.expandHomedir()
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

This deletes both the OS keyring and the directory by default.
If you encounter an error of keyring, try --token-cache-storage=disk.
`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			o.expandHomedir()
			tokenCacheConfig, err := o.tokenCacheOptions.tokenCacheConfig()
			if err != nil {
				return fmt.Errorf("clean: %w", err)
			}
			in := clean.Input{
				TokenCacheConfig: tokenCacheConfig,
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

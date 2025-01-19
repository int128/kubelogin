package cmd

import (
	"path/filepath"
	"strings"

	"k8s.io/client-go/util/homedir"
)

func expandHomedir(s string) string {
	if !strings.HasPrefix(s, "~") {
		return s
	}
	return filepath.Join(homedir.HomeDir(), strings.TrimPrefix(s, "~"))
}

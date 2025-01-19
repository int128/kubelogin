package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/int128/kubelogin/integration_test/httpdriver"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/testing/clock"
	"github.com/int128/kubelogin/pkg/testing/logger"
)

func TestClean(t *testing.T) {
	tokenCacheDir := t.TempDir()

	cmd := di.NewCmdForHeadless(clock.Fake(time.Now()), os.Stdin, os.Stdout, logger.New(t), httpdriver.Zero(t))
	exitCode := cmd.Run(context.TODO(), []string{
		"kubelogin",
		"clean",
		"--token-cache-dir", tokenCacheDir,
		"--token-cache-storage", "disk",
	}, "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

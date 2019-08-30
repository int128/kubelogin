package e2e_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/e2e_test/idp"
	"github.com/int128/kubelogin/e2e_test/idp/mock_idp"
	"github.com/int128/kubelogin/e2e_test/localserver"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/usecases/auth"
)

// Run the integration tests of the credential plugin use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the output.
//
func TestCmd_Run_CredentialPlugin(t *testing.T) {
	timeout := 1 * time.Second
	cacheDir, err := ioutil.TempDir("", "kube")
	if err != nil {
		t.Fatalf("could not create a cache dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cacheDir); err != nil {
			t.Errorf("could not clean up the cache dir: %s", err)
		}
	}()

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service))
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)

		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		credentialPluginInteraction.EXPECT().
			Write(gomock.Any()).
			Do(func(out credentialplugin.Output) {
				if out.Token != idToken {
					t.Errorf("Token wants %s but %s", idToken, out.Token)
				}
				if out.Expiry != tokenExpiryFuture {
					t.Errorf("Expiry wants %v but %v", tokenExpiryFuture, out.Expiry)
				}
			})

		runGetTokenCmd(t, ctx,
			openBrowserOnReadyFunc(t, ctx, nil),
			credentialPluginInteraction,
			"--skip-open-browser",
			"--listen-port", "0",
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		)
	})
}

func runGetTokenCmd(t *testing.T, ctx context.Context, localServerReadyFunc auth.LocalServerReadyFunc, interaction credentialplugin.Interface, args ...string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(mock_logger.New(t), localServerReadyFunc, interaction)
	exitCode := cmd.Run(ctx, append([]string{"kubelogin", "get-token", "--v=1"}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

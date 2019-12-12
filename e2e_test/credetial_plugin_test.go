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
	"github.com/int128/kubelogin/e2e_test/keys"
	"github.com/int128/kubelogin/e2e_test/localserver"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

// Run the integration tests of the credential plugin use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the output.
//
func TestCredentialPlugin(t *testing.T) {
	cacheDir, err := ioutil.TempDir("", "kube")
	if err != nil {
		t.Fatalf("could not create a cache dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cacheDir); err != nil {
			t.Errorf("could not clean up the cache dir: %s", err)
		}
	}()

	t.Run("NoTLS", func(t *testing.T) {
		testCredentialPlugin(t, cacheDir, keys.None, nil)
	})
	t.Run("TLS", func(t *testing.T) {
		testCredentialPlugin(t, cacheDir, keys.Server, []string{"--certificate-authority", keys.Server.CACertPath})
	})
}

func testCredentialPlugin(t *testing.T, cacheDir string, idpTLS keys.Keys, extraArgs []string) {
	timeout := 1 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)
		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		assertCredentialPluginOutput(t, credentialPluginInteraction, &idToken)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, openBrowserOnReadyFunc(t, ctx, idpTLS), credentialPluginInteraction, args)
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "", tokenExpiryFuture)
		setupMockIDPForROPC(service, serverURL, "openid", "USER", "PASS", idToken)
		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		assertCredentialPluginOutput(t, credentialPluginInteraction, &idToken)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--username", "USER",
			"--password", "PASS",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, openBrowserOnReadyFunc(t, ctx, idpTLS), credentialPluginInteraction, args)
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "email profile openid", &idToken)

		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		assertCredentialPluginOutput(t, credentialPluginInteraction, &idToken)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--oidc-extra-scope", "email",
			"--oidc-extra-scope", "profile",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, openBrowserOnReadyFunc(t, ctx, idpTLS), credentialPluginInteraction, args)
	})
}

func assertCredentialPluginOutput(t *testing.T, credentialPluginInteraction *mock_credentialplugin.MockInterface, idToken *string) {
	credentialPluginInteraction.EXPECT().
		Write(gomock.Any()).
		Do(func(out credentialplugin.Output) {
			if out.Token != *idToken {
				t.Errorf("Token wants %s but %s", *idToken, out.Token)
			}
			if out.Expiry != tokenExpiryFuture {
				t.Errorf("Expiry wants %v but %v", tokenExpiryFuture, out.Expiry)
			}
		})
}

func runGetTokenCmd(t *testing.T, ctx context.Context, localServerReadyFunc authentication.LocalServerReadyFunc, interaction credentialplugin.Interface, args []string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(mock_logger.New(t), localServerReadyFunc, interaction)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin", "get-token",
		"--v=1",
		"--skip-open-browser",
		"--listen-port", "0",
	}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

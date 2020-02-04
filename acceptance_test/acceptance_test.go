package acceptance_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"golang.org/x/sync/errgroup"
)

const (
	tokenCacheDir = "output/token-cache"
	kubeconfigEnv = "KUBECONFIG=output/kubeconfig.yaml:kubeconfig_oidc.yaml"
)

func init() {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
}

func Test(t *testing.T) {
	if _, err := os.Stat("output/kubeconfig.yaml"); err != nil {
		t.Skipf("skip the test: %s", err)
	}
	if err := os.RemoveAll(tokenCacheDir); err != nil {
		t.Fatalf("could not remove the token cache: %s", err)
	}
	ctx := context.TODO()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return runKubectl(ctx, t, eg) })
	eg.Go(func() error { return runBrowser(ctx) })
	if err := eg.Wait(); err != nil {
		t.Errorf("error: %s", err)
	}
}

func runKubectl(ctx context.Context, t *testing.T, eg *errgroup.Group) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.Command("kubectl", "--user=oidc", "--namespace=dex", "get", "deploy")
	cmd.Env = append(os.Environ(), kubeconfigEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	eg.Go(func() error {
		<-ctx.Done()
		if cmd.Process == nil {
			log.Printf("process not started")
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			log.Printf("process terminated with exit code %d", cmd.ProcessState.ExitCode())
			return nil
		}
		log.Printf("sending SIGTERM to pid %d", cmd.Process.Pid)
		// kill the child processes
		// https://medium.com/@felixge/killing-a-child-process-and-all-of-its-children-in-go-54079af94773
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
			t.Errorf("could not send a signal: %s", err)
		}
		return nil
	})
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not run a command: %w", err)
	}
	return nil
}

func runBrowser(ctx context.Context) error {
	execOpts := chromedp.DefaultExecAllocatorOptions[:]
	execOpts = append(execOpts, chromedp.NoSandbox)
	ctx, cancel := chromedp.NewExecAllocator(ctx, execOpts...)
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(log.Printf))
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := openKubeloginAndLogInToDex(ctx); err != nil {
		return fmt.Errorf("could not run the browser: %w", err)
	}
	return nil
}

func openKubeloginAndLogInToDex(ctx context.Context) error {
	for {
		var location string
		err := chromedp.Run(ctx,
			chromedp.Navigate(`http://localhost:8000`),
			chromedp.Location(&location),
		)
		if err != nil {
			return err
		}
		log.Printf("location: %s", location)
		if strings.HasPrefix(location, `http://`) || strings.HasPrefix(location, `https://`) {
			break
		}
		time.Sleep(2 * time.Second)
	}

	err := chromedp.Run(ctx,
		// https://dex-server:10443/dex/auth/local
		chromedp.WaitVisible(`#login`),
		logPageMetadata(),
		chromedp.SendKeys(`#login`, `admin@example.com`),
		chromedp.SendKeys(`#password`, `password`),
		chromedp.Submit(`#submit-login`),
		// https://dex-server:10443/dex/approval
		chromedp.WaitVisible(`.dex-btn.theme-btn--success`),
		logPageMetadata(),
		chromedp.Submit(`.dex-btn.theme-btn--success`),
		// http://localhost:8000
		chromedp.WaitReady(`body`),
		logPageMetadata(),
	)
	if err != nil {
		return err
	}
	return nil
}

func logPageMetadata() chromedp.Action {
	var location string
	var title string
	return chromedp.Tasks{
		chromedp.Location(&location),
		chromedp.Title(&title),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Printf("location: %s [%s]", location, title)
			return nil
		}),
	}
}

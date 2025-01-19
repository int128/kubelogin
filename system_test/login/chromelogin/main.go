package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

func init() {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s URL", os.Args[0])
		return
	}
	url := os.Args[1]
	if err := runBrowser(context.Background(), url); err != nil {
		log.Fatalf("error: %s", err)
	}
}

func runBrowser(ctx context.Context, url string) error {
	execOpts := chromedp.DefaultExecAllocatorOptions[:]
	execOpts = append(execOpts,
		chromedp.NoSandbox,
		chromedp.WSURLReadTimeout(30*time.Second),
	)
	ctx, cancelExec := chromedp.NewExecAllocator(ctx, execOpts...)
	defer cancelExec()
	ctx, cancelCtx := chromedp.NewContext(ctx, chromedp.WithLogf(log.Printf))
	defer cancelCtx()
	log.Printf("Opening a new browser and navigating to %s", url)
	if err := openBrowser(ctx, url); err != nil {
		return fmt.Errorf("could not open a new browser: %w", err)
	}

	ctx, cancelTimeout := context.WithTimeout(ctx, 30*time.Second)
	defer cancelTimeout()
	log.Printf("Logging in to Dex")
	if err := logInToDex(ctx); err != nil {
		return fmt.Errorf("could not run the browser: %w", err)
	}
	return nil
}

func openBrowser(ctx context.Context, url string) error {
	for {
		var location string
		err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Location(&location),
		)
		if err != nil {
			return err
		}
		log.Printf("Location: %s", location)
		if strings.HasPrefix(location, `http://`) || strings.HasPrefix(location, `https://`) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
}

func logInToDex(ctx context.Context) error {
	return chromedp.Run(ctx,
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
}

func logPageMetadata() chromedp.Action {
	var location string
	var title string
	return chromedp.Tasks{
		chromedp.Location(&location),
		chromedp.Title(&title),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Printf("Location: %s, Title: %s", location, title)
			return nil
		}),
	}
}

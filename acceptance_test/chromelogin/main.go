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
	execOpts = append(execOpts, chromedp.NoSandbox)
	ctx, cancel := chromedp.NewExecAllocator(ctx, execOpts...)
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(log.Printf))
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := logInToDex(ctx, url); err != nil {
		return fmt.Errorf("could not run the browser: %w", err)
	}
	return nil
}

func logInToDex(ctx context.Context, url string) error {
	for {
		var location string
		err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Location(&location),
		)
		if err != nil {
			return err
		}
		log.Printf("location: %s", location)
		if strings.HasPrefix(location, `http://`) || strings.HasPrefix(location, `https://`) {
			break
		}
		time.Sleep(1 * time.Second)
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

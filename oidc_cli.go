package main

import (
	"context"
	"fmt"
)

// ReceiveAuthCodeFromCLI receives an auth code from CLI
func ReceiveAuthCodeFromCLI(ctx context.Context, authCodeCh chan<- string, errCh chan<- error) {
	var authCode string
	if _, err := fmt.Scanln(&authCode); err != nil {
		errCh <- err
	} else {
		authCodeCh <- authCode
	}
}

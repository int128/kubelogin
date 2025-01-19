//go:build tools

package main

import (
	_ "github.com/google/wire/cmd/wire"
	_ "github.com/vektra/mockery/v2/cmd"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)

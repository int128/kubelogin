package reader

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestReader_ReadPasswordFromCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cat is not available on Windows")
	}

	t.Run("TrimTrailingNewline", func(t *testing.T) {
		r := Reader{Stdin: strings.NewReader("PASS\n")}
		got, err := r.ReadPasswordFromCommand(context.TODO(), "cat")
		if err != nil {
			t.Fatalf("ReadPasswordFromCommand error: %s", err)
		}
		if got != "PASS" {
			t.Errorf("password wants PASS but was %q", got)
		}
	})

	t.Run("EmptyOutput", func(t *testing.T) {
		r := Reader{Stdin: strings.NewReader("\n")}
		_, err := r.ReadPasswordFromCommand(context.TODO(), "cat")
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("EmptyCommand", func(t *testing.T) {
		r := Reader{Stdin: strings.NewReader("")}
		_, err := r.ReadPasswordFromCommand(context.TODO(), " ")
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("CommandError", func(t *testing.T) {
		// cat prints the stdin and then fails on the missing file.
		r := Reader{Stdin: strings.NewReader("SECRET\n")}
		_, err := r.ReadPasswordFromCommand(context.TODO(), "cat - "+t.TempDir()+"/missing")
		if err == nil {
			t.Fatalf("err wants non-nil but nil")
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("err must not contain the output: %s", err)
		}
	})
}

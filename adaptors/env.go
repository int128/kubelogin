package adaptors

import (
	"os"

	"github.com/int128/kubelogin/adaptors/interfaces"
)

func NewEnv() adaptors.Env {
	return &Env{}
}

// Env provides the environment dependent facilities.
type Env struct{}

// Getenv wraps os.Getenv().
func (*Env) Getenv(key string) string {
	return os.Getenv(key)
}

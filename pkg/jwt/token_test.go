package jwt_test

import (
	"testing"
	"time"

	"github.com/int128/kubelogin/pkg/jwt"
)

type timeProvider time.Time

func (tp timeProvider) Now() time.Time {
	return time.Time(tp)
}

func TestClaims_IsExpired(t *testing.T) {
	claims := jwt.Claims{
		Expiry: time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	t.Run("Expired", func(t *testing.T) {
		tp := timeProvider(time.Date(2019, 1, 2, 4, 0, 0, 0, time.UTC))
		got := claims.IsExpired(tp)
		if got != true {
			t.Errorf("IsExpired() wants true but false")
		}
	})

	t.Run("NotExpired", func(t *testing.T) {
		tp := timeProvider(time.Date(2019, 1, 2, 0, 0, 0, 0, time.UTC))
		got := claims.IsExpired(tp)
		if got != false {
			t.Errorf("IsExpired() wants false but true")
		}
	})
}

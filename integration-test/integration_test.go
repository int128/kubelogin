package integration

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/int128/kubelogin/cli"
)

type configuration struct {
	Issuer string
}

func Test(t *testing.T) {
	conf := configuration{
		Issuer: "http://localhost:9000",
	}
	authServer := &http.Server{
		Addr:    "localhost:9000",
		Handler: NewAuthHandler(conf.Issuer),
	}
	defer authServer.Shutdown(context.Background())
	kubeconfig := createKubeconfig(t, conf.Issuer)
	defer os.Remove(kubeconfig)

	go func() {
		if err := authServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		res, err := http.Get("http://localhost:8000/")
		if err != nil {
			t.Error(err)
		}
		if res.StatusCode != 200 {
			t.Errorf("StatusCode wants 200 but %d: res=%+v", res.StatusCode, res)
		}
	}()
	c := cli.CLI{KubeConfig: kubeconfig}
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(b), "id-token: ey") == -1 {
		t.Errorf("kubeconfig wants id-token but %s", string(b))
	}
	if strings.Index(string(b), "refresh-token: 44df4c82-5ce7-4260-b54d-1da0d396ef2a") == -1 {
		t.Errorf("kubeconfig wants refresh-token but %s", string(b))
	}
}

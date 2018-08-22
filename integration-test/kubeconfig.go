package integration

import (
	"html/template"
	"io/ioutil"
	"log"
	"testing"
)

func createKubeconfig(t *testing.T, issuer string) string {
	t.Helper()
	f, err := ioutil.TempFile("", "kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tpl, err := template.ParseFiles("testdata/kubeconfig.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Execute(f, struct{ Issuer string }{issuer}); err != nil {
		t.Fatal(err)
	}
	log.Printf("Created %s", f.Name())
	return f.Name()
}

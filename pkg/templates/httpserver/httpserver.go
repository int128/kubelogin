package main

import (
	"log"
	"net/http"

	"github.com/int128/kubelogin/pkg/templates"
)

func main() {
	http.HandleFunc("/AuthCodeBrowserSuccessHTML", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "text/html")
		_, _ = w.Write([]byte(templates.AuthCodeBrowserSuccessHTML))
	})
	log.Printf("http://localhost:8000/AuthCodeBrowserSuccessHTML")
	log.Fatal(http.ListenAndServe("127.0.0.1:8000", nil))
}

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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "text/html")
		_, _ = w.Write([]byte(`
<html>
<body>
<ul>
<li><a href="AuthCodeBrowserSuccessHTML">AuthCodeBrowserSuccessHTML</a></li>
</ul>
</body>
</html>
`))
	})
	log.Printf("http://localhost:8000")
	log.Fatal(http.ListenAndServe("127.0.0.1:8000", nil))
}

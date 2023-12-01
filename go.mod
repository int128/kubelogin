module github.com/pipedrive/kubelogin

go 1.15

require (
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/go-test/deep v1.0.4
	github.com/golang-jwt/jwt/v4 v4.4.1
	github.com/golang/mock v1.4.4
	github.com/google/wire v0.3.0
	github.com/pipedrive/oauth2cli v1.8.2-pipedrive.0.20211027140131-4b9ebd5614fa
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.18.0 // indirect
	golang.org/x/oauth2 v0.0.0-20211005180243-6b3c2da341f1
	golang.org/x/sync v0.1.0
	golang.org/x/term v0.15.0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gopkg.in/square/go-jose.v2 v2.4.0 // indirect
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/apimachinery v0.17.16
	k8s.io/client-go v0.17.16
	k8s.io/klog v1.0.0
)

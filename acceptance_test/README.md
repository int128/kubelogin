# acceptance_test

This is an acceptance test for verifying behavior of kubelogin
using a real Kubernetes cluster and OpenID Connect provider.

TODO: components diagram


## How it works

It performs the following steps:

1. Create a Kubernetes cluster using Kind.
1. Get the CA certificate from the cluster.
1. Generate a TLS server certificate for the Dex.
1. Deploy the Dex.
1. Deploy the cluster role binding.
1. Import the CA certificate for Chromium.
1. Run the test.


## Technical consideration

### Network and DNS

Constraints:

- kube-apiserver runs on the host network.
- kube-apiserver cannot resolve a service name by kube-dns, e.g. `server.dex.svc.cluster.local`.
- kube-apiserver cannot access a cluster IP.
- Chromium requires exactly match of domain name between Dex URL and a server certificate.

kube-apiserver accesses Dex via the following route:

```
kube-apiserver
↓
kind-control-plane:30443 (host port)
↓
dex-service:30443 (node port)
↓
dex-pod-container:30443 (pod container port)
```

### TLS server certificate

Constraints:

- kube-apiserver requires `--oidc-issuer` is HTTPS URL.
- kube-apiserver requires a CA certificate file at startup, if `--oidc-ca-file` is given.
- It is not possible to put a file into kube-apiserver at startup.
- It is not possible to issue a server certificate using Let's Encrypt on CI.
- Chromium requires a valid certificate.

Solutions:

- Generate a server certificate signed by the CA of the cluster.
- Set the server certificate to Dex.
- Set the CA certificate to kube-apiserver.
- Set the CA certificate to Chromium.

### Test

It need to concurrently run `kubectl` and open the browser.


## Run locally

You need to set up Docker and Kind.

```shell script
# run the test
make

# clean up
make delete-cluster
```

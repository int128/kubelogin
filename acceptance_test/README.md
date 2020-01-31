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

Technical considerations:

- Network
  - kube-apiserver runs on the host network.
- Kubernetes OpenID Connect authentication
  - Set the extra arguments to kube-apiserver, e.g. the issuer, client ID and secret.
    See [cluster.yaml](cluster.yaml).
- TLS server certificate
  - Kubernetes requires that an issuer has HTTPS scheme.
- Chromium
- TODO: more


## Run locally

You need to set up Docker and Kind.

Run the test:

```shell script
make
```

Delete the cluster:

```shell script
make delete-cluster
```

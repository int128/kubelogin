# acceptance_test

This is an acceptance test for verifying behavior of kubelogin
using a real Kubernetes cluster and OpenID Connect provider.

TODO: components diagram


## How it works

The acceptance test is performed by the following steps:

1. Create a Kubernetes cluster using Kind.
1. Get the CA key pair from the cluster.
1. Generate a TLS server certificate for the Dex.
1. Deploy the Dex.
1. Deploy the cluster role binding.
1. Import the CA certificate for Chromium.
1. Run the test.

Technical issues:

- Kubernetes OpenID Connect authentication
  - It sets the extra arguments to Kubernetes API server, e.g. the issuer, client ID and secret.
    See [cluster.yaml](cluster.yaml).
- TLS server certificate
  - Kubernetes requires that an issuer has HTTPS scheme.
- Chromium
- Network design
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

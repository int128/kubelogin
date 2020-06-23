# kubelogin/acceptance_test

This is a manual test for verifying Kubernetes OIDC authentication with your OIDC provider.


## Purpose

This test checks the following points:

1. You can set up your OIDC provider using [setup guide](../docs/setup.md).
1. The plugin works with your OIDC provider.


## Getting Started

### Prerequisite

You need to build the plugin into the parent directory.

```sh
make -C ..
```

You need to set up your provider.
See [setup guide](../docs/setup.md) for more.

You need to install the following tools:

- Docker
- Kind
- kubectl

You can check if the tools are available.

```sh
make check
```

### 1. Create a cluster

Create a cluster.
For example, you can create a cluster with Google account authentication.

```sh
make OIDC_ISSUER_URL=https://accounts.google.com \
  OIDC_CLIENT_ID=REDACTED.apps.googleusercontent.com \
  OIDC_CLIENT_SECRET=REDACTED \
  YOUR_EMAIL=REDACTED@gmail.com
```

It will do the following steps:

1. Create a cluster.
1. Set up access control. It allows read-only access from your email address.
1. Set up kubectl to enable the plugin.

You can change kubectl configuration in generated `output/kubeconfig.yaml`.

### 2. Run kubectl

Make sure you can log in to the provider and access the cluster.

```console
% export KUBECONFIG=$PWD/output/kubeconfig.yaml
% kubectl get pods -A
```

### Clean up

To delete the cluster and generated files:

```sh
make delete-cluster
make clean
```

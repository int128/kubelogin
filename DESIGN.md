# Design of kubelogin

This explains design of kubelogin.

## Use cases

Kubelogin is a command line tool and designed to run as both a standalone command and a kubectl plugin.

It respects the following flags, commonly used in kubectl:

```
      --kubeconfig string              Path to the kubeconfig file
      --context string                 The name of the kubeconfig context to use
      --user string                    The name of the kubeconfig user to use. Prior to --context
      --certificate-authority string   Path to a cert file for the certificate authority
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  -v, --v int                          If set to 1 or greater, it shows debug log
```

As well as it respects the environment variable `KUBECONFIG`.


### Login by the command

TODO

### Wrap kubectl and login transparently

TODO


## Architecture

Kubelogin consists of the following layers:

- `usecases`: This provides the use-cases.
- `adaptor`: This provides external access and converts objects between the use-cases and external system.


### Use-cases

This provides the use-cases mentioned in the previous section.

This layer should not contain external access such as HTTP requests and system calls.


### Adaptor

This provides external access such as command line interface and HTTP requests.



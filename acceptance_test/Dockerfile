FROM alpine:3.11

RUN apk add --update ttf-freefont chromium
RUN apk add nss-tools
# https://kubernetes.io/docs/tasks/tools/install-kubectl/
RUN wget -O /usr/local/bin/kubectl "https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl" && \
    chmod +x /usr/local/bin/kubectl && \
    kubectl version --client

# run as a dedicated user
RUN adduser -D -h /runner runner

COPY output/kubelogin_linux_amd64 /usr/local/bin/kubectl-oidc_login

COPY kubeconfig_oidc.yaml /runner/
COPY output/kubeconfig.yaml /runner/output/
COPY output/ca.crt /runner/output/

COPY output/kubelogin_acceptance_test_linux_amd64 /usr/local/bin/kubelogin_acceptance_test_linux_amd64

RUN chown -R runner:runner /runner
USER runner
WORKDIR /runner

# import the CA certificate for chromium
RUN mkdir -p .pki/nssdb && \
    certutil -A -d sql:.pki/nssdb -n kubernetes -i output/ca.crt -t "TC,,"

CMD ["kubelogin_acceptance_test_linux_amd64", "-test.v"]

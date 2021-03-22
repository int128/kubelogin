FROM gcr.io/distroless/base-debian10
COPY kubelogin /
ENTRYPOINT ["/kubelogin"]

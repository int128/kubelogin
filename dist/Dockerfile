FROM alpine:3.11

ARG KUBELOGIN_VERSION="{{ env "VERSION" }}"
ARG KUBELOGIN_SHA256="{{ sha256 .linux_amd64_archive }}"

# Download the release and test the checksum
RUN wget -O /kubelogin.zip "https://github.com/int128/kubelogin/releases/download/$KUBELOGIN_VERSION/kubelogin_linux_amd64.zip" && \
    unzip /kubelogin.zip && \
    rm /kubelogin.zip && \
    echo "$KUBELOGIN_SHA256  /kubelogin" | sha256sum -c -

USER daemon
ENTRYPOINT ["/kubelogin"]

FROM golang:1.16 as builder

WORKDIR /builder
COPY go.* .
RUN go mod download
COPY Makefile .
COPY main.go .
COPY pkg pkg
ARG VERSION
RUN make VERSION=$VERSION

FROM gcr.io/distroless/base-debian10
COPY --from=builder /builder/kubelogin /
ENTRYPOINT ["/kubelogin"]

FROM golang:1.21 as builder

WORKDIR /builder
COPY go.* .
RUN go mod download
COPY main.go .
COPY pkg pkg
RUN go build

FROM gcr.io/distroless/base-debian12
COPY --from=builder /builder/kubelogin /
ENTRYPOINT ["/kubelogin"]

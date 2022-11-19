FROM golang:1.19 as builder

WORKDIR /builder
COPY go.* .
RUN go mod download
COPY main.go .
COPY pkg pkg
RUN go build

FROM gcr.io/distroless/base-debian10
COPY --from=builder /builder/kubelogin /
ENTRYPOINT ["/kubelogin"]

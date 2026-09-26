FROM --platform=$BUILDPLATFORM golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

WORKDIR /builder

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy the go source
COPY main.go .
COPY pkg pkg

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build

FROM gcr.io/distroless/base-debian12
COPY --from=builder /builder/kubelogin /
ENTRYPOINT ["/kubelogin"]

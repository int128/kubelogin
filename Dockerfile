FROM --platform=$BUILDPLATFORM golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a AS builder

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

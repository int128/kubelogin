FROM --platform=$BUILDPLATFORM golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS builder

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

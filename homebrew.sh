#!/bin/bash -xe

dist_bin="$1"
dist_sha256=$(shasum -a 256 -b "$dist_bin" | cut -f1 -d' ')

cat <<EOF
class Kubelogin < Formula
  desc "A kubectl plugin for Kubernetes OpenID Connect authentication"
  homepage "https://github.com/int128/kubelogin"
  url "https://github.com/int128/kubelogin/releases/download/${CIRCLE_TAG}/kubelogin_darwin_amd64"
  version "${CIRCLE_TAG}"
  sha256 "${dist_sha256}"
  def install
    bin.install "kubelogin_darwin_amd64" => "kubelogin"
    ln_s bin/"kubelogin", bin/"kubectl-oidc_login"
  end
  test do
    system "#{bin}/kubelogin -h"
    system "#{bin}/kubectl-oidc_login -h"
  end
end
EOF

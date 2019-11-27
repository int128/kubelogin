class Kubelogin < Formula
  desc "A kubectl plugin for Kubernetes OpenID Connect authentication"
  homepage "https://github.com/pipedrive/kubelogin"
  url "https://github.com/pipedrive/kubelogin/releases/download/{{ env "VERSION" }}/kubelogin_darwin_amd64.zip"
  version "{{ env "VERSION" }}"
  sha256 "{{ sha256 .darwin_amd64_archive }}"
  def install
    bin.install "kubelogin" => "kubelogin"
    ln_s bin/"kubelogin", bin/"kubectl-oidc_login"
  end
  test do
    system "#{bin}/kubelogin -h"
    system "#{bin}/kubectl-oidc_login -h"
  end
end

class Kubelogin < Formula
  desc "A kubectl plugin for Kubernetes OpenID Connect authentication"
  homepage "https://github.com/int128/kubelogin"
  url "https://github.com/int128/kubelogin/releases/download/{{ env "VERSION" }}/kubelogin_darwin_amd64.zip"
  version "{{ env "VERSION" }}"
  sha256 "{{ .darwin_amd64_zip_sha256 }}"
  def install
    bin.install "kubelogin_darwin_amd64" => "kubelogin"
    ln_s bin/"kubelogin", bin/"kubectl-oidc_login"
  end
  test do
    system "#{bin}/kubelogin -h"
    system "#{bin}/kubectl-oidc_login -h"
  end
end

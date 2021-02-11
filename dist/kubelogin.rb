class Kubelogin < Formula
  desc "A kubectl plugin for Kubernetes OpenID Connect authentication"
  homepage "https://github.com/int128/kubelogin"
  version "{{ env "VERSION" }}"

  on_macos do
    url "https://github.com/int128/kubelogin/releases/download/{{ env "VERSION" }}/kubelogin_darwin_amd64.zip"
    sha256 "{{ sha256 .darwin_amd64_archive }}"
  end
  on_linux do
    url "https://github.com/int128/kubelogin/releases/download/{{ env "VERSION" }}/kubelogin_linux_amd64.zip"
    sha256 "{{ sha256 .linux_amd64_archive }}"
  end

  def install
    bin.install "kubelogin" => "kubelogin"
    ln_s bin/"kubelogin", bin/"kubectl-oidc_login"
  end

  test do
    system "#{bin}/kubelogin -h"
    system "#{bin}/kubectl-oidc_login -h"
  end
end

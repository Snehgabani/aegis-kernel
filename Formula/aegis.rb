class Aegis < Formula
  desc "Deterministic tool-call clearance gateway for autonomous AI agents"
  homepage "https://github.com/Snehgabani/aegis-kernel"
  url "https://registry.npmjs.org/@aegis-kernel/cli/-/cli-1.0.0.tgz"
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  license "MIT"

  depends_on "node@20"

  def install
    system "npm", "install", *Language::Node.std_npm_install_args(libexec)
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    system "#{bin}/aegis", "--version"
  end
end

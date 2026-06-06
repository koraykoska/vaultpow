# Homebrew formula for vaultpow.
#
# This file is the formula for the *self-hosted tap* shipped from
# github.com/koraykoska/vaultpow. Install via:
#
#   brew tap koraykoska/vaultpow https://github.com/koraykoska/vaultpow
#   brew install vaultpow
#
# (`brew tap user/<name> URL` is the form that lets a tap live in a repo
# whose name doesn't start with `homebrew-`. After tapping, the formula is
# resolvable as plain `vaultpow`, or fully qualified as
# `koraykoska/vaultpow/vaultpow`.)
#
# The version + sha256 lines below are bumped automatically by the
# `update-formula` job in .github/workflows/release.yml after each release
# tag is published.

class Vaultpow < Formula
  desc "kubectx-style context switcher for HashiCorp Vault and OpenBao"
  homepage "https://github.com/koraykoska/vaultpow"
  version "0.1.4"
  license "MIT"

  # The trailing `# bump:<asset>` comments mark each sha256 line so the
  # release workflow's update-formula job can find and rewrite it
  # idempotently. Don't remove or reword the markers without updating
  # scripts/update-formula.sh in lockstep.

  on_macos do
    on_arm do
      url "https://github.com/koraykoska/vaultpow/releases/download/v#{version}/vaultpow-macos-arm64.tar.gz"
      sha256 "9913f2316aba2ae8f0d11393cdeca9f7242002e08ca1459d726bdf075bf1b746" # bump:macos-arm64
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/koraykoska/vaultpow/releases/download/v#{version}/vaultpow-linux-amd64.tar.gz"
      sha256 "0576fbd2135e897abb2c75fd47a6515a4e2b70580775153785910cc6781494ba" # bump:linux-amd64
    end
    on_arm do
      url "https://github.com/koraykoska/vaultpow/releases/download/v#{version}/vaultpow-linux-arm64.tar.gz"
      sha256 "79a6a0cd9ed19bb8ea0510530b3aabe71a2fa7966177e76e808f0032d8dd0d75" # bump:linux-arm64
    end
  end

  # No `depends_on` for `vault`/`bao`: neither is in Homebrew core, and
  # both live in separate taps (`hashicorp/tap` and `openbao/tap`) that
  # we don't want to force users to add. vaultpow's token probes and
  # renewals go through HTTP directly — the only paths that need a real
  # CLI are interactive logins (OIDC, userpass) and namespace management,
  # and the caveats below tell users how to get one when they need it.

  def install
    bin.install "vaultpow"

    # Generate and install shell completions in the standard brew-managed
    # locations. `generate_completions_from_executable` runs the binary at
    # install-time, captures its output, and writes to bash/zsh/fish
    # completion paths under the brew prefix. Brew handles uninstall too.
    generate_completions_from_executable(bin/"vaultpow", "completions")

    # NOTE on shell hook installation: we deliberately do NOT install the
    # zsh-init.sh / bash-init.sh files. They're embedded in the binary via
    # `include_str!`, so `vaultpow shell-init zsh|bash` always emits the
    # current snippet. Users add the eval line to their shell rc (see
    # caveats below); brew never modifies the user's rc files.
  end

  def caveats
    <<~EOS
      Add the shell hook to wrap `vault` AND `bao` with vaultpow:

        # zsh — append to ~/.zshrc
        echo 'eval "$(vaultpow shell-init zsh)"' >> ~/.zshrc

        # bash — append to ~/.bashrc (use `eval`, NOT `source <(…)`;
        # bash 3.2 on macOS drops functions loaded via process substitution)
        echo 'eval "$(vaultpow shell-init bash)"' >> ~/.bashrc

      Then reload your shell. The wrapped `vault`/`bao` commands will pick
      up the current cluster's address, namespace, and token automatically,
      and will renew or re-authenticate as tokens approach expiry.

      Get started:
        vaultpow add-cluster
        vaultpow auth
        vault kv get secret/foo     # or: bao kv get secret/foo

      Note: vaultpow itself has no runtime dependencies — token probes
      and renewals go through HTTP directly. The `vault` / `bao` CLI is
      only needed for interactive logins (OIDC, userpass) and namespace
      management. Install one when you need it:

        brew tap   hashicorp/tap
        brew install hashicorp/tap/vault

      OpenBao (https://openbao.org/docs/install/) is wire-compatible
      and works as a drop-in replacement.
    EOS
  end

  test do
    # The binary runs and reports its version.
    assert_match version.to_s, shell_output("#{bin}/vaultpow --version")

    # The shell-init subcommand emits a wrapper for both vault and bao.
    zsh_init = shell_output("#{bin}/vaultpow shell-init zsh")
    assert_match "vault()", zsh_init
    assert_match "bao()", zsh_init

    # Completions are generated successfully (exit code = 0 is enough).
    system bin/"vaultpow", "completions", "zsh"
  end
end

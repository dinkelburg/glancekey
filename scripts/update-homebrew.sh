#!/bin/zsh
# Points the Homebrew tap (github.com/dinkelburg/homebrew-<id>) at the release in build/downloads, which
# scripts/release.sh has just published:
#   brew install --cask dinkelburg/<id>/<id>       the Mac app
#   brew install dinkelburg/<id>/<id>-agent        the Linux program
set -euo pipefail
cd "${0:A:h}/.."
source scripts/brand.sh

downloads=build/downloads
work=build/homebrew-tap
checksum() { grep " $1\$" $downloads/SHA256SUMS | cut -d' ' -f1 }

rm -rf $work
gh repo clone dinkelburg/homebrew-$APP_ID $work -- --quiet
mkdir -p $work/Casks $work/Formula

cat > $work/Casks/$APP_ID.rb <<RUBY
cask "$APP_ID" do
  version "$VERSION"
  sha256 "$(checksum $APP_NAME-$VERSION.zip)"

  url "$DOWNLOADS/$APP_NAME-#{version}.zip"
  name "$APP_NAME"
  desc "Unlock your computer and approve sudo with Face ID on your iPhone"
  homepage "$WEBSITE/"

  livecheck do
    url "$DOWNLOADS/$APP_NAME.zip"
    strategy :extract_plist
  end

  depends_on macos: :sonoma

  app "$APP_NAME.app"

  uninstall quit: "$BUNDLE_ID.mac"

  zap trash: "~/Library/Preferences/$BUNDLE_ID.mac.plist"
end
RUBY

cat > $work/Formula/$APP_ID-agent.rb <<RUBY
class ${(C)APP_ID}Agent < Formula
  desc "Unlock your computer and approve sudo with Face ID on your iPhone"
  homepage "$WEBSITE/"
  version "$VERSION"

  if Hardware::CPU.arm?
    url "$DOWNLOADS/$APP_ID-agent-$VERSION-linux-arm64"
    sha256 "$(checksum $APP_ID-agent-$VERSION-linux-arm64)"
  else
    url "$DOWNLOADS/$APP_ID-agent-$VERSION-linux-amd64"
    sha256 "$(checksum $APP_ID-agent-$VERSION-linux-amd64)"
  end

  depends_on :linux

  def install
    bin.install Dir["$APP_ID-agent-*"].first => "$APP_ID-agent"
  end

  def caveats
    <<~EOS
      Start it with your session, then pair your iPhone:
        $APP_ID-agent install-service
        $APP_ID-agent set-password
        $APP_ID-agent pair
      After brew upgrade, run $APP_ID-agent install-service again.
      Docs: $WEBSITE/docs
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/$APP_ID-agent version")
  end
end
RUBY

cd $work
git add -A
if git diff --cached --quiet; then
  echo "The Homebrew tap already points at $VERSION."
  exit 0
fi
git commit -qm "$APP_NAME $VERSION"
git push -q
echo "Updated the Homebrew tap to $VERSION."

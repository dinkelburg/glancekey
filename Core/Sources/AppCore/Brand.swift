import Foundation

/// The app's name. To rename the app, change it here, in project.yml, linux/brand.go, relay/src/index.ts and
/// relay/wrangler.jsonc; scripts/check-brand.sh (part of scripts/test.sh) checks that they agree and that nothing
/// else spells it out. `name` is only what you see. `id` also names the URL scheme, keychain items and the files
/// and paths on the computers, so changing it means setting up again: pairing, and enable-sudo.
public enum Brand {
    public static let name = "GlanceKey"
    public static let id = "glancekey"
    public static let relay = URL(string: "https://relay.glancekey.com")!
    /// The relay we host, also under the address pairings from before 2026-10-26 use. Only computers on it have the
    /// App Store app's free limits (`FreeLimits`).
    public static let hostedRelayHosts: Set<String> = ["relay.glancekey.com", "glancekey.dinkelworks.nl"]
    public static let website = URL(string: "https://www.glancekey.com")!
    public static let download = website.appending(path: "download")
    public static let docs = website.appending(path: "docs")
    public static let privacyPolicy = website.appending(path: "privacy")

    public static let urlScheme = id

    public static func keychainService(_ item: String) -> String {
        "nl.dinkelworks.\(id).\(item)"
    }
}

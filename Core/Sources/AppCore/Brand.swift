import Foundation

/// The app's name. To rename the app, change it here, in project.yml, linux/brand.go, relay/src/index.ts and
/// relay/wrangler.jsonc; scripts/check-brand.sh (part of scripts/test.sh) checks that they agree and that nothing
/// else spells it out. `name` is only what you see. `id` also names the URL scheme, keychain items and the files
/// and paths on the computers, so changing it means setting up again: pairing, and enable-sudo.
public enum Brand {
    public static let name = "GlanceKey"
    public static let id = "glancekey"
    public static let relay = URL(string: "https://glancekey.dinkelworks.nl")!

    public static let urlScheme = id

    public static func keychainService(_ item: String) -> String {
        "nl.dinkelworks.\(id).\(item)"
    }
}

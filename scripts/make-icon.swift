// Renders the 1024×1024 app icons: a keyhole whose round part is an eye looking back at you.
// The same shape as site/public/logo.svg, in the same 1024-point coordinates (y down).
// Usage: swift scripts/make-icon.swift iOS/Assets.xcassets/AppIcon.appiconset
import AppKit

let folder = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
let size = 1024
let sRGB = CGColorSpace(name: CGColorSpace.sRGB)!

func color(_ hex: UInt32, alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

struct Palette {
    var background: [CGColor]?  // top-left to bottom-right; nil leaves it transparent for iOS to fill
    var keyhole, iris, pupil, glint: CGColor
}

func render(_ palette: Palette, to name: String) throws {
    let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: sRGB,
                            bitmapInfo: palette.background == nil ? CGImageAlphaInfo.premultipliedLast.rawValue
                                                                  : CGImageAlphaInfo.noneSkipLast.rawValue)!
    // Work in the SVG's coordinates: origin top left, y down.
    context.translateBy(x: 0, y: CGFloat(size))
    context.scaleBy(x: 1, y: -1)

    if let colors = palette.background {
        let gradient = CGGradient(colorsSpace: sRGB, colors: colors as CFArray, locations: [0, 1])!
        context.drawLinearGradient(gradient, start: .zero, end: CGPoint(x: size, y: size), options: [])
    }
    func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat, _ fill: CGColor) {
        context.setFillColor(fill)
        context.fillEllipse(in: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))
    }
    circle(512, 410, 200, palette.keyhole)
    context.setFillColor(palette.keyhole)
    context.addLines(between: [CGPoint(x: 432, y: 540), CGPoint(x: 592, y: 540), CGPoint(x: 650, y: 818), CGPoint(x: 374, y: 818)])
    context.fillPath()
    circle(512, 410, 118, palette.iris)
    circle(512, 410, 56, palette.pupil)
    circle(550, 372, 22, palette.glint)

    let png = NSBitmapImageRep(cgImage: context.makeImage()!).representation(using: .png, properties: [:])!
    try png.write(to: folder.appendingPathComponent(name))
    print("wrote \(name)")
}

// Light: white keyhole on the website's blue.
try render(Palette(background: [color(0x2b8cff), color(0x0a4fd6)], keyhole: color(0xffffff), iris: color(0x0a4fd6),
                   pupil: color(0x0b1424), glint: color(0xffffff)), to: "icon.png")
// Dark home screens: iOS draws the dark background; a brighter iris keeps the eye visible on it.
try render(Palette(background: nil, keyhole: color(0xffffff), iris: color(0x2b7fff), pupil: color(0x0b1424),
                   glint: color(0xffffff)), to: "icon-dark.png")
// Tinted home screens: grayscale, which iOS colours with the user's tint.
try render(Palette(background: nil, keyhole: color(0xffffff), iris: color(0x5a5a5a), pupil: color(0x141414),
                   glint: color(0xffffff)), to: "icon-tinted.png")

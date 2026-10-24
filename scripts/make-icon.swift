// Renders the 1024×1024 app icon: a blue gradient with the Face ID glyph.
// Usage: swift scripts/make-icon.swift <output.png>
import AppKit

let size = 1024
let output = CommandLine.arguments.dropFirst().first ?? "icon.png"
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: colorSpace, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!

let gradient = CGGradient(colorsSpace: colorSpace, colors: [
    CGColor(red: 0.16, green: 0.45, blue: 1.0, alpha: 1),
    CGColor(red: 0.42, green: 0.22, blue: 0.95, alpha: 1),
] as CFArray, locations: [0, 1])!
context.drawLinearGradient(gradient, start: CGPoint(x: 0, y: size), end: CGPoint(x: size, y: 0), options: [])

let configuration = NSImage.SymbolConfiguration(pointSize: 520, weight: .regular)
    .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))
if let symbol = NSImage(systemSymbolName: "faceid", accessibilityDescription: nil)?.withSymbolConfiguration(configuration) {
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    let symbolSize = symbol.size
    symbol.draw(in: NSRect(x: (CGFloat(size) - symbolSize.width) / 2, y: (CGFloat(size) - symbolSize.height) / 2,
                           width: symbolSize.width, height: symbolSize.height))
    NSGraphicsContext.restoreGraphicsState()
}

let png = NSBitmapImageRep(cgImage: context.makeImage()!).representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: output))
print("wrote \(output)")

import AppCore
import AppKit

/// The app icon's keyhole for the menu bar, as a template image so macOS draws it in the menu bar's own color. The
/// same shape as Mac/AppIcon.icon and site/public/logo.svg, in their 1024-point coordinates, with the iris cut out
/// so the eye still shows in one color.
enum MenuBarIcon {
    static let normal = image(alpha: 1)
    /// While this Mac can't be unlocked yet: not set up, or offline.
    static let dimmed = image(alpha: 0.4)

    private static func image(alpha: CGFloat) -> NSImage {
        let height: CGFloat = 16
        let scale = height / 608  // the keyhole runs from y 210 to 818, x 312 to 712
        let image = NSImage(size: NSSize(width: 400 * scale, height: height), flipped: true) { _ in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            context.scaleBy(x: scale, y: scale)
            context.translateBy(x: -312, y: -210)
            context.setAlpha(alpha)
            context.beginTransparencyLayer(auxiliaryInfo: nil)
            context.setFillColor(.black)
            func circle(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) {
                context.fillEllipse(in: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))
            }
            circle(512, 410, 200)
            context.addLines(between: [CGPoint(x: 432, y: 540), CGPoint(x: 592, y: 540), CGPoint(x: 650, y: 818), CGPoint(x: 374, y: 818)])
            context.fillPath()
            context.setBlendMode(.clear)
            circle(512, 410, 118)  // iris
            context.setBlendMode(.normal)
            circle(512, 410, 56)  // pupil
            context.setBlendMode(.clear)
            circle(550, 372, 22)  // glint
            context.endTransparencyLayer()
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = Brand.name
        return image
    }
}

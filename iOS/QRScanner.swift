import AppCore
import AVFoundation
import SwiftUI
import VisionKit

/// Scans the pairing code a computer shows, with Apple's scanner (VisionKit). The camera image stays on the iPhone:
/// only the code it reads is used, to pair. The Camera app and pasting the code work too.
struct QRScanButton: View {
    let onCode: (String) -> Void
    @State private var scanning = false
    @State private var cameraDenied = false

    /// No scanner in the simulator, or on an iPhone without one.
    static var isSupported: Bool { DataScannerViewController.isSupported }

    var body: some View {
        Button {
            Task { await start() }
        } label: {
            Label("Scan QR code", systemImage: "qrcode.viewfinder")
                .frame(maxWidth: .infinity, minHeight: 36)
        }
        .buttonStyle(.borderedProminent)
        .fullScreenCover(isPresented: $scanning) {
            NavigationStack {
                QRScanner { code in
                    scanning = false
                    onCode(code)
                }
                .ignoresSafeArea()
                .navigationTitle("Scan the pairing code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanning = false } }
                }
            }
        }
        .alert("Camera access is off", isPresented: $cameraDenied) {
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Allow \(Brand.name) to use the camera in Settings, or scan the code with the Camera app.")
        }
    }

    private func start() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: scanning = true
        case .notDetermined:
            if await AVCaptureDevice.requestAccess(for: .video) { scanning = true } else { cameraDenied = true }
        default: cameraDenied = true
        }
    }
}

/// The camera view. Calls `onCode` once, with the first pairing code it sees; other QR codes are ignored.
private struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        if !scanner.isScanning { try? scanner.startScanning() }
    }

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onCode: (String) -> Void
        private var found = false

        init(onCode: @escaping (String) -> Void) {
            self.onCode = onCode
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let barcode) in addedItems {
                guard !found, let text = barcode.payloadStringValue, PairingInvite(string: text) != nil else { continue }
                found = true
                dataScanner.stopScanning()
                onCode(text)
            }
        }
    }
}

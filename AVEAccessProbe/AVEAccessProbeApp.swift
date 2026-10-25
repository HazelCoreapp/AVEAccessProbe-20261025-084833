import SwiftUI
import UIKit
import Darwin
import VideoToolbox
import CoreVideo
import CoreMedia
import CoreFoundation

// A diagnostic app for the owner's iPhone. No kernel methods are invoked.
@main
struct AVEAccessProbeApp: App {
    @State private var report = "Choose a diagnostic below.\nBoth use normal operating-system interfaces; neither installs a jailbreak."
    @State private var encoding = false

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                VStack(alignment: .leading, spacing: 16) {
                    Text("AVE / VideoToolbox diagnostics")
                        .font(.title2.bold())
                    Text("Inspects available video encoders and the implementation IDs selected for H.264 / HEVC. All operations use documented video APIs; no exploits or firmware changes.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    ScrollView {
                        Text(report)
                            .font(.system(.footnote, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(12)
                    }
                    .background(Color(uiColor: .secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    Button("Identify video encoder (V3 NEW)") {
                        encoding = true
                        report = "Reading available video encoders and selected encoder IDs…"
                        DispatchQueue.global(qos: .userInitiated).async {
                            let result = VideoToolboxIdentityProbe.run()
                            DispatchQueue.main.async {
                                report = result
                                encoding = false
                            }
                        }
                    }
                    .disabled(encoding)
                    .buttonStyle(.borderedProminent)
                    Button("Run hardware encode test (V2)") {
                        encoding = true
                        report = "Running 2 normal hardware-video encode tests. Please wait…"
                        DispatchQueue.global(qos: .userInitiated).async {
                            let result = VideoToolboxProbe.run()
                            DispatchQueue.main.async {
                                report = result
                                encoding = false
                            }
                        }
                    }
                    .disabled(encoding)
                    .buttonStyle(.borderedProminent)
                    Button("Run original connection check (V1)") { report = AVEProbe.run() }
                        .disabled(encoding)
                        .buttonStyle(.bordered)
                    Button("Copy results") { UIPasteboard.general.string = report }
                        .buttonStyle(.bordered)
                }
                .padding()
                .navigationTitle("AVE Probe")
            }
        }
    }
}

enum AVEProbe {
    // The iOS SDK does not officially expose IOKit to ordinary App Store apps.
    // Dynamic symbol lookup allows a signed development app to *check* whether
    // the service interfaces are present and what error they return.
    private typealias ServiceMatching = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutableRawPointer?
    private typealias GetMatchingService = @convention(c) (UInt32, UnsafeMutableRawPointer?) -> UInt32
    private typealias OpenService = @convention(c) (UInt32, UInt32, UInt32, UnsafeMutablePointer<UInt32>?) -> Int32
    private typealias ReleaseObject = @convention(c) (UInt32) -> Int32
    private typealias CloseService = @convention(c) (UInt32) -> Int32

    static func run() -> String {
        var output: [String] = []
        output.append("AVE Access Probe 1.0 | read-only service check")
        output.append("OS: \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)")
        output.append("Hardware identifier: \(hardwareIdentifier())")
        output.append("")

        let path = "/System/Library/Frameworks/IOKit.framework/IOKit"
        guard let library = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            output.append("IOKit library not loadable in this process.")
            if let error = dlerror() {
                output.append("dlopen: \(String(cString: error))")
            }
            output.append("This is a runtime/OS restriction, not an exploitable result.")
            return output.joined(separator: "\n")
        }
        defer { dlclose(library) }

        func resolve<T>(_ symbol: String, as type: T.Type) -> T? {
            guard let address = dlsym(library, symbol) else { return nil }
            return unsafeBitCast(address, to: type)
        }

        guard let match: ServiceMatching = resolve("IOServiceMatching", as: ServiceMatching.self),
              let get: GetMatchingService = resolve("IOServiceGetMatchingService", as: GetMatchingService.self),
              let open: OpenService = resolve("IOServiceOpen", as: OpenService.self),
              let release: ReleaseObject = resolve("IOObjectRelease", as: ReleaseObject.self),
              let close: CloseService = resolve("IOServiceClose", as: CloseService.self) else {
            output.append("A required IOKit symbol is unavailable to this process.")
            return output.joined(separator: "\n")
        }
        output.append("IOKit symbols: available")

        // AppleAVE2Driver and AppleAVE2UserClient are class names recovered
        // from the user's actual iOS 18.7.9 AppleAVE2 binary.
        for className in ["AppleAVE2Driver", "AppleAVE2UserClient", "AppleAVE2"] {
            let matching = className.withCString { match($0) }
            guard matching != nil else {
                output.append("\(className): matching dictionary unavailable")
                continue
            }
            // 'get' consumes the CoreFoundation matching dictionary.
            let service = get(0, matching)
            guard service != 0 else {
                output.append("\(className): no visible matching service")
                continue
            }
            defer { _ = release(service) }
            output.append("\(className): matching service visible")

            var connection: UInt32 = 0
            // Only try the default user-client type (0). No external methods,
            // property setters, fuzzing, video commands or unsafe arguments.
            let result = open(service, mach_task_self_, 0, &connection)
            output.append("  IOServiceOpen(type=0): 0x\(String(UInt32(bitPattern: result), radix: 16))")
            if result == 0, connection != 0 {
                output.append("  SUCCESS: user-client connection can be opened.")
                _ = close(connection)
            } else {
                output.append("  No connection; access, type or driver state may prohibit it.")
            }
        }
        output.append("")
        output.append("A successful open is NOT kernel read/write or a jailbreak.")
        output.append("A missing service is NOT proof the driver isn't installed.")
        return output.joined(separator: "\n")
    }

    private static func hardwareIdentifier() -> String {
        var system = utsname()
        guard uname(&system) == 0 else { return "unknown" }
        return withUnsafeBytes(of: system.machine) { bytes in
            String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
}


// VIDEO TOOLBOX DIAGNOSTIC V2
// Uses the same standard iOS encoder APIs that ordinary camera/video applications use.
// In particular, this deliberately never sends malformed dimensions or low-level
// kernel commands, and never calls any IOConnect external method.
private final class EncodedFrameResult {
    private let lock = NSLock()
    private var callbackCount = 0
    private var successfulFrames = 0
    private var totalBytes = 0
    private var errors: [Int32] = []

    func received(status: OSStatus, sampleBuffer: CMSampleBuffer?) {
        lock.lock()
        defer { lock.unlock() }
        callbackCount += 1
        if status != noErr { errors.append(status) }
        if status == noErr, let sample = sampleBuffer,
           CMSampleBufferDataIsReady(sample),
           let block = CMSampleBufferGetDataBuffer(sample) {
            successfulFrames += 1
            totalBytes += CMBlockBufferGetDataLength(block)
        }
    }
    func summary() -> String {
        lock.lock()
        defer { lock.unlock() }
        return "outputCallbacks=\(callbackCount), framesEncoded=\(successfulFrames), encodedBytes=\(totalBytes), callbackErrors=\(errors)"
    }
}

private func videoToolboxOutput(_ refcon: UnsafeMutableRawPointer?,
                                _ sourceRefcon: UnsafeMutableRawPointer?,
                                _ status: OSStatus,
                                _ infoFlags: VTEncodeInfoFlags,
                                _ sampleBuffer: CMSampleBuffer?) {
    guard let refcon else { return }
    let collector = Unmanaged<EncodedFrameResult>.fromOpaque(refcon).takeUnretainedValue()
    collector.received(status: status, sampleBuffer: sampleBuffer)
}

enum VideoToolboxProbe {
    static func run() -> String {
        var lines = [
            "AVE Access Probe 2.0 | VideoToolbox hardware encoding test",
            "iOS \(UIDevice.current.systemVersion) | model \(UIDevice.current.model)",
            "Valid inputs only: one synthetic 640x480 black frame per codec.",
            "This tests Apple's PUBLIC VideoToolbox API, not an exploit.",
            ""
        ]
        lines.append(contentsOf: runOne(name: "H.264", codec: kCMVideoCodecType_H264))
        lines.append("")
        lines.append(contentsOf: runOne(name: "HEVC / H.265", codec: kCMVideoCodecType_HEVC))
        lines.append("")
        lines.append("IMPORTANT: hardware-accelerated encoding does not prove AppleAVE2 was the implementation used, or that an app can reach the suspected vulnerability.")
        lines.append("No direct AppleAVE2 user-client calls were attempted in this test.")
        return lines.joined(separator: "\n")
    }

    private static func runOne(name: String, codec: CMVideoCodecType) -> [String] {
        let width: Int32 = 640
        let height: Int32 = 480
        var lines = ["=== \(name) ==="]
        let state = EncodedFrameResult()
        let encoderSpec: [String: Any] = [
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String: true
        ]
        let pixelAttributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_32BGRA),
            kCVPixelBufferWidthKey as String: Int(width),
            kCVPixelBufferHeightKey as String: Int(height),
            kCVPixelBufferIOSurfacePropertiesKey as String: [:] as [String: Any]
        ]
        var session: VTCompressionSession?
        let createResult = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            width: width,
            height: height,
            codecType: codec,
            encoderSpecification: encoderSpec as CFDictionary,
            imageBufferAttributes: pixelAttributes as CFDictionary,
            compressedDataAllocator: nil,
            outputCallback: videoToolboxOutput,
            refcon: Unmanaged.passUnretained(state).toOpaque(),
            compressionSessionOut: &session
        )
        lines.append("VTCompressionSessionCreate (hardware required): OSStatus \(createResult)")
        guard createResult == noErr, let session else {
            lines.append("No hardware encoding session for this codec; nothing submitted.")
            return lines
        }
        defer { VTCompressionSessionInvalidate(session) }

        // Apple exposes a read-only indication of the chosen acceleration mode.
        var property: CFTypeRef?
        let propertyResult = VTSessionCopyProperty(
            session,
            key: kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
            allocator: kCFAllocatorDefault,
            valueOut: &property
        )
        if propertyResult == noErr, let property {
            if CFEqual(property, kCFBooleanTrue) {
                lines.append("UsingHardwareAcceleratedVideoEncoder: TRUE")
            } else if CFEqual(property, kCFBooleanFalse) {
                lines.append("UsingHardwareAcceleratedVideoEncoder: FALSE")
            } else {
                lines.append("Hardware property returned an unexpected value")
            }
        } else {
            lines.append("Hardware acceleration property unavailable (OSStatus \(propertyResult))")
        }

        let prepResult = VTCompressionSessionPrepareToEncodeFrames(session)
        lines.append("PrepareToEncodeFrames: OSStatus \(prepResult)")
        guard prepResult == noErr else { return lines }

        var pixelBuffer: CVPixelBuffer?
        let pixelResult = CVPixelBufferCreate(
            kCFAllocatorDefault, Int(width), Int(height),
            kCVPixelFormatType_32BGRA, pixelAttributes as CFDictionary,
            &pixelBuffer
        )
        lines.append("CVPixelBufferCreate: CVReturn \(pixelResult)")
        guard pixelResult == kCVReturnSuccess, let pixelBuffer else { return lines }
        let lockResult = CVPixelBufferLockBaseAddress(pixelBuffer, [])
        if lockResult == kCVReturnSuccess {
            if let address = CVPixelBufferGetBaseAddress(pixelBuffer) {
                memset(address, 0, CVPixelBufferGetBytesPerRow(pixelBuffer) * CVPixelBufferGetHeight(pixelBuffer))
            }
            CVPixelBufferUnlockBaseAddress(pixelBuffer, [])
        }
        var flags = VTEncodeInfoFlags()
        let encodeResult = VTCompressionSessionEncodeFrame(
            session,
            imageBuffer: pixelBuffer,
            presentationTimeStamp: CMTime(value: 0, timescale: 30),
            duration: CMTime(value: 1, timescale: 30),
            frameProperties: nil,
            sourceFrameRefcon: nil,
            infoFlagsOut: &flags
        )
        lines.append("EncodeFrame: OSStatus \(encodeResult)")
        let completion = VTCompressionSessionCompleteFrames(
            session, untilPresentationTimeStamp: CMTime.invalid
        )
        lines.append("CompleteFrames: OSStatus \(completion)")
        lines.append(state.summary())
        return lines
    }
}


// VIDEO TOOLBOX DIAGNOSTIC V3
// Uses only Apple's documented encoder-list / encoder-selection interfaces.
// IDs refer to VideoToolbox encoders; they do NOT expose a kernel driver
// call stack, user-client entitlement, or vulnerability reachability.
enum VideoToolboxIdentityProbe {
    static func run() -> String {
        var result = [
            "AVE Access Probe 3.0 | Encoder implementation IDs",
            "iOS \(UIDevice.current.systemVersion)",
            "Read-only VideoToolbox enumeration + safe session metadata",
            ""
        ]

        // Registered/available encoders (not necessarily the selected one).
        var available: CFArray?
        let listStatus = VTCopyVideoEncoderList(nil, &available)
        result.append("VTCopyVideoEncoderList: OSStatus \(listStatus)")
        if listStatus == noErr, let available {
            let count = CFArrayGetCount(available)
            result.append("Registered encoders: \(count)")
            if count > 0 {
                for index in 0..<min(count, 40) {
                    guard let entryPointer = CFArrayGetValueAtIndex(available, index) else { continue }
                    let entry = Unmanaged<CFDictionary>
                        .fromOpaque(UnsafeMutableRawPointer(mutating: entryPointer))
                        .takeUnretainedValue()
                    let name = field(entry, key: kVTVideoEncoderList_DisplayName)
                        ?? field(entry, key: kVTVideoEncoderList_EncoderName)
                        ?? "unknown"
                    let codec = field(entry, key: kVTVideoEncoderList_CodecName) ?? "unknown"
                    let identifier = field(entry, key: kVTVideoEncoderList_EncoderID) ?? "unavailable"
                    let hardware = field(entry, key: kVTVideoEncoderList_IsHardwareAccelerated) ?? "unavailable"
                    result.append("- \(name) [\(codec)]")
                    result.append("  ID: \(identifier)")
                    result.append("  Hardware flag: \(hardware)")
                }
            }
        } else {
            result.append("The current process/OS did not return an encoder list.")
        }

        for (name, codec) in [("H.264", kCMVideoCodecType_H264),
                              ("HEVC / H.265", kCMVideoCodecType_HEVC)] {
            result.append("")
            result.append("=== Selected \(name) implementation ===")
            let hardwareSpec: [String: Any] = [
                kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String: true
            ]
            var selectedID: CFString?
            let selectionStatus = VTCopySupportedPropertyDictionaryForEncoder(
                width: 640,
                height: 480,
                codecType: codec,
                encoderSpecification: hardwareSpec as CFDictionary,
                encoderIDOut: &selectedID,
                supportedPropertiesOut: nil
            )
            result.append("VTCopySupportedPropertyDictionaryForEncoder: OSStatus \(selectionStatus)")
            if let selectedID {
                result.append("Selected encoder ID (preflight): \(selectedID)")
            } else {
                result.append("Selected encoder ID (preflight): unavailable")
            }

            // Also ask the actual compression session for its selected encoder.
            var session: VTCompressionSession?
            let createStatus = VTCompressionSessionCreate(
                allocator: kCFAllocatorDefault,
                width: 640,
                height: 480,
                codecType: codec,
                encoderSpecification: hardwareSpec as CFDictionary,
                imageBufferAttributes: nil,
                compressedDataAllocator: nil,
                outputCallback: nil,
                refcon: nil,
                compressionSessionOut: &session
            )
            result.append("VTCompressionSessionCreate: OSStatus \(createStatus)")
            if createStatus == noErr, let session {
                var selectedProperty: CFTypeRef?
                let propertyStatus = VTSessionCopyProperty(
                    session,
                    key: kVTCompressionPropertyKey_EncoderID,
                    allocator: kCFAllocatorDefault,
                    valueOut: &selectedProperty
                )
                result.append("Session EncoderID property: OSStatus \(propertyStatus)")
                if propertyStatus == noErr, let selectedProperty {
                    result.append("Session encoder ID: \(selectedProperty)")
                } else {
                    result.append("Session encoder ID: unavailable")
                }
                VTCompressionSessionInvalidate(session)
            }
        }
        result.append("")
        result.append("NOTE: Identifiers do not prove AppleAVE2 is the backing driver or that a vulnerable function is reachable.")
        result.append("No video frames, private kernel methods or exploit inputs were sent.")
        return result.joined(separator: "\n")
    }

    private static func field(_ dictionary: CFDictionary, key: CFString) -> String? {
        let rawKey = Unmanaged.passUnretained(key).toOpaque()
        guard let rawValue = CFDictionaryGetValue(dictionary, rawKey) else { return nil }
        let value = Unmanaged<AnyObject>
            .fromOpaque(UnsafeMutableRawPointer(mutating: rawValue))
            .takeUnretainedValue()
        return String(describing: value)
    }
}

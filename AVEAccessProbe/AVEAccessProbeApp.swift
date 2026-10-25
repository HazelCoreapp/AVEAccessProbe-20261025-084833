import SwiftUI
import UIKit
import Darwin

// A diagnostic app for the owner's iPhone. No kernel methods are invoked.
@main
struct AVEAccessProbeApp: App {
    @State private var report = "Tap Run connection check.\nNo firmware changes or exploit payloads will be sent."

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                VStack(alignment: .leading, spacing: 16) {
                    Text("AppleAVE2 connection check")
                        .font(.title2.bold())
                    Text("Tests whether an ordinary sandboxed app can locate and open Apple's video encoder driver. It does not jailbreak the phone.")
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
                    Button("Run connection check") { report = AVEProbe.run() }
                        .buttonStyle(.borderedProminent)
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

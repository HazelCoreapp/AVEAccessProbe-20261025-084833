# AVE Access Probe — iPhone XS Max / iOS 18.7.9

This is a **real SwiftUI iPhone diagnostic app** that checks whether a normal, sandboxed iOS app can find/open the `AppleAVE2Driver` service. It does **not** jailbreak the phone, modify the kernel, fuzz video commands, or call any IOConnect external method.

## What is supplied

- Real Swift source (`AVEAccessProbe/AVEAccessProbeApp.swift`)
- XcodeGen project (`project.yml`)
- GitHub Actions build that compiles an unsigned IPA on an Apple-hosted macOS runner (`.github/workflows/build-ipa.yml`)
- Optional Windows PowerShell helper (`BUILD-ON-WINDOWS.ps1`)

**Why not an IPA in this ZIP?** Compiling a signed, iOS-compatible binary requires Apple's SDK or a compatible iOS cross toolchain. The included GitHub Actions workflow does that using Xcode without charging for a public repository's standard hosted build. I haven't executed that remote build or tested the app on your iPhone.

## Fastest path with Windows 11 (no Mac, no paid developer account)

1. Unzip. Right-click `BUILD-ON-WINDOWS.ps1` → Run with PowerShell, or from PowerShell run `powershell -NoProfile -ExecutionPolicy Bypass -File .\BUILD-ON-WINDOWS.ps1` inside the extracted folder.
2. The helper uses **GitHub CLI** and **Git**; it offers to install them with `winget` only if missing. Browser sign-in to a *free* GitHub account is required. It creates a **public** GitHub repository containing only the code in this package, triggers the macOS build, and downloads the unsigned `.ipa` to a `build-output` folder.
3. Use [Sideloadly](https://sideloadly.io/) for Windows to sign/install the `.ipa` with your free Apple account over USB, or another trusted free IPA signing tool. Signing is necessary to launch the app on stock iOS. Enable Developer Mode/trust the profile on the phone if prompted. **Do not give your Apple ID password to anyone in chat.**
4. Launch **AVE Access Probe** on the iPhone, press **Run connection check**, then **Copy results**. Share only the result text, not a serial number or Apple ID.

If you already have a Mac with Xcode installed, run `brew install xcodegen && xcodegen generate`, and then build the project normally with your personal signing team.

## Interpreting results

- `IOKit library not loadable` → runtime restriction or unavailable library; not a vulnerability.
- `no visible matching service` → IOKit service not visible by that class name; does not prove driver absent.
- `IOServiceOpen(type=0): 0x...` → record this exact return code; the driver may enforce sandbox restrictions or require a different type.
- `SUCCESS` → an ordinary app can open an IOKit connection. **This is not yet a kernel exploit or jailbreak.**

The app only opens and immediately closes a default (type 0) connection. It never writes video payloads, triggers out-of-bounds dimensions, or requests kernel privileges.

## Build / signing notes

- Target: iPhoneOS 16.0+, arm64 (including A12 on iOS 18.7.9)
- GitHub's macOS runner will create an **unsigned IPA**. Sideloadly signs it for your individual phone with your Apple account.
- Apple's free sideload signatures usually expire after 7 days. No payment is required.
- Keeping the repository public means all its source code is visible; this package contains no private iPhone information.

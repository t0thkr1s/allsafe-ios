import SwiftUI

struct JailbreakDetectionView: View {
    @State private var detectionResult: String = ""
    @State private var isDetectionInProgress = false
    @State private var showSuccessDialog = false
    
    var body: some View {
        VStack(spacing: 24) {
            JailbreakChallengeHeaderView()
            JailbreakMissionBriefingView()
            JailbreakDetectionPortalView(
                detectionResult: $detectionResult,
                isDetectionInProgress: $isDetectionInProgress,
                detectAction: performJailbreakDetection
            )
            
            Spacer()
        }
        .padding()
        .background(Color.black)
        .alert("Jailbreak Detection Bypassed!", isPresented: $showSuccessDialog) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("FLAG{jailbreak_detection_bypassed_j4il}")
        }
    }
    
    private func performJailbreakDetection() {
        isDetectionInProgress = true
        detectionResult = ""
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            isDetectionInProgress = false
            
            if isJailbroken() {
                detectionResult = "[ALERT] JAILBREAK DETECTED! Device security compromised."
            } else {
                detectionResult = "[SUCCESS] Device appears to be secure. No jailbreak detected."
                showSuccessDialog = true
            }
        }
    }
    
    private func isJailbroken() -> Bool {
        // Skip detection in simulator for testing purposes
        #if targetEnvironment(simulator)
        return false
        #else
        // Multiple jailbreak detection methods
        return checkSuspiciousApps() || 
               checkSuspiciousPaths() || 
               checkSuspiciousSchemes() ||
               checkWriteAccess()
        #endif
    }
    
    private func checkSuspiciousApps() -> Bool {
        let suspiciousApps = [
            "cydia://", "sileo://", "zbra://", "undecimus://",
            "checkra1n://", "taurine://", "odyssey://"
        ]
        
        for app in suspiciousApps {
            if let url = URL(string: app), UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return false
    }
    
    private func checkSuspiciousPaths() -> Bool {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/libexec/ssh-keysign",
            "/bin/bash",
            "/etc/apt"
        ]
        
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    private func checkSuspiciousSchemes() -> Bool {
        let schemes = ["cydia", "sileo", "zbra", "filza", "activator"]
        for scheme in schemes {
            if let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return false
    }
    
    private func checkWriteAccess() -> Bool {
        // Try to write to restricted directories that should not be writable on non-jailbroken devices
        let restrictedPaths = [
            "/private/test_jailbreak.txt",
            "/var/mobile/test_jailbreak.txt",
            "/etc/test_jailbreak.txt"
        ]
        
        for testPath in restrictedPaths {
            do {
                try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
                try? FileManager.default.removeItem(atPath: testPath)
                return true // If we can write to any restricted path, it's likely jailbroken
            } catch {
                // Expected behavior on non-jailbroken devices
                continue
            }
        }
        return false
    }
}

struct JailbreakChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE 07]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)
            
            Text("JAILBREAK DETECTION BYPASS")
                .font(.system(size: 18, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
            
            Rectangle()
                .fill(Color.green)
                .frame(height: 1)
                .frame(maxWidth: 250)
        }
    }
}

struct JailbreakMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("This application implements comprehensive jailbreak detection mechanisms to prevent execution on compromised devices. The detection logic checks for suspicious applications, file paths, URL schemes, and write permissions that indicate a jailbroken environment.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)
            
            Text("\nDETECTION METHODS:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.yellow)
            
            VStack(alignment: .leading, spacing: 4) {
                Text("• Suspicious app detection (Cydia, Sileo, etc.)")
                Text("• Jailbreak file path verification")
                Text("• Custom URL scheme checks")
                Text("• Root filesystem write access tests")
            }
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.gray)
            
            Text("\nTARGET: Use Frida to hook the jailbreak detection method or try other alternatives.")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(.yellow)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.green, lineWidth: 1)
                .background(Color.black.opacity(0.3))
        )
    }
}

struct JailbreakDetectionPortalView: View {
    @Binding var detectionResult: String
    @Binding var isDetectionInProgress: Bool
    let detectAction: () -> Void
    
    var body: some View {
        VStack(spacing: 16) {
            Text("JAILBREAK DETECTION PORTAL")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            VStack(spacing: 12) {
                Button(action: detectAction) {
                    HStack {
                        if isDetectionInProgress {
                            ProgressView()
                                .scaleEffect(0.8)
                                .progressViewStyle(CircularProgressViewStyle(tint: .black))
                        }
                        Text(isDetectionInProgress ? "[SCANNING DEVICE...]" : "[RUN JAILBREAK DETECTION]")
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.black)
                    }
                }
                .disabled(isDetectionInProgress)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Color.green)
                .cornerRadius(0)
                
                if !detectionResult.isEmpty {
                    Text(detectionResult)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundColor(detectionResult.contains("ALERT") ? .red : .green)
                        .multilineTextAlignment(.center)
                        .padding(.top, 8)
                }
            }
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.gray, lineWidth: 1)
                .background(Color.black.opacity(0.2))
        )
    }
}

#Preview {
    JailbreakDetectionView()
}

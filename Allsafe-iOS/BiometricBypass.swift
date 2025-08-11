//
//  BiometricBypassChallengeView.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 11.
//

import SwiftUI
import LocalAuthentication
import CryptoKit

struct BiometricBypassChallengeView: View {
    @State private var isAuthenticated: Bool = false
    @State private var statusMessage: String = ""
    @State private var showFlagDialog: Bool = false
    @State private var authenticationAttempts: Int = 0
    
    // Simple obfuscated flag - no complex encoding needed
    private let obfuscatedFlag = "GMBH|c21n4us2d_5bvui_czq5tt4e_x2ui_gs2e5~"
    
    var body: some View {
        VStack(spacing: 24) {
            BiometricChallengeHeaderView()
            BiometricMissionBriefingView()
            
            BiometricActionPanel(
                authenticateAction: {
                    performBiometricAuthentication()
                },
                isAuthenticated: isAuthenticated
            )
            
            if !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(authenticationAttempts > 0 ? .red : .yellow)
                    .padding(.top, 4)
            }
            
            Spacer()
        }
        .padding()
        .background(Color.black)
        .alert("🏁 FLAG CAPTURED", isPresented: $showFlagDialog) {
                    Button("COPY FLAG") {
                        UIPasteboard.general.string = decryptFlag()
                        statusMessage = "Flag copied to clipboard!"
                    }
                    Button("CLOSE") {
                        showFlagDialog = false
                    }
                } message: {
                    Text(decryptFlag())
                        .font(.system(size: 14, design: .monospaced))
                }
    }
    
    private func decryptFlag() -> String {
        return String(obfuscatedFlag.compactMap { char in
            guard let ascii = char.asciiValue else { return char }
            return Character(UnicodeScalar(ascii - 1))
        })
    }
    
    
    private func performBiometricAuthentication() {
        let context = LAContext()
        var error: NSError?
        
        authenticationAttempts += 1
        statusMessage = "Checking biometric availability..."
        
        // First check for any biometric authentication
        let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
        
        guard context.canEvaluatePolicy(policy, error: &error) else {
            handleBiometricError(error: error)
            return
        }
        
        statusMessage = "Initiating biometric scan..."
        
        context.evaluatePolicy(
            policy,
            localizedReason: "Authenticate to access the classified flag"
        ) { [self] success, authenticationError in
            
            DispatchQueue.main.async {
                if success {
                    self.handleSuccessfulAuthentication()
                } else {
                    self.handleBiometricError(error: error)
                }
            }
        }
    }
    
    private func handleBiometricError(error: NSError?) {
        if let error = error as? LAError {
            switch error.code {
            case .biometryNotEnrolled:
                statusMessage = "⚠️ No biometrics enrolled. Go to Settings > Face ID & Passcode"
            case .biometryNotAvailable:
                statusMessage = "⚠️ Biometric authentication not supported on this device"
            case .biometryLockout:
                statusMessage = "⚠️ Biometrics locked. Use passcode to unlock"
            case .passcodeNotSet:
                statusMessage = "⚠️ Device passcode not set. Required for biometric auth"
            default:
                statusMessage = "⚠️ Biometric setup error: \(error.localizedDescription)"
            }
        } else {
            statusMessage = "⚠️ Unknown biometric configuration error"
        }
    }
    
    private func handleSuccessfulAuthentication() {
        isAuthenticated = true
        statusMessage = "✅ BIOMETRIC AUTHENTICATION SUCCESSFUL"
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.showFlagDialog = true
        }
    }
}

// Additional obfuscation - split the flag components
private extension BiometricBypassChallengeView {
    func getFlagPrefix() -> String {
        return String(bytes: [0x46, 0x4C, 0x41, 0x47], encoding: .utf8) ?? ""
    }
    
    func getFlagSuffix() -> String {
        return String(bytes: [0x7D], encoding: .utf8) ?? ""
    }
}

struct BiometricChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)
            
            Text("BIOMETRIC AUTHENTICATION BYPASS")
                .font(.system(size: 18, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
            
            Rectangle()
                .fill(Color.green)
                .frame(height: 1)
                .frame(maxWidth: 300)
        }
    }
}

struct BiometricMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("This application uses biometric authentication with additional security layers including anti-tampering checks and encrypted flag storage. The flag is not stored in plain text.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)
            
            Text("\nOBJECTIVE:")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
            
            Text("1. Bypass biometric authentication and validation layers\n2. Extract the encrypted flag through runtime manipulation\n3. Defeat anti-debugging measures if present")
                .font(.system(size: 12, design: .monospaced))
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

struct BiometricActionPanel: View {
    let authenticateAction: () -> Void
    let isAuthenticated: Bool
    
    var body: some View {
        VStack(spacing: 16) {
            Text("BIOMETRIC SECURITY GATE")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            VStack(spacing: 12) {
                Button(action: authenticateAction) {
                    HStack {
                        Image(systemName: isAuthenticated ? "checkmark.shield.fill" : "faceid")
                            .foregroundColor(.white)
                        Text(isAuthenticated ? "[AUTHENTICATED]" : "[AUTHENTICATE]")
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.white)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(isAuthenticated ? Color.green : Color.blue)
                .cornerRadius(0)
                .disabled(isAuthenticated)
                
                Text("Face ID / Touch ID Required")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.gray)
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
    BiometricBypassChallengeView()
}

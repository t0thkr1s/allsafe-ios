import SwiftUI
import Foundation

// SSL Pinning challenge view
struct SSLPinningBypassView: View {
    @State private var requestResult: String = ""
    @State private var isRequestInProgress = false
    @State private var showSuccessDialog = false
    
    var body: some View {
        VStack(spacing: 24) {
            SSLPinningChallengeHeaderView()
            SSLPinningMissionBriefingView()
            SSLPinningTestPortalView(
                requestResult: $requestResult,
                isRequestInProgress: $isRequestInProgress,
                requestAction: performSecureRequest
            )
            
            Spacer()
        }
        .padding()
        .background(Color.black)
        .alert("SSL Pinning Bypassed!", isPresented: $showSuccessDialog) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("FLAG{ssl_pinning_bypass_success_h4ck}")
        }
    }
    
    private func performSecureRequest() {
        isRequestInProgress = true
        requestResult = ""
        
        // Simulate network request with SSL pinning
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            isRequestInProgress = false
            
            let result = makeSecureAPICall()
            
            if result.success {
                requestResult = "[SUCCESS] Connection established! Data retrieved: \(result.data)"
                showSuccessDialog = true
            } else {
                requestResult = "[FAILED] \(result.error)"
            }
        }
    }
    
    private func makeSecureAPICall() -> (success: Bool, data: String, error: String) {
        // Simulate SSL pinning validation
        let isPinningBypassed = isSSLPinningBypassed()
        
        if isPinningBypassed {
            return (true, "{'flag':'FLAG{ssl_pinning_bypass_success_h4ck}','user':'admin','token':'abc123'}", "")
        } else {
            return (false, "", "SSL Certificate validation failed. Connection blocked by SSL Pinning.")
        }
    }
    
    private func isSSLPinningBypassed() -> Bool {
        // This method implements SSL certificate pinning validation
        // In a real scenario, this would check the server's certificate against pinned certificates
        // For the challenge, we'll simulate that SSL pinning is active and blocks the connection
        
        #if targetEnvironment(simulator)
        // In simulator, we can simulate the bypass being successful for testing
        return false // Change to true to test success flow
        #else
        // On real device, this would normally return false until bypassed with Frida
        return validateCertificatePinning()
        #endif
    }
    
    private func validateCertificatePinning() -> Bool {
        // Simulated certificate pinning logic
        // This would normally involve checking server certificates against pinned public keys
        let pinnedCertificateHashes = [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake pinned cert hash
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  // Another fake pinned cert hash
        ]
        
        // In a real implementation, this would:
        // 1. Get the server's certificate during TLS handshake
        // 2. Calculate the certificate's hash
        // 3. Compare against pinned hashes
        // 4. Return true only if there's a match
        
        // For this challenge, we simulate that pinning is active and blocks requests
        return false
    }
}

struct SSLPinningChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)
            
            Text("SSL PINNING BYPASS")
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

struct SSLPinningMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("This application implements SSL Certificate Pinning to prevent man-in-the-middle attacks. The app validates server certificates against pre-pinned public keys, blocking connections to servers with untrusted certificates - including proxy tools like Burp Suite.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)
            
            Text("\nSSL PINNING PROTECTION:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.yellow)
            
            VStack(alignment: .leading, spacing: 4) {
                Text("• Certificate hash validation")
                Text("• Public key pinning verification") 
                Text("• TLS handshake integrity checks")
                Text("• Proxy detection and blocking")
            }
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.gray)
            
            Text("\nTARGET: Bypass SSL pinning to intercept HTTPS traffic")
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

struct SSLPinningTestPortalView: View {
    @Binding var requestResult: String
    @Binding var isRequestInProgress: Bool
    let requestAction: () -> Void
    
    var body: some View {
        VStack(spacing: 16) {
            Text("BACKEND API CALL CHECK")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            VStack(spacing: 12) {
                Button(action: requestAction) {
                    HStack {
                        if isRequestInProgress {
                            ProgressView()
                                .scaleEffect(0.8)
                                .progressViewStyle(CircularProgressViewStyle(tint: .black))
                        }
                        Text(isRequestInProgress ? "[CONNECTING...]" : "[MAKE SECURE REQUEST]")
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.black)
                    }
                }
                .disabled(isRequestInProgress)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Color.green)
                .cornerRadius(0)
                
                if !requestResult.isEmpty {
                    ScrollView {
                        Text(requestResult)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(requestResult.contains("SUCCESS") ? .green : .red)
                            .multilineTextAlignment(.leading)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 120)
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 0)
                            .stroke(Color.gray, lineWidth: 1)
                            .background(Color.black.opacity(0.5))
                    )
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

// Compatibility alias for the routing
typealias SSLPinningBypassChallengeView = SSLPinningBypassView

#Preview {
    SSLPinningBypassView()
}

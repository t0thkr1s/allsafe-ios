//
//  HardcodedSecrets.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 10..
//

import SwiftUI
import CryptoKit
import Foundation
import CommonCrypto

struct HardcodedKeysVulnerabilityView: View {
    @State private var secretData: String = ""
    @State private var isFileCreated: Bool = false
    @State private var fileName: String = ""

    // 16 bytes -> AES-128
    let key = "MyS3cr3tK3y2024!"
    let iv  = "InitVector123456"

    var body: some View {
        VStack(spacing: 24) {
            HardcodedKeysChallengeHeaderView()
            HardcodedKeysMissionBriefingView()
            SecretDataFormView(secretData: $secretData, encryptAction: encryptAndSaveFlag)

            if isFileCreated {
                FileCreatedStatusView(fileName: fileName)
            }

            Spacer()
        }
        .padding()
        .background(Color.black)
    }

    private func encryptAndSaveFlag() {
        let flagToEncrypt = generateFlagFromSecrets()

        guard let encryptedData = encryptFlagCBC(flag: flagToEncrypt) else {
            return
        }

        // Save Base64 so CyberChef can decode easily
        let base64String = encryptedData.base64EncodedString()
        let timestamp = String(Int(Date().timeIntervalSince1970))
        fileName = "encrypted_secrets_\(timestamp).dat"

        if let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let fileURL = documentsDirectory.appendingPathComponent(fileName)

            do {
                try base64String.write(to: fileURL, atomically: true, encoding: .utf8)
                withAnimation(.easeInOut(duration: 0.3)) {
                    isFileCreated = true
                }
            } catch {
                print("Failed to write encrypted file: \(error)")
            }
        }
    }

    private func generateFlagFromSecrets() -> String {
        let combined = key + iv
        let hash = abs(combined.hashValue)
        let flagSuffix = String(hash).suffix(4)
        return "FLAG{hardcoded_keys_extracted_\(flagSuffix)}"
    }

    // MARK: - AES CBC PKCS7 Encryption
    private func encryptFlagCBC(flag: String) -> Data? {
        guard let keyData = key.data(using: .utf8),
              let ivData = iv.data(using: .utf8),
              let plaintextData = flag.data(using: .utf8) else {
            return nil
        }

        let cryptLength = size_t(plaintextData.count + kCCBlockSizeAES128)
        var cryptData   = Data(count: cryptLength)

        var bytesEncrypted = 0

        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            plaintextData.withUnsafeBytes { dataBytes in
                ivData.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, kCCKeySizeAES128,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, plaintextData.count,
                            cryptBytes.baseAddress, cryptLength,
                            &bytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            print("Encryption failed, status: \(status)")
            return nil
        }

        cryptData.removeSubrange(bytesEncrypted..<cryptData.count)
        return cryptData
    }
}

// MARK: - Component Views

struct HardcodedKeysChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE 02]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)
            
            Text("HARDCODED ENCRYPTION KEYS")
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

struct HardcodedKeysMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("This application encrypts sensitive data using hardcoded cryptographic keys embedded directly in the source code. A common but dangerous practice that allows attackers to decrypt protected data through reverse engineering.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)
            
            Text("\nOBJECTIVE:")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
            
            Text("1. Reverse engineer the application\n2. Extract hardcoded encryption keys\n3. Decrypt the generated file\n4. Retrieve the hidden flag")
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

struct SecretDataFormView: View {
    @Binding var secretData: String
    let encryptAction: () -> Void
    
    var body: some View {
        VStack(spacing: 16) {
            Text("SECURE BACKUP FUNCTION")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            VStack(spacing: 12) {
                Button(action: encryptAction) {
                    Text("[ENCRYPT & SAVE FILE]")
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                        .foregroundColor(.white)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Color.green)
                .cornerRadius(0)
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

struct FileCreatedStatusView: View {
    let fileName: String
    
    var body: some View {
        VStack(spacing: 8) {
            Text("[STATUS: FILE ENCRYPTED]")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("Encrypted file created: \(fileName)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.green)
            
            Text("Location: Documents directory\nEncryption: AES-CBC + PKCS7")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .lineSpacing(2)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.green, lineWidth: 1)
                .background(Color.green.opacity(0.1))
        )
    }
}

#Preview {
    HardcodedKeysVulnerabilityView()
}

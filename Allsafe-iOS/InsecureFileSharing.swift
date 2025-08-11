//
//  InsecureFileSharing.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 11.
//

import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct InsecureFileSharingView: View {
    @State private var createdFiles: [URL] = []
    @State private var fileNames: [String] = []
    @State private var showShareSheet: Bool = false
    @State private var itemsToShare: [Any] = []
    @State private var statusMessage: String = ""

    var body: some View {
        VStack(spacing: 24) {
            FileSharingChallengeHeaderView()
            FileSharingMissionBriefingView()

            ShareActionPanel(
                shareAction: {
                    presentSystemPickerOrFallback()
                }
            )

            if !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.yellow)
                    .padding(.top, 4)
            }

            Spacer()
        }
        .padding()
        .background(Color.black)
        .sheet(isPresented: $showShareSheet) {
            ActivityView(activityItems: itemsToShare)
        }
        .onAppear {
            createFlagFileIfNeeded()
            refreshDocumentsList()
        }
    }
    private func createFlagFileIfNeeded() {
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            statusMessage = "Failed to locate Documents directory"
            return
        }

        let flagFileName = "itunes_export_share_flag.csv"
        let flagContent = "FLAG{itunes_file_sharing_exposed}"

        let flagURL = documentsDirectory.appendingPathComponent(flagFileName)
        if !FileManager.default.fileExists(atPath: flagURL.path) {
            do {
                try flagContent.data(using: .utf8)?.write(to: flagURL, options: .atomic)
            } catch {
                statusMessage = "Failed to create flag file: \(error.localizedDescription)"
            }
        }
    }

    private func refreshDocumentsList() {
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            statusMessage = "Failed to load Documents directory"
            return
        }

        do {
            let urls = try FileManager.default.contentsOfDirectory(
                at: documentsDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
            createdFiles = urls.sorted(by: { $0.lastPathComponent.lowercased() < $1.lastPathComponent.lowercased() })
            fileNames = createdFiles.map { $0.lastPathComponent }
        } catch {
            statusMessage = "Failed to enumerate Documents: \(error.localizedDescription)"
        }
    }

    private func presentSystemPickerOrFallback() {
        guard !createdFiles.isEmpty else {
            statusMessage = "No files found in Documents"
            return
        }

        presentDocumentPickerAllowingAnyType { pickedURLs in
            if !pickedURLs.isEmpty {
                itemsToShare = pickedURLs
                showShareSheet = true
                return
            }

            if let fallback = createdFiles.last(where: { $0.lastPathComponent.hasPrefix("itunes_export_") }) ?? createdFiles.first {
                itemsToShare = [fallback]
                showShareSheet = true
            } else {
                statusMessage = "No files selected"
            }
        }
    }

    private func presentDocumentPickerAllowingAnyType(completion: @escaping ([URL]) -> Void) {
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let root = scene.keyWindow?.rootViewController else {
            completion([])
            return
        }

        let types: [UTType] = [UTType.item]

        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: true)
        picker.allowsMultipleSelection = true

        let delegate = DocumentPickerDelegateWrapper { urls in
            completion(urls)
        }
        picker.delegate = delegate
        DocumentPickerDelegateRepository.shared.store(delegate: delegate, for: picker)
        root.present(picker, animated: true)
    }
}

struct FileSharingChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)

            Text("INSECURE ITUNES FILE SHARING")
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

struct FileSharingMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)

            Text("This application exposes its Documents directory through iTunes File Sharing and the Files app, allowing external browsing and extraction of app data.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)

            Text("\nOBJECTIVE:")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(.green)

            Text("1. Choose files via the system picker (all types allowed)\n2. If not possible, a default iTunes-export file is auto-selected")
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

struct ShareActionPanel: View {
    let shareAction: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Text("FILE SHARING CONTROL")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)

            VStack(spacing: 12) {
                Button(action: shareAction) {
                    Text("[SELECT & SHARE]")
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

struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
        controller.excludedActivityTypes = []
        return controller
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

private class DocumentPickerDelegateWrapper: NSObject, UIDocumentPickerDelegate {
    private let completion: ([URL]) -> Void

    init(completion: @escaping ([URL]) -> Void) {
        self.completion = completion
        super.init()
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        completion([])
        DocumentPickerDelegateRepository.shared.remove(for: controller)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        completion(urls)
        DocumentPickerDelegateRepository.shared.remove(for: controller)
    }
}

private class DocumentPickerDelegateRepository {
    static let shared = DocumentPickerDelegateRepository()
    private var storage: [ObjectIdentifier: DocumentPickerDelegateWrapper] = [:]

    func store(delegate: DocumentPickerDelegateWrapper, for picker: UIDocumentPickerViewController) {
        let key = ObjectIdentifier(picker)
        storage[key] = delegate
    }

    func remove(for picker: UIDocumentPickerViewController) {
        let key = ObjectIdentifier(picker)
        storage.removeValue(forKey: key)
    }
}

private extension UIWindowScene {
    var keyWindow: UIWindow? {
        return self.windows.first { $0.isKeyWindow }
    }
}

#Preview {
    InsecureFileSharingView()
}

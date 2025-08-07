//
//  DrawerMenuView.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 05..
//

import SwiftUI

struct DrawerMenuView: View {
    @Binding var isOpen: Bool
    @Binding var selectedVulnerability: VulnerabilityType?
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            VStack(alignment: .leading, spacing: 8) {
                Text("ALLSAFE")
                    .font(.system(size: 24, weight: .bold, design: .monospaced))
                    .foregroundColor(.green)
                
                Text("CYBERSECURITY")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.green)
                    .tracking(1)
                
                Rectangle()
                    .fill(Color.green)
                    .frame(height: 1)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 4)
                
                Text("VULNERABILITY MODULES")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.gray)
                    .tracking(1)
                    .padding(.top, 4)
            }
            .padding()
            .background(Color.black)
            
            // Menu items
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(VulnerabilityType.allCases) { vulnerability in
                        DrawerMenuItem(
                            vulnerability: vulnerability,
                            isSelected: selectedVulnerability == vulnerability
                        ) {
                            selectedVulnerability = vulnerability
                            withAnimation(.easeInOut(duration: 0.3)) {
                                isOpen = false
                            }
                        }
                    }
                }
            }
            .background(Color.black)
            
            Spacer()
        }
        .background(Color.black)
        .overlay(
            Rectangle()
                .stroke(Color.green.opacity(0.3), lineWidth: 1)
        )
    }
}


struct DrawerMenuItem: View {
    let vulnerability: VulnerabilityType
    let isSelected: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: vulnerability.icon)
                    .font(.title3)
                    .foregroundColor(isSelected ? .black : .green)
                    .frame(width: 24)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(vulnerability.title)
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                        .foregroundColor(isSelected ? .black : .white)
                        .multilineTextAlignment(.leading)
                    
                    Text(vulnerability.description)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(isSelected ? .black.opacity(0.8) : .gray)
                        .multilineTextAlignment(.leading)
                }
                
                Spacer()
                
                // Difficulty badge
                Text(vulnerability.difficulty)
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        RoundedRectangle(cornerRadius: 0)
                            .fill(difficultyColor(vulnerability.difficulty).opacity(isSelected ? 0.8 : 0.2))
                    )
                    .foregroundColor(isSelected ? .black : difficultyColor(vulnerability.difficulty))
                    .overlay(
                        RoundedRectangle(cornerRadius: 0)
                            .stroke(difficultyColor(vulnerability.difficulty), lineWidth: 1)
                    )
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .background(
            Rectangle()
                .fill(isSelected ? Color.green : Color.clear)
        )
        .buttonStyle(PlainButtonStyle())
    }
    
    private func difficultyColor(_ difficulty: String) -> Color {
        switch difficulty {
        case "Easy":
            return .green
        case "Medium":
            return .yellow
        case "Hard":
            return .red
        default:
            return .gray
        }
    }
}

#Preview {
    DrawerMenuView(
        isOpen: .constant(true),
        selectedVulnerability: .constant(.userDefaults)
    )
    .frame(width: 280)
}

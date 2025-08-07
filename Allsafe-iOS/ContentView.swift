//
//  ContentView.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 05..
//

import SwiftUI

struct ContentView: View {
    @State private var isDrawerOpen = false
    @State private var selectedVulnerability: VulnerabilityType? = nil
    
    var body: some View {
        NavigationView {
            ZStack {
                // Main content area
                VStack {
                    if let vulnerability = selectedVulnerability {
                        VulnerabilityDetailView(vulnerability: vulnerability)
                    } else {
                        WelcomeView()
                    }
                }
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button(action: {
                            withAnimation(.easeInOut(duration: 0.3)) {
                                isDrawerOpen.toggle()
                            }
                        }) {
                            Image(systemName: "line.horizontal.3")
                                .font(.title2)
                                .foregroundColor(.green)
                        }
                    }
                }
                
                // Drawer overlay
                if isDrawerOpen {
                    Color.black.opacity(0.7)
                        .edgesIgnoringSafeArea(.all)
                        .onTapGesture {
                            withAnimation(.easeInOut(duration: 0.3)) {
                                isDrawerOpen = false
                            }
                        }
                    
                    HStack {
                        DrawerMenuView(
                            isOpen: $isDrawerOpen,
                            selectedVulnerability: $selectedVulnerability
                        )
                        .frame(width: 280)
                        
                        Spacer()
                    }
                    .transition(.move(edge: .leading))
                }
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

struct WelcomeView: View {
    var body: some View {
        VStack(spacing: 20) {
            // Allsafe logo-style text
            VStack(spacing: 5) {
                Text("ALLSAFE")
                    .font(.system(size: 42, weight: .bold, design: .monospaced))
                    .foregroundColor(.green)
                
                Text("CYBERSECURITY")
                    .font(.system(size: 14, weight: .medium, design: .monospaced))
                    .foregroundColor(.green)
                    .tracking(2)
            }
            
            Rectangle()
                .fill(Color.green)
                .frame(height: 2)
                .frame(maxWidth: 200)
            
            Text("MOBILE PENETRATION TESTING LAB")
                .font(.system(size: 16, weight: .medium, design: .monospaced))
                .multilineTextAlignment(.center)
                .foregroundColor(.white)
                .tracking(1)
            
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("> ")
                        .foregroundColor(.green)
                        .fontDesign(.monospaced)
                    Text("Identify mobile security vulnerabilities")
                        .fontDesign(.monospaced)
                        .foregroundColor(.white)
                }
                
                HStack {
                    Text("> ")
                        .foregroundColor(.green)
                        .fontDesign(.monospaced)
                    Text("Extract flags from insecure implementations")
                        .fontDesign(.monospaced)
                        .foregroundColor(.white)
                }
                
                HStack {
                    Text("> ")
                        .foregroundColor(.green)
                        .fontDesign(.monospaced)
                    Text("Practice OWASP MSTG methodologies")
                        .fontDesign(.monospaced)
                        .foregroundColor(.white)
                }
                
                HStack {
                    Text("> ")
                        .foregroundColor(.green)
                        .fontDesign(.monospaced)
                    Text("Master mobile application security")
                        .fontDesign(.monospaced)
                        .foregroundColor(.white)
                }
            }
            .padding(20)
            .background(
                RoundedRectangle(cornerRadius: 0)
                    .stroke(Color.green, lineWidth: 1)
                    .background(Color.black.opacity(0.3))
            )
            
            Text("[MENU] Access vulnerability modules")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.green)
                .padding(.top)
        }
        .padding()
        .background(Color.black)
    }
}

#Preview {
    ContentView()
}

import SwiftUI
import WebKit

struct WebViewXSSView: View {
    @State private var userInput: String = ""
    @State private var showSuccessDialog = false
    @State private var xssTriggered = false
    
    var body: some View {
        VStack(spacing: 24) {
            WebViewXSSChallengeHeaderView()
            WebViewXSSMissionBriefingView()
            
            VStack(spacing: 16) {
                XSSInputPortalView(
                    userInput: $userInput
                )
                
                VulnerableWebViewContainer(
                    userInput: userInput,
                    xssTriggered: $xssTriggered
                )
            }
            
            Spacer()
        }
        .padding()
        .background(Color.black)
        .alert("XSS Injection Successful!", isPresented: $showSuccessDialog) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("FLAG{webview_xss_injection_successful_w3b}")
        }
        .onChange(of: xssTriggered) { triggered in
            if triggered {
                showSuccessDialog = true
            }
        }
    }
    
}

struct WebViewXSSChallengeHeaderView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("[CHALLENGE 09]")
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(.green)
                .tracking(2)
            
            Text("WEBVIEW XSS INJECTION")
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

struct WebViewXSSMissionBriefingView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MISSION BRIEFING:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
            
            Text("This application contains a vulnerable WebView implementation that directly injects user input into HTML content without proper sanitization. The WebView lacks essential security configurations, making it susceptible to Cross-Site Scripting (XSS) attacks.")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)
                .lineSpacing(2)
            
            Text("\nVULNERABILITIES:")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.yellow)
            
            VStack(alignment: .leading, spacing: 4) {
                Text("• Unfiltered user input injection")
                Text("• Missing content security policy (CSP)")
                Text("• JavaScript execution enabled")
                Text("• No input validation or sanitization")
            }
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.gray)
            
            Text("\nTARGET: Execute JavaScript code in the WebView context")
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

struct XSSInputPortalView: View {
    @Binding var userInput: String
    
    var body: some View {
        VStack(spacing: 16) {
            Text("USER INPUT PORTAL")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            Text("Enter your XSS payload - it will execute in real-time:")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
            
            TextField("Try: <script>alert('XSS')</script>", text: $userInput, axis: .vertical)
                .textFieldStyle(PlainTextFieldStyle())
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 0)
                        .stroke(Color.gray, lineWidth: 1)
                        .background(Color.black.opacity(0.5))
                )
                .lineLimit(3...6)
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.gray, lineWidth: 1)
                .background(Color.black.opacity(0.2))
        )
    }
}

struct VulnerableWebViewContainer: View {
    let userInput: String
    @Binding var xssTriggered: Bool
    
    var body: some View {
        VStack(spacing: 12) {
            Text("VULNERABLE WEBVIEW")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.red)
                .tracking(1)
            
            VulnerableWebView(
                userInput: userInput,
                xssTriggered: $xssTriggered
            )
            .frame(height: 300)
            .background(Color.white)
            .cornerRadius(0)
            .overlay(
                RoundedRectangle(cornerRadius: 0)
                    .stroke(Color.red, lineWidth: 2)
            )
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.red.opacity(0.5), lineWidth: 1)
                .background(Color.red.opacity(0.1))
        )
    }
}

struct VulnerableWebView: UIViewRepresentable {
    let userInput: String
    @Binding var xssTriggered: Bool
    
    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        
        // VULNERABLE: Enable JavaScript (this is often necessary but dangerous with unfiltered input)
        configuration.preferences.javaScriptEnabled = true
        
        // VULNERABLE: Allow arbitrary loads in local context
        configuration.limitsNavigationsToAppBoundDomains = false
        
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        
        // Inject a message handler to detect XSS
        let contentController = webView.configuration.userContentController
        contentController.add(context.coordinator, name: "XSSDetector")
        
        return webView
    }
    
    func updateUIView(_ webView: WKWebView, context: Context) {
        // VULNERABLE: Direct injection of user input without sanitization
        let htmlContent = generateVulnerableHTML(with: userInput)
        webView.loadHTMLString(htmlContent, baseURL: nil)
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    private func generateVulnerableHTML(with input: String) -> String {
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Vulnerable WebView</title>
            <style>
                body {
                    font-family: 'Courier New', monospace;
                    font-size: 16px;
                    background: #1a1a1a;
                    color: #00ff00;
                    padding: 20px;
                    margin: 0;
                }
                .container {
                    border: 1px solid #00ff00;
                    padding: 15px;
                    background: rgba(0, 255, 0, 0.1);
                }
                .input-display {
                    background: #000;
                    border: 1px solid #333;
                    padding: 15px;
                    margin-top: 15px;
                    word-wrap: break-word;
                    font-size: 14px;
                    line-height: 1.4;
                }
                .warning {
                    color: #ff0000;
                    font-size: 14px;
                    margin-top: 15px;
                }
                h2 {
                    font-size: 20px;
                    margin: 0 0 15px 0;
                }
            </style>
            <script>
                // XSS Detection Script
                window.xssDetected = false;
                
                function triggerXSSDetection() {
                    if (!window.xssDetected) {
                        window.xssDetected = true;
                        try {
                            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.XSSDetector) {
                                window.webkit.messageHandlers.XSSDetector.postMessage('XSS_TRIGGERED');
                            }
                        } catch(e) {
                            console.log('Failed to send XSS detection message:', e);
                        }
                    }
                }
                
                // Setup detection after page loads
                document.addEventListener('DOMContentLoaded', function() {
                    // Override alert immediately
                    var originalAlert = window.alert;
                    window.alert = function(message) {
                        triggerXSSDetection();
                        return originalAlert.call(window, message);
                    };
                    
                    // Override other common functions
                    var originalConfirm = window.confirm;
                    window.confirm = function(message) {
                        triggerXSSDetection();
                        return originalConfirm.call(window, message);
                    };
                    
                    // Check for immediate script execution
                    setTimeout(function() {
                        var allScripts = document.getElementsByTagName('script');
                        if (allScripts.length > 1) {
                            // Additional scripts were added, likely XSS
                            triggerXSSDetection();
                        }
                    }, 100);
                });
                
                // Also setup overrides immediately in case DOMContentLoaded already fired
                var originalAlert = window.alert;
                window.alert = function(message) {
                    triggerXSSDetection();
                    return originalAlert ? originalAlert.call(window, message) : undefined;
                };
                
                // Global success function
                window.xssSuccess = triggerXSSDetection;
            </script>
        </head>
        <body>
            <div class="container">
                <h2>[ALLSAFE WEBVIEW]</h2>
                <p>User Message Display:</p>
                <div class="input-display">
                    \(input.isEmpty ? "No input provided" : input)
                </div>
                <div class="warning">
                    ⚠️ WARNING: This WebView processes user input without sanitization
                </div>
            </div>
        </body>
        </html>
        """
    }
    
    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let parent: VulnerableWebView
        
        init(_ parent: VulnerableWebView) {
            self.parent = parent
        }
        
        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            if message.name == "XSSDetector" && message.body as? String == "XSS_TRIGGERED" {
                DispatchQueue.main.async {
                    self.parent.xssTriggered = true
                }
            }
        }
    }
}

#Preview {
    WebViewXSSView()
}

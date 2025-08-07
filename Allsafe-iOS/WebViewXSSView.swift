import SwiftUI
import WebKit

struct WebViewXSSView: View {
    @State private var userInput: String = ""
    
    var body: some View {
        VStack(spacing: 24) {
            WebViewXSSChallengeHeaderView()
            WebViewXSSMissionBriefingView()
            
            // Only the input portal with invisible WebView
            XSSInputPortalView(userInput: $userInput)
            
            Spacer()
        }
        .padding()
        .background(Color.black)
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
    @State private var showInvisibleWebView = false
    @State private var xssTriggered = false
    @State private var showSuccessDialog = false
    
    var body: some View {
        VStack(spacing: 16) {
            Text("XSS INJECTION TERMINAL")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.green)
                .tracking(1)
            
            Text("Enter JavaScript payload and execute:")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
            
            VStack(alignment: .leading, spacing: 8) {
                Text("EFFECTIVE PAYLOADS:")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.yellow)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("• <script>alert('XSS Success!')</script>")
                    Text("• <img src=x onerror=\"alert('Injected!')\">")
                    Text("• <svg onload=\"alert('SVG XSS')\">")
                    Text("• <script>console.log('XSS Executed')</script>")
                    Text("• <div onclick=\"alert('Click XSS')\">Click me</div>")
                }
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.gray)
                
                HStack {
                    Button("Test Alert") {
                        userInput = "<script>alert('XSS Test Successful!')</script>"
                    }
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.black)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.yellow)
                    .cornerRadius(0)
                    
                    Button("Clear") {
                        userInput = ""
                        showInvisibleWebView = false
                    }
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.red)
                    .cornerRadius(0)
                }
            }
            
            TextField("Enter XSS payload...", text: $userInput, axis: .vertical)
                .textFieldStyle(PlainTextFieldStyle())
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 0)
                        .stroke(Color.gray, lineWidth: 1)
                        .background(Color.black.opacity(0.7))
                )
                .lineLimit(2...8)
            
            // EXECUTE BUTTON
            Button(action: {
                executeXSSPayload()
            }) {
                HStack {
                    Image(systemName: "play.fill")
                    Text("[EXECUTE XSS PAYLOAD]")
                }
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.black)
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
                .background(Color.green)
                .cornerRadius(0)
                .overlay(
                    RoundedRectangle(cornerRadius: 0)
                        .stroke(Color.white, lineWidth: 1)
                )
            }
            .disabled(userInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 0)
                .stroke(Color.gray, lineWidth: 1)
                .background(Color.black.opacity(0.2))
        )
        .background(
            // INVISIBLE WEBVIEW
            Group {
                if showInvisibleWebView {
                    InvisibleXSSWebView(
                        userInput: userInput,
                        xssTriggered: $xssTriggered
                    )
                    .frame(width: 0, height: 0)
                    .opacity(0)
                }
            }
        )
        .alert("🚨 XSS ATTACK SUCCESSFUL! 🚨", isPresented: $showSuccessDialog) {
            Button("Claim Flag", role: .none) { }
            Button("Execute Another", role: .cancel) {
                xssTriggered = false
                showInvisibleWebView = false
            }
        } message: {
            Text("Congratulations! Your XSS payload executed successfully!\n\n🏴 FLAG{webview_xss_injection_successful_w3b} 🏴\n\nThe invisible WebView rendered your payload and triggered the popup!")
        }
        .onChange(of: xssTriggered) { triggered in
            if triggered {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                    showSuccessDialog = true
                }
            }
        }
    }
    
    private func executeXSSPayload() {
        guard !userInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        
        // Reset state and show invisible webview
        xssTriggered = false
        showInvisibleWebView = true
    }
}

struct InvisibleXSSWebView: UIViewRepresentable {
    let userInput: String
    @Binding var xssTriggered: Bool
    
    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.limitsNavigationsToAppBoundDomains = false
        configuration.suppressesIncrementalRendering = false
        
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        
        // Add message handler for XSS detection
        let contentController = webView.configuration.userContentController
        contentController.add(context.coordinator, name: "XSSDetector")
        
        // Make completely invisible
        webView.isHidden = true
        webView.alpha = 0
        
        return webView
    }
    
    func updateUIView(_ webView: WKWebView, context: Context) {
        // Generate minimal HTML with user input
        let minimalHTML = generateMinimalHTML(with: userInput)
        
        // Enable JavaScript for this navigation
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = true
        webView.configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        
        webView.loadHTMLString(minimalHTML, baseURL: nil)
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    private func generateMinimalHTML(with input: String) -> String {
        // Generate the smallest possible HTML that will execute the XSS
        return """
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body>
<script>
window.xssDetected = false;
function notifySuccess() {
    if (!window.xssDetected) {
        window.xssDetected = true;
        try {
            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.XSSDetector) {
                window.webkit.messageHandlers.XSSDetector.postMessage('XSS_TRIGGERED');
            }
        } catch(e) {}
    }
}

// Override alert to detect XSS
var originalAlert = window.alert;
window.alert = function(message) {
    notifySuccess();
    return originalAlert ? originalAlert.call(window, message) : undefined;
};

// Override other methods
var originalConsole = console.log;
console.log = function() {
    notifySuccess();
    return originalConsole.apply(console, arguments);
};

var originalConfirm = window.confirm;
window.confirm = function(message) {
    notifySuccess();
    return originalConfirm ? originalConfirm.call(window, message) : true;
};

window.triggerXSS = notifySuccess;
</script>
""" + input + """
</body>
</html>
"""
    }
    
    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let parent: InvisibleXSSWebView
        
        init(_ parent: InvisibleXSSWebView) {
            self.parent = parent
        }
        
        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            if message.name == "XSSDetector" && message.body as? String == "XSS_TRIGGERED" {
                DispatchQueue.main.async {
                    self.parent.xssTriggered = true
                }
            }
        }
        
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, preferences: WKWebpagePreferences, decisionHandler: @escaping (WKNavigationActionPolicy, WKWebpagePreferences) -> Void) {
            preferences.allowsContentJavaScript = true
            decisionHandler(.allow, preferences)
        }
        
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            // Check for immediate script execution after load
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                webView.evaluateJavaScript("document.getElementsByTagName('script').length > 1") { result, error in
                    if let scriptCount = result as? Bool, scriptCount {
                        DispatchQueue.main.async {
                            self.parent.xssTriggered = true
                        }
                    }
                }
            }
        }
    }
}

#Preview {
    WebViewXSSView()
}

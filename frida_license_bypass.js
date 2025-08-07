// frida_license_bypass.js
// Basic License Key Validation Bypass Script for Allsafe-iOS Challenge 06
// Usage: frida -U -l frida_license_bypass.js "Allsafe-iOS"

console.log("🔓 Starting License Key Bypass...");
console.log("📱 Target: Allsafe-iOS Challenge 06");
console.log("🎯 Objective: Bypass validateLicense() method");

// Wait for the app to fully load
setTimeout(function() {
    console.log("🔍 Searching for LicenseKeyVulnerabilityView class...");
    
    try {
        // Method 1: Try to find Objective-C class
        var LicenseView = ObjC.classes.LicenseKeyVulnerabilityView;
        
        if (LicenseView) {
            console.log("✅ Found LicenseKeyVulnerabilityView class via ObjC");
            
            // Look for the validateLicense method
            var validateLicense = LicenseView['- validateLicense'];
            
            if (validateLicense) {
                console.log("🎯 Found validateLicense method - installing hook...");
                
                Interceptor.attach(validateLicense.implementation, {
                    onEnter: function(args) {
                        console.log("🚀 validateLicense called - preparing bypass...");
                        console.log("📝 Arguments:", args);
                    },
                    onLeave: function(retval) {
                        console.log("📤 Original return value:", retval);
                        // Force return true (1)
                        retval.replace(ptr(1));
                        console.log("✨ Bypassed! New return value: true");
                        console.log("🏆 License validation should now succeed!");
                    }
                });
                
                console.log("🎉 License validation bypass installed successfully!");
                console.log("💡 Now enter any license key in the app and tap validate!");
                
            } else {
                console.log("❌ validateLicense method not found in ObjC class");
            }
        } else {
            console.log("⚠️  LicenseKeyVulnerabilityView class not found via ObjC");
        }
        
    } catch (error) {
        console.log("❌ Error with ObjC approach:", error);
    }
    
    // Method 2: Search through all loaded modules for Swift methods
    console.log("🔍 Searching through loaded modules for Swift methods...");
    
    var modules = Process.enumerateModules();
    var found = false;
    
    modules.forEach(function(module) {
        if (module.name.includes("Allsafe")) {
            console.log("📦 Checking module:", module.name);
            
            var exports = module.enumerateExports();
            exports.forEach(function(exp) {
                // Look for mangled Swift method names containing validateLicense
                if (exp.name.includes("validateLicense") || 
                    (exp.name.includes("License") && exp.name.includes("validate"))) {
                    
                    console.log("🎯 Found potential target:", exp.name, "at", exp.address);
                    
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                console.log("🚀 Swift method called:", exp.name);
                            },
                            onLeave: function(retval) {
                                if (retval && !retval.isNull()) {
                                    console.log("📤 Original return:", retval);
                                    retval.replace(ptr(1)); // Force true
                                    console.log("✨ Swift method bypassed!");
                                }
                            }
                        });
                        found = true;
                        console.log("✅ Swift method hook installed!");
                    } catch (e) {
                        console.log("⚠️  Could not hook:", exp.name, "Error:", e);
                    }
                }
            });
        }
    });
    
    if (!found) {
        console.log("❌ No validateLicense methods found in any approach");
        console.log("💡 Try running the discovery script first to find the exact method signature");
    }
    
}, 3000);

// Helper function to monitor all method calls (optional)
function monitorAllCalls() {
    console.log("🔍 Monitoring all method calls for debugging...");
    
    Interceptor.attach(Module.findExportByName(null, "objc_msgSend"), {
        onEnter: function(args) {
            var selector = ObjC.selectorAsString(args[1]);
            if (selector && selector.includes("validate")) {
                console.log("📞 Method call:", selector);
            }
        }
    });
}

// Uncomment the line below to enable monitoring (generates lots of output)
// monitorAllCalls();

console.log("🎯 Bypass script loaded. Navigate to Challenge 06 in the app!");
console.log("📝 Enter any license key and tap 'VALIDATE LICENSE' to test the bypass.");

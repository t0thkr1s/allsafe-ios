# License Key Validation Bypass Challenge

## Challenge Description

**Challenge 06: License Key Validation Bypass**  
**Difficulty: Hard**  
**Target:** Bypass license key validation and reveal the flag

This challenge simulates a real-world scenario where an application implements license key validation that can be bypassed using dynamic instrumentation tools like Frida. The application contains a `validateLicense()` method that normally returns `false` unless a valid license key is provided, but through Frida scripting, you can intercept and manipulate this method to always return `true`.

## Challenge Details

### Vulnerable Method
The application contains a method called `validateLicense()` in the `LicenseKeyVulnerabilityView` class:

```swift
@objc private func validateLicense() -> Bool {
    // This method would normally perform complex license validation
    // For the CTF challenge, this always returns false unless bypassed with Frida
    let validKeys = ["VALID-ALLSAFE-LICENSE-2024", "DEMO-KEY-12345"]
    return validKeys.contains(licenseKey)
}
```

### Objective
- Bypass the license validation check using Frida
- Make the `validateLicense()` method return `true`
- Trigger the success dialog to reveal the flag: `FLAG{license_key_bypass_success_f1ag}`

## Solution

### Prerequisites
1. Install Frida on your system
2. Install Frida on the iOS device (jailbroken device or simulator)
3. Install the Allsafe-iOS application on the target device

### Method 1: Basic Method Override

Create a Frida script to override the `validateLicense` method:

```javascript
// frida_license_bypass.js
console.log("Starting License Key Bypass...");

// Wait for the app to load
setTimeout(function() {
    // Get reference to the LicenseKeyVulnerabilityView class
    var LicenseView = ObjC.classes.LicenseKeyVulnerabilityView;
    
    if (LicenseView) {
        console.log("Found LicenseKeyVulnerabilityView class");
        
        // Override the validateLicense method
        var validateLicense = LicenseView['- validateLicense'];
        
        if (validateLicense) {
            Interceptor.attach(validateLicense.implementation, {
                onEnter: function(args) {
                    console.log("validateLicense called - bypassing...");
                },
                onLeave: function(retval) {
                    console.log("Original return value:", retval);
                    // Force return true
                    retval.replace(ptr(1));
                    console.log("Bypassed! New return value:", retval);
                }
            });
            console.log("License validation bypass installed!");
        } else {
            console.log("validateLicense method not found");
        }
    } else {
        console.log("LicenseKeyVulnerabilityView class not found");
    }
}, 2000);
```

### Method 2: Swift Method Hooking

For Swift methods, you may need to find the mangled method name:

```javascript
// frida_swift_bypass.js
console.log("Swift License Key Bypass Starting...");

// Search for validateLicense method in all loaded modules
var modules = Process.enumerateModules();
modules.forEach(function(module) {
    var exports = module.enumerateExports();
    exports.forEach(function(exp) {
        if (exp.name.includes("validateLicense")) {
            console.log("Found potential target:", exp.name, "at", exp.address);
            
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("Method called:", exp.name);
                },
                onLeave: function(retval) {
                    console.log("Original return:", retval);
                    retval.replace(ptr(1)); // Force true
                    console.log("Return value changed to true!");
                }
            });
        }
    });
});
```

### Method 3: Class-dump and Method Discovery

First, discover the exact method signature:

```bash
# Get the app's bundle identifier
frida-ps -U | grep -i allsafe

# Discover methods in the app
frida -U -l discover_methods.js "Allsafe-iOS"
```

```javascript
// discover_methods.js
console.log("Discovering methods...");

ObjC.choose(ObjC.classes.NSObject, {
    onMatch: function(instance) {
        var className = instance.$className;
        if (className.includes("License")) {
            console.log("Found class:", className);
            
            var methods = instance.$class.$methods;
            methods.forEach(function(method) {
                if (method.includes("validate") || method.includes("license")) {
                    console.log("  Method:", method);
                }
            });
        }
    },
    onComplete: function() {
        console.log("Discovery complete");
    }
});
```

### Running the Exploit

1. Start the Allsafe-iOS app on your device
2. Navigate to Challenge 06 (License Key Validation Bypass)
3. Run the Frida script:

```bash
# Method 1: Using Frida with script file
frida -U -l frida_license_bypass.js "Allsafe-iOS"

# Method 2: Using Frida with inline script
frida -U --eval "setTimeout(function(){var c=ObjC.classes.LicenseKeyVulnerabilityView;if(c){var m=c['- validateLicense'];if(m){Interceptor.attach(m.implementation,{onLeave:function(r){r.replace(ptr(1));}});console.log('Bypass active!')}}},2000);" "Allsafe-iOS"
```

4. In the app, enter any license key (e.g., "FRIDA-BYPASS-TEST")
5. Tap the "VALIDATE LICENSE" button
6. The validation should succeed and display the flag in an alert dialog

## Learning Objectives

This challenge teaches:
- **Dynamic Analysis**: Understanding how to use Frida for runtime manipulation
- **Method Hooking**: Intercepting and modifying method return values
- **iOS Security**: Understanding client-side validation vulnerabilities
- **Reverse Engineering**: Finding and targeting specific methods in mobile applications
- **Objective-C/Swift Interop**: Working with both Objective-C and Swift methods in Frida

## Defense Strategies

To prevent this type of attack in real applications:
1. **Server-side Validation**: Always validate license keys on the server
2. **Certificate Pinning**: Prevent man-in-the-middle attacks
3. **Code Obfuscation**: Make reverse engineering more difficult
4. **Anti-debugging**: Detect and prevent debugging/instrumentation
5. **Integrity Checks**: Verify the application hasn't been modified
6. **Root/Jailbreak Detection**: Prevent running on compromised devices

## Flag
`FLAG{license_key_bypass_success_f1ag}`

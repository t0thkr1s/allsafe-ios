// discover_methods.js
// Script to discover classes and methods within the Allsafe-iOS app
// Usage: frida -U -l discover_methods.js "Allsafe-iOS"

console.log("🔍 Discovering methods and classes in Allsafe-iOS...");

ObjC.choose(ObjC.classes.NSObject, {
    onMatch: function(instance) {
        var className = instance.$className;
        if (className.includes("License") || className.includes("Vulnerability")) {
            console.log("🏷 Found class:", className);
            
            var methods = instance.$class.$methods;
            methods.forEach(function(method) {
                console.log("  ⚙️ Method:", method);
            });
        }
    },
    onComplete: function() {
        console.log("🔍 Discovery complete. All methods listed.");
    }
});

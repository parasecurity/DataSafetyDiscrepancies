(() => {
    'use strict';

    // Configuration object containing settings related to root bypassing
    const CONFIG = {
        fingerprint: "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys", // Device fingerprint to spoof
        secureProps: {
            "ro.secure": "1",               // Set the 'ro.secure' property to 1 (indicating secure system)
            "ro.debuggable": "0",           // Set 'ro.debuggable' to 0 (disables debugging)
            "ro.build.type": "user",        // Set build type to 'user' (indicating production environment)
            "ro.build.tags": "release-keys" // Set build tags to 'release-keys'
        }
    };

    // Root indicators including paths, packages, commands, and binaries commonly found on rooted devices
    const ROOT_INDICATORS = {
        paths: new Set([
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            // List other paths commonly associated with root
        ]),
        packages: new Set([
            "com.noshufou.android.su", // Superuser package
            "eu.chainfire.supersu",     // SuperSU package
            "com.topjohnwu.magisk",     // Magisk package
            // Other package names that indicate root access
        ]),
        commands: new Set([
            "su", "which su", "whereis su", "locate su", "find / -name su", // Commands to detect root presence
        ]),
        binaries: new Set([
            "su", "busybox", "magisk", "supersu", // Binary names indicating root
        ])
    };

    // Logger utility to log messages with a prefix for easier identification
    const Logger = {
        prefix: "RootBypass: ",
        info(message) {
            console.log(`${this.prefix}${message}`);
        },
        error(message, error) {
            console.error(`${this.prefix}ERROR: ${message}`, error || "");
        }
    };

    // Function to bypass native file system checks (like fopen, access, stat)
    function bypassNativeFileCheck() {
        // Hook fopen function to intercept file access attempts
        const fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter(args) {
                    this.path = args[0].readUtf8String(); // Capture the file path
                },
                onLeave(retval) {
                    if (retval.toInt32() !== 0) {
                        const path = this.path.toLowerCase();
                        // Block access to root-related paths
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            Logger.info(`Blocked fopen: ${this.path}`);
                            retval.replace(ptr(0x0)); // Replace return value to block the fopen operation
                        }
                    }
                }
            });
        }

        // Similar hooking for 'access', 'stat', and 'lstat' to block access to root paths
        const access = Module.findExportByName("libc.so", "access");
        if (access) {
            Interceptor.attach(access, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() === 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            Logger.info(`Blocked access: ${this.path}`);
                            retval.replace(ptr(-1)); // Block the access
                        }
                    }
                }
            });
        }

        // Intercept stat system calls to block access to sensitive file stats
        const stat = Module.findExportByName("libc.so", "stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        Logger.info(`Blocked stat: ${this.path}`);
                        retval.replace(ptr(-1)); // Block the stat check
                    }
                }
            });
        }

        // Intercept lstat system calls to block symbolic link checks
        const lstat = Module.findExportByName("libc.so", "lstat");
        if (lstat) {
            Interceptor.attach(lstat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        Logger.info(`Blocked lstat: ${this.path}`);
                        retval.replace(ptr(-1)); // Block the lstat check
                    }
                }
            });
        }
    }

    // Function to bypass Java file checks (such as File.exists, FileInputStream, etc.)
    function bypassJavaFileCheck() {
        // Hook the UnixFileSystem checkAccess method to block root file access checks in Java
        const UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            const filename = file.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file access check: ${filename}`);
                return false; // Return false to block access
            }
            return this.checkAccess(file, access); // Otherwise, allow normal access check
        };

        // Similar function for blocking other file checks (exists, length, and stream access)
        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            const filename = this.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file exists check: ${filename}`);
                return false; // Block the check
            }
            return this.exists(); // Otherwise, allow normal check
        };

        File.length.implementation = function() {
            const filename = this.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file length check: ${filename}`);
                return 0; // Block the check
            }
            return this.length(); // Otherwise, allow normal check
        };

        // Block FileInputStream creation for files in root directories
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            const filename = file.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked FileInputStream creation: ${filename}`);
                throw new Java.use("java.io.FileNotFoundException").$new(filename); // Throw an exception to block access
            }
            return this.$init(file); // Otherwise, allow normal FileInputStream creation
        };
    }

    // Function to spoof system properties to hide root-related properties
    function setProp() {
        try {
            const Build = Java.use("android.os.Build");
            const fields = {
                "TAGS": "release-keys",
                "TYPE": "user",
                "FINGERPRINT": CONFIG.fingerprint
            };

            // Change the Build properties to make the system look like a normal, non-rooted device
            Object.entries(fields).forEach(([field, value]) => {
                const fieldObj = Build.class.getDeclaredField(field);
                fieldObj.setAccessible(true);
                fieldObj.set(null, value);
            });

            // Hook the system_property_get function to return the spoofed values for secure properties
            const system_property_get = Module.findExportByName("libc.so", "__system_property_get");
            if (system_property_get) {
                Interceptor.attach(system_property_get, {
                    onEnter(args) {
                        this.key = args[0].readCString();
                        this.ret = args[1];
                    },
                    onLeave(retval) {
                        const secureValue = CONFIG.secureProps[this.key];
                        if (secureValue !== undefined) {
                            const valuePtr = Memory.allocUtf8String(secureValue);
                            Memory.copy(this.ret, valuePtr, secureValue.length + 1);
                        }
                    }
                });
            }

            // Block getprop command to prevent root-related properties from being accessed
            const Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                if (cmd.startsWith("getprop ")) {
                    const prop = cmd.split(" ")[1];
                    if (CONFIG.secureProps[prop]) {
                        Logger.info(`Blocked getprop command: ${cmd}`);
                        return null; // Block getprop command
                    }
                }
                return this.exec(cmd); // Otherwise, allow normal execution
            };
        } catch (error) {
            Logger.error("Error setting up build properties bypass", error); // Log error if any
        }
    }

    // Function to bypass root package checks (such as checking for Superuser or Magisk packages)
    function bypassRootPackageCheck() {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
        
        // Block package checks by altering the package name if it matches a known root package
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            if (ROOT_INDICATORS.packages.has(str)) {
                Logger.info(`Blocked package check: ${str}`);
                str = "com.nonexistent.package"; // Replace with a non-existent package name
            }
            return this.getPackageInfo(str, i); // Return the normal package info
        };
    }

    // Initialize all the root bypass functions
    function init() {
        Logger.info("Initializing root bypass...");
        bypassNativeFileCheck();
        bypassJavaFileCheck();
        setProp();
        bypassRootPackageCheck();
    }

    init(); // Call the init function to apply bypassing
})();

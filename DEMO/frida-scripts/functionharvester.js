function trace(pattern) {
    var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";
    if (type === "java") {
        var found = false;
        Java.enumerateLoadedClasses({
            onMatch: function (aClass) {
                if (aClass.match(pattern)) {
                    found = true;
                    try {
                        traceClass(aClass);
                    } catch (error) {
                        // console.error(`Failed to trace class ${aClass}: ${error}`);
                    }
                }
            },
            onComplete: function () {
                if (!found) {
                    // console.log(`No class matched pattern: ${pattern}`);
                }
            }
        });
    }
}

function traceClass(targetClass) {
    try {
        var hook = Java.use(targetClass);
        var methods = hook.class.getDeclaredMethods();
        hook.$dispose;

        var parsedMethods = [];
        methods.forEach(function (method) {
            var match = method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/);
            if (match) {
                parsedMethods.push(match[1]);
            }
        });

        var targets = uniqBy(parsedMethods, JSON.stringify);
        targets.forEach(function (targetMethod) {
            traceMethod(targetClass + "." + targetMethod);
        });
    } catch (error) {
        // console.error(`Error tracing class ${targetClass}:`, error);
    }
}
function traceMethod(targetClassMethod) {
    try {
        var delim = targetClassMethod.lastIndexOf(".");
        if (delim === -1) return;

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
        var hook = Java.use(targetClass);

        if (!hook[targetMethod]) {
            console.error('Method not found:', targetClassMethod);
            return;
        }

        var overloads = hook[targetMethod].overloads;
        if (!overloads || overloads.length === 0) {
            console.error('No overloads found for:', targetClassMethod);
            return;
        }

        overloads.forEach(function (overload) {
            overload.implementation = function () {
                var logMsg = "\n###HOOKED_METHOD_START###";
                logMsg += "\n@@@Method@@@:" + targetClassMethod;

                // Serialize and log arguments with types
                logMsg += "\n@@@Arguments@@@";
                for (var j = 0; j < arguments.length; j++) {
                    var serializedArg = serializeArgument(arguments[j]);
                    logMsg += `\narg[${j}]@@@${serializedArg}@@@${getType(arguments[j])}`;
                }

                var retval;
                try {
                    // Call the original method
                    retval = this[targetMethod].apply(this, arguments);
                } catch (err) {
                    logMsg += `\n@@@Error@@@: Exception while calling ${targetClassMethod}@@@${err}`;
                    console.error(logMsg + "\n###HOOKED_METHOD_END###");
                    return null; // Handle as needed
                }

                // Serialize and log return value with type
                logMsg += `\n@@@ReturnValue@@@${retval}@@@${getType(retval)}`;

                // Get and log stack trace
                try {
                    var threadInstance = Java.use('java.lang.Thread').currentThread();
                    var stack = threadInstance.getStackTrace();
                    var fullCallStack = getStackTrace(stack);
                    logMsg += "\n@@@StackTrace@@@\n" + fullCallStack;
                } catch (err) {
                    logMsg += "\n@@@Error@@@: Unable to capture stack trace@@@" + err;
                }

                logMsg += "\n###HOOKED_METHOD_END###\n";
                console.log(logMsg);
                return retval;
            };
        });
    } catch (error) {
        console.error(`Error during hooking ${targetClassMethod}:`, error);
    }

    function serializeArgument(arg) {
        if (arg === null || arg === undefined) {
            return String(arg);
        }
    
        // Handle primitive JS types
        if (typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean') {
            return arg.toString();
        }
    
        // Try to JSON stringify plain JS objects
        if (typeof arg === 'object' && !Java.isJavaObject(arg)) {
            try {
                return JSON.stringify(arg, null, 2);
            } catch (e) {
                return arg.toString();
            }
        }
    
        // Java array handling
        if (Java.isJavaObject(arg) && arg.getClass().isArray()) {
            const len = arg.length;
            let result = `JavaArray[length=${len}] [`;
            for (let i = 0; i < len; i++) {
                try {
                    result += serializeArgument(arg[i]) + (i < len - 1 ? ", " : "");
                } catch (e) {
                    result += "<error>";
                }
            }
            result += "]";
            return result;
        }
    
        // Java List handling (e.g., ArrayList, etc.)
        if (Java.isJavaObject(arg) && Java.use("java.util.List").class.isInstance(arg)) {
            try {
                let result = `JavaList[size=${arg.size()}] [`;
                for (let i = 0; i < arg.size(); i++) {
                    result += serializeArgument(arg.get(i)) + (i < arg.size() - 1 ? ", " : "");
                }
                result += "]";
                return result;
            } catch (e) {
                return "JavaList<error>";
            }
        }
    
        // Java object: reflect and dump all fields
        if (Java.isJavaObject(arg)) {
            try {
                const cls = arg.getClass();
                const clsName = cls.getName();
                const fields = cls.getDeclaredFields();
                let result = `Object<${clsName}> {`;
                for (let i = 0; i < fields.length; i++) {
                    try {
                        const field = fields[i];
                        field.setAccessible(true);
                        const fieldName = field.getName();
                        const fieldVal = field.get(arg);
                        result += `\n  ${fieldName}: ${serializeArgument(fieldVal)}`;
                    } catch (e) {
                        result += `\n  ${fields[i].getName()}: <error>`;
                    }
                }
                result += "\n}";
                return result;
            } catch (e) {
                return `JavaObject<error: ${e}>`;
            }
        }
    
        // Fallback to default string
        try {
            return arg.toString();
        } catch (e) {
            return "<unserializable>";
        }
    }
    

    function getType(arg) {
        if (arg === null) return "null";
        if (arg === undefined) return "undefined";
        if (Java.available && arg.$className) return arg.$className;  // Handle Java objects
        return typeof arg;
    }

    function getStackTrace(stack) {
        var trace = "";
        for (var i = 0; i < stack.length; i++) {
            trace += `  ${stack[i].toString()}\n`;
        }
        return trace;
    }
} 
// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


// Anti-detection techniques to bypass Frida detection
function antiFridaBypass() {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    //send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    //send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    // if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
    //     try {
    //         //useProcessManager = true;
    //         //var ProcessManager = Java.use('java.lang.ProcessManager');
    //     } catch (err) {
    //         //send("ProcessManager Hook failed: " + err);
    //     }
    // } else {
    //     //send("ProcessManager hook not loaded");
    // }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            //send("KeyInfo Hook failed: " + err);
        }
    } else {
        //send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            //send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            //send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                //send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                //send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                //send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                //send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                //send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                //send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            //send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            //send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            //send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                //send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            //send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                //send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                //send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                //send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            //send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            //send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    //send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    //send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    //send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    //send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            //send("Bypass isInsideSecureHardware");
            return true;
        }
    }
}

function hookNetworkTraffic() {
    // Interceptor.attach(Module.findExportByName('libssl.so', 'SSL_write'), {
    //     onEnter: function(args) {
    //         console.log('[NETWORK_TRAFFIC_HOOKS] SSL_write Hooked!');

    //         try {
    //             var data = Memory.readUtf8String(args[1], args[2].toInt32());
    //             console.log('[NETWORK_TRAFFIC_HOOKS] Data Sent: ' + data);
    //             // Attempt to get Java stack trace if running from Java
    //             try {
    //                 Java.perform(function() {
    //                     console.log('[NETWORK_TRAFFIC_HOOKS] Java Stack Trace:');
    //                     console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //                 });
    //             } catch (e) {
    //                 console.log('[NETWORK_TRAFFIC_HOOKS] Could not get Java stack trace:', e);
    //             }
    //         } 
    //         catch (e) {
    //             console.log('[NETWORK_TRAFFIC_HOOKS] ', e);
    //         }
            
    //         console.log('---------------------------------------------------');
    //     }
    // });
    const F_GETFL = 3;
    const S_IFSOCK = 0xC000; // socket file type mask
    const S_IFMT = 0xF000;   // file type mask

    // Native syscall to get file descriptor info
    const fstat = new NativeFunction(
        Module.findExportByName(null, "fstat"),
        'int',
        ['int', 'pointer']
    );

    // Native getsockopt() to check if the fd is a socket
    const getsockopt = new NativeFunction(
        Module.findExportByName(null, 'getsockopt'),
        'int',
        ['int', 'int', 'int', 'pointer', 'pointer']
    );

    const SOL_SOCKET = 1;
    const SO_TYPE = 3;

    Interceptor.attach(Module.findExportByName(null, 'write'), {
        onEnter: function (args) {
            const fd = args[0].toInt32();
            const buf = args[1];
            const count = args[2].toInt32();

            // Prepare to call getsockopt(fd, SOL_SOCKET, SO_TYPE, ...)
            const optval = Memory.alloc(4); // int
            const optlen = Memory.alloc(4); // socklen_t
            optlen.writeU32(4);

            const result = getsockopt(fd, SOL_SOCKET, SO_TYPE, optval, optlen);

            if (result !== 0) {
                // Not a socket or error occurred
                return;
            }

            const socketType = optval.readU32();

            // Only proceed for SOCK_STREAM (TCP): 1
            if (socketType !== 1) return;

            // This is a TCP socket write
            const rawData = Memory.readByteArray(buf, count);
            // var data = Memory.readUtf8String(buf, count);

            console.log('\n[+] write() to network socket (fd=' + fd + ', size=' + count + ')');

            // Print hexdump
            // console.log(hexdump(buf, {
            //     length: count,
            //     header: true,
            //     ansi: true
            // }));



            // Try best-effort printable string
            const ascii = tryToAscii(rawData);
            if (ascii.trim().length > 0) {
                console.log('[ASCII output]:\n' + ascii);
            }
        }
    });
}

// Helper to safely convert binary buffer to printable ASCII
function tryToAscii(byteArray) {
    return Array.from(new Uint8Array(byteArray))
        .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
        .join('');
}

Java.perform(function () {
    antiFridaBypass();
    const hookTargets = [
        "android.accounts.AccountManager.addAccount",
        "android.accounts.AccountManager.getAccounts",
        "android.accounts.AccountManager.getAccountsByType",
        "android.accounts.AccountManager.getAccountsByTypeAndFeatures",
        "android.accounts.AccountManager.getAccountsByTypeForPackage",
        "android.accounts.AccountManager.getAuthToken",
        "android.accounts.AccountManager.getPassword",
        "android.accounts.AccountManager.getPreviousName",
        "android.accounts.AccountManager.getUserData",
        "android.accounts.AccountManager.setPassword",
        "android.accounts.AccountManager.setUserData",
        "android.app.ActivityManager.getRecentTasks",
        "android.app.ActivityManager.getRunningAppProcesses",
        "android.app.ActivityManager.getRunningTasks",
        "android.app.AppOpsManager.startWatchingMode",
        "android.app.AppOpsManager.startWatchingStarted",
        "android.app.usage.UsageStatsManager.getAppStandbyBucket",
        "android.app.WallpaperManager.getDrawable",
        "android.bluetooth.BluetoothA2dp.getConnectedDevices",
        "android.bluetooth.BluetoothA2dp.getDevicesMatchingConnectionStates",
        "android.bluetooth.BluetoothAdapter.getAddress",
        "android.bluetooth.BluetoothAdapter.getBondedDevices",
        "android.bluetooth.BluetoothAdapter.getName",
        "android.bluetooth.BluetoothDevice.getName",
        "android.bluetooth.BluetoothDevice.getType",
        "android.bluetooth.BluetoothDevice.getUuids",
        "android.bluetooth.BluetoothHeadset.getConnectedDevices",
        "android.bluetooth.BluetoothHearingAid.getDevicesMatchingConnectionStates",
        "android.bluetooth.BluetoothManager.getConnectedDevices",
        "android.bluetooth.BluetoothManager.getDevicesMatchingConnectionStates",
        "android.content.ContentProvider.openAssetFile",
        "android.content.ContentProvider.openTypedAssetFile",
        "android.content.ContentResolver.query",
        "android.location.LocationManager.addGpsStatusListener",
        "android.location.LocationManager.addNmeaListener",
        "android.location.LocationManager.getCurrentLocation",
        "android.location.LocationManager.getLastKnownLocation",
        "android.location.LocationManager.registerGnssStatusCallback",
        "android.location.LocationManager.requestLocationUpdates",
        "android.location.LocationManager.requestSingleUpdate",
        "android.media.RingtoneManager.getRingtone",
        "android.net.wifi.WifiInfo.getBSSID",
        "android.net.wifi.WifiInfo.getSSID",
        "android.os.BatteryManager.getLongProperty",
        "android.os.Build.getSerial",
        "android.os.Debug.getMemoryInfo",
        "android.os.Debug.getNativeHeapAllocatedSize",
        "android.os.Debug.getNativeHeapFreeSize",
        "android.os.Debug.getNativeHeapSize",
        "android.os.Debug.getRuntimeStat",
        "android.os.health.HealthStats.getMeasurement",
        "android.os.health.HealthStats.getStats",
        "android.os.PowerManager.getCurrentThermalStatus",
        "android.os.StrictMode.getThreadPolicy",
        "android.os.StrictMode.getVmPolicy",
        "android.telecom.TelecomManager.getCallCapablePhoneAccounts",
        "android.telecom.TelecomManager.getDefaultOutgoingPhoneAccount",
        "android.telecom.TelecomManager.isVoiceMailNumber",
        "android.telephony.PhoneNumberUtils.isVoiceMailNumber",
        "android.telephony.PhoneStateListener.onCellInfoChanged",
        "android.telephony.PhoneStateListener.onCellLocationChanged",
        "android.telephony.SubscriptionInfo.getIccId",
        "android.telephony.SubscriptionManager.getActiveSubscriptionInfo",
        "android.telephony.SubscriptionManager.getActiveSubscriptionInfoForSimSlotIndex",
        "android.telephony.SubscriptionManager.getActiveSubscriptionInfoList",
        "android.telephony.TelephonyManager.getAllCellInfo",
        "android.telephony.TelephonyManager.getCardIdForDefaultEuicc",
        "android.telephony.TelephonyManager.getCellLocation",
        "android.telephony.TelephonyManager.getDataNetworkType",
        "android.telephony.TelephonyManager.getDeviceId",
        "android.telephony.TelephonyManager.getDeviceSoftwareVersion",
        "android.telephony.TelephonyManager.getGroupIdLevel1",
        "android.telephony.TelephonyManager.getImei",
        "android.telephony.TelephonyManager.getLine1Number",
        "android.telephony.TelephonyManager.getMeid",
        "android.telephony.TelephonyManager.getNeighboringCellInfo",
        "android.telephony.TelephonyManager.getNetworkCountryIso",
        "android.telephony.TelephonyManager.getNetworkOperator",
        "android.telephony.TelephonyManager.getNetworkOperatorName",
        "android.telephony.TelephonyManager.getPhoneCount",
        "android.telephony.TelephonyManager.getServiceState",
        "android.telephony.TelephonyManager.getSimSerialNumber",
        "android.telephony.TelephonyManager.getSimSpecificCarrierId",
        "android.telephony.TelephonyManager.getSubscriberId",
        "android.telephony.TelephonyManager.getVisualVoicemailPackageName",
        "android.telephony.TelephonyManager.getVoiceMailNumber",
        "android.telephony.TelephonyManager.getVoiceNetworkType",
        "android.telephony.TelephonyManager.requestCellInfoUpdate",
        "java.io.File.getFreeSpace",
        "java.io.File.getTotalSpace",
        "java.io.File.getUsableSpace",
        "java.net.NetworkInterface.getHardwareAddress"
    ];

    hookTargets.forEach(className => {
        setTimeout(() => traceMethod(className), 10);
    });

    // hookNetworkTraffic();

}, 0);


package envcloak;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Hooker {
    // Backup methods for original implementations
    public static Method backupGetInstallerPackageName;
    public static Method backupLoadClass;

    // Backup methods for InstallSourceInfo (Android 11+)
    public static Method backupGetInstallingPackageName;
    public static Method backupGetInitiatingPackageName;

    // Backup methods for Settings.*.getStringForUser
    public static Method backupSecureGetStringForUser;
    public static Method backupSystemGetStringForUser;
    public static Method backupGlobalGetStringForUser;
    public static Method backupNameValueCacheGetStringForUser;

    // Backup methods for android.os.SystemProperties native getters
    public static Method backupSystemPropertiesNativeGet1;
    public static Method backupSystemPropertiesNativeGet2;
    public static Method backupSystemPropertiesNativeGetInt;
    public static Method backupSystemPropertiesNativeGetLong;
    public static Method backupSystemPropertiesNativeGetBoolean;

    // Backup methods for ProcessImpl.start() and ProcessManager.exec()
    public static Method backupProcessImplStart;
    public static Method backupProcessManagerExec;
    // Some Android versions/ROMs have multiple overloads; keep all backups to match hookAllMethods behavior.
    public static Method[] backupProcessImplStartAll;
    public static Method[] backupProcessManagerExecAll;

    // ==== ImNotADeveloper: keys / overrides ====
    private static final Set<String> SETTINGS_BANNED_KEYS = new HashSet<>(Arrays.asList(
            "development_settings_enabled",
            "adb_enabled",
            "adb_wifi_enabled"
    ));

    // Same overrides as reference project (used both for SystemProperties and getprop command masking)
    private static final Map<String, String> PROP_OVERRIDES = new HashMap<>();

    static {
        PROP_OVERRIDES.put("sys.usb.ffs.ready", "0");
        PROP_OVERRIDES.put("sys.usb.config", "mtp");
        PROP_OVERRIDES.put("persist.sys.usb.config", "mtp");
        PROP_OVERRIDES.put("sys.usb.state", "mtp");
        PROP_OVERRIDES.put("init.svc.adbd", "stopped");
    }

    // Native callback to notify C++ when target class is loaded
    public static native void onClassLoaded(Class<?> clazz);

    private static Object callBackup(Method backup, Object[] args) throws Throwable {
        if (backup == null) return null;

        boolean isStatic = Modifier.isStatic(backup.getModifiers());
        Object thiz = null;
        Object[] realArgs = args;

        // For non-static methods, lsplant usually passes args[0] as "this".
        // But to be defensive across versions/bridges, detect if args[0] is instance of declaring class.
        if (!isStatic && args != null && args.length > 0 && args[0] != null && backup.getDeclaringClass().isInstance(args[0])) {
            thiz = args[0];
            realArgs = Arrays.copyOfRange(args, 1, args.length);
        }

        try {
            return backup.invoke(isStatic ? null : thiz, realArgs);
        } catch (InvocationTargetException e) {
            // Unwrap original exception so lsplant can propagate correctly.
            Throwable cause = e.getCause();
            throw (cause != null) ? cause : e;
        }
    }

    private static Object callAnyBackup(Method[] backups, Method singleBackup, Object[] args) throws Throwable {
        if (backups != null) {
            for (Method m : backups) {
                if (m == null) continue;
                try {
                    return callBackup(m, args);
                } catch (IllegalArgumentException ignored) {
                    // Signature mismatch (e.g. different overload); try next.
                }
            }
        }
        return callBackup(singleBackup, args);
    }

    private static String firstStringArg(Object[] args) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof String) return (String) a;
        }
        return null;
    }

    // ===================== Existing hooks =====================
    public Object hookGetInstallerPackageName(Object[] args) {
        return "com.android.vending";
    }

    public Object hookGetInstallingPackageName(Object[] args) {
        return "com.android.vending";
    }

    public Object hookGetInitiatingPackageName(Object[] args) {
        return "com.android.vending";
    }

    public Object hookLoadClass(Object[] args) throws Throwable {
        Class<?> clazz = (Class<?>) callBackup(backupLoadClass, args);
        return clazz;
    }

    // ===================== ImNotADeveloper ports =====================

    private Object hookSettingsGetStringForUserInternal(Method backup, Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null && SETTINGS_BANNED_KEYS.contains(key)) {
            return "0";
        }
        return callBackup(backup, args);
    }

    public Object hookSecureGetStringForUser(Object[] args) throws Throwable {
        return hookSettingsGetStringForUserInternal(backupSecureGetStringForUser, args);
    }

    public Object hookSystemGetStringForUser(Object[] args) throws Throwable {
        return hookSettingsGetStringForUserInternal(backupSystemGetStringForUser, args);
    }

    public Object hookGlobalGetStringForUser(Object[] args) throws Throwable {
        return hookSettingsGetStringForUserInternal(backupGlobalGetStringForUser, args);
    }

    public Object hookNameValueCacheGetStringForUser(Object[] args) throws Throwable {
        return hookSettingsGetStringForUserInternal(backupNameValueCacheGetStringForUser, args);
    }

    public Object hookSystemPropertiesNativeGet1(Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null) {
            String v = PROP_OVERRIDES.get(key);
            if (v != null) return v;
        }
        return callBackup(backupSystemPropertiesNativeGet1, args);
    }

    public Object hookSystemPropertiesNativeGet2(Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null) {
            String v = PROP_OVERRIDES.get(key);
            if (v != null) return v;
        }
        return callBackup(backupSystemPropertiesNativeGet2, args);
    }

    public Object hookSystemPropertiesNativeGetInt(Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null) {
            String v = PROP_OVERRIDES.get(key);
            if (v != null) {
                try {
                    return Integer.parseInt(v);
                } catch (NumberFormatException ignored) { }
            }
        }
        return callBackup(backupSystemPropertiesNativeGetInt, args);
    }

    public Object hookSystemPropertiesNativeGetLong(Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null) {
            String v = PROP_OVERRIDES.get(key);
            if (v != null) {
                try {
                    return Long.parseLong(v);
                } catch (NumberFormatException ignored) { }
            }
        }
        return callBackup(backupSystemPropertiesNativeGetLong, args);
    }

    public Object hookSystemPropertiesNativeGetBoolean(Object[] args) throws Throwable {
        String key = firstStringArg(args);
        if (key != null) {
            String v = PROP_OVERRIDES.get(key);
            if (v != null) {
                return v.equalsIgnoreCase("true") || v.equals("1");
            }
        }
        return callBackup(backupSystemPropertiesNativeGetBoolean, args);
    }

    private void maskGetProp(Object[] args) {
        if (args == null) return;
        int cmdIdx = -1;
        String[] cmd = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i] instanceof String[]) {
                cmd = (String[]) args[i];
                cmdIdx = i;
                break;
            }
        }
        if (cmd == null || cmd.length < 2) return;
        if (!"getprop".equals(cmd[0])) return;
        String key = cmd[1];
        if (!PROP_OVERRIDES.containsKey(key)) return;

        String[] newCmd = Arrays.copyOf(cmd, cmd.length);
        newCmd[1] = "Dummy" + System.currentTimeMillis();
        args[cmdIdx] = newCmd;
    }

    public Object hookProcessImplStart(Object[] args) throws Throwable {
        maskGetProp(args);
        return callAnyBackup(backupProcessImplStartAll, backupProcessImplStart, args);
    }

    public Object hookProcessManagerExec(Object[] args) throws Throwable {
        maskGetProp(args);
        return callAnyBackup(backupProcessManagerExecAll, backupProcessManagerExec, args);
    }
}


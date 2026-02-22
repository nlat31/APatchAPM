package sample;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class Hooker {
    private static final String TAG = "Sample/Hooker";

    public static Method backupSystemLoadLibrary;

    private static void logI(String msg) {
        try {
            Class<?> log = Class.forName("android.util.Log");
            Method i = log.getMethod("i", String.class, String.class);
            i.invoke(null, TAG, msg);
        } catch (Throwable ignored) {
        }
    }

    private static String firstStringArg(Object[] args) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof String) return (String) a;
        }
        return null;
    }

    private static Object callBackup(Method backup, Object[] args) throws Throwable {
        if (backup == null) return null;

        boolean isStatic = Modifier.isStatic(backup.getModifiers());
        Object thiz = null;
        Object[] realArgs = args;

        if (!isStatic && args != null && args.length > 0 && args[0] != null && backup.getDeclaringClass().isInstance(args[0])) {
            thiz = args[0];
            realArgs = new Object[args.length - 1];
            System.arraycopy(args, 1, realArgs, 0, realArgs.length);
        }

        try {
            return backup.invoke(isStatic ? null : thiz, realArgs);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw (cause != null) ? cause : e;
        }
    }

    // Hook target: java.lang.System.loadLibrary(String)
    public Object hookSystemLoadLibrary(Object[] args) throws Throwable {
        String lib = firstStringArg(args);
        logI("System.loadLibrary: " + lib);
        callBackup(backupSystemLoadLibrary, args);
        return null;
    }
}


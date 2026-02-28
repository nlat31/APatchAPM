package shadowso;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class Hooker {
    private static final String TAG = "shadowso";

    public static Method backupActivityThreadMain;

    private static void logI(String msg) {
        try {
            Class<?> log = Class.forName("android.util.Log");
            Method i = log.getMethod("i", String.class, String.class);
            i.invoke(null, TAG, msg);
        } catch (Throwable ignored) {
        }
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

    // Demo hook target: android.app.ActivityThread.main(String[] args)
    // This is the app process entrypoint and is always called.
    public Object hookActivityThreadMain(Object[] args) throws Throwable {
        logI("ActivityThread.main");
        callBackup(backupActivityThreadMain, args);
        return null;
    }
}


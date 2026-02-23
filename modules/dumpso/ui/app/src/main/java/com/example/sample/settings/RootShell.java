package com.apm.dumpso;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public final class RootShell {
    private RootShell() {}

    public static final class Result {
        public final int code;
        public final String out;
        public final String err;

        public Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }
    }

    public static Result exec(String cmd) {
        Process p = null;
        try {
            p = new ProcessBuilder("su", "-c", cmd).start();
            String out = readAll(p.getInputStream());
            String err = readAll(p.getErrorStream());
            int code = p.waitFor();
            return new Result(code, out, err);
        } catch (Throwable t) {
            return new Result(1, "", String.valueOf(t));
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    public static boolean ensureRoot() {
        Result r = exec("id");
        return r.code == 0 && r.out != null && r.out.contains("uid=");
    }

    private static String readAll(java.io.InputStream is) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }
}


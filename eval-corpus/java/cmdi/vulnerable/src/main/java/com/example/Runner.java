package com.example;

public class Runner {
    /** Run a shell command. VULNERABLE: untrusted arg in a shell string. */
    public Process run(String arg) throws Exception {
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", "echo " + arg});
    }
}

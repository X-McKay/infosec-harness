package com.example;

public class Runner {
    /** Run a command. */
    public Process run(String arg) throws Exception {
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", "echo " + arg});
    }
}

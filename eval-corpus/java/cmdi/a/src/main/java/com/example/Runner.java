package com.example;

public class Runner {
    /** Run a command. */
    public Process run(String arg) throws Exception {
        return new ProcessBuilder("echo", arg).start();
    }
}

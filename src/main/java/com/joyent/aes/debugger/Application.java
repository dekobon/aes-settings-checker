package com.joyent.aes.debugger;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public class Application {
    public static void main(final String[] argv) {
        if (argv.length < 1) {
            System.err.println("Debug output file path must be specified as first argument");
            System.exit(1);
        }

        File debugFile = new File(argv[0]);

        try (Writer writer = new FileWriter(debugFile, true)) {
            writer.append("======================\n");
            writer.append("AES-NI Support Checker\n");
            writer.append("======================\n");

            final Checkable[] checkers = new Checkable[] {
                    new AesJavaChecker(writer),
                    new AesOsChecker(writer),
                    new LibnssChecker(writer)
            };

            for (Checkable checker : checkers) {
                checker.check();
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}

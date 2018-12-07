package com.joyent.aes.debugger;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class AesOsChecker implements Checkable {
    private final Writer out;

    public AesOsChecker(final Writer writer) {
        this.out = writer;
    }

    @Override
    public void check() throws IOException {
        logUnameOutput();
        logFileIfExists("/etc/lsb-release");
        logFileIfExists("/etc/redhat-release");
        logFileIfExists("/etc/centos-release");
        logFileIfExists("/etc/debian_version");
        logFileIfExists("/etc/issue");

        System.out.printf("AES support shown in /proc/cpuinfo: %b\n",
                hasSupportAsDetectedByProcCpuInfo());
        System.out.printf("AES support shown in lscpu: %b\n",
                hasSupportAsDetectedByLscpu());
        System.out.printf("AES support shown in /proc/crypto: %b\n",
                hasSupportAsDetectedByProcCrypto());
        out.append("\n");
    }

    private void logUnameOutput() throws IOException {
        out.append("[[Start uname -a output]]\n");

        ProcessBuilder builder = new ProcessBuilder()
                .command("uname", "-a");

        Process process;

        try {
            process = builder.start();
        } catch (IOException e) {
            System.out.println("Error running uname");
            out.append("Error running uname:\n");
            out.append(ExceptionUtils.getStackTrace(e));
            out.append("[[End uname -a output]]\n\n");
            return;
        }

        try {
            if (process.waitFor() > 0) {
                out.append(String.format("uname exited with code %d\n",
                        process.exitValue()));
            }
        } catch (InterruptedException e) {
            System.exit(0);
        }

        IOUtils.copy(process.getInputStream(), out, StandardCharsets.UTF_8);

        out.append("[[End uname -a output]]\n\n");
    }

    private void logFileIfExists(final String filePath) throws IOException {
        File file = new File(filePath);

        if (file.exists() && file.canRead()) {
            out.append(String.format("[[Start %s]]\n", filePath));
            try (Reader in = new FileReader(file)) {
                IOUtils.copy(in, out);
            }
            out.append(String.format("[[End %s]]\n\n", filePath));
        }
    }

    private boolean hasSupportAsDetectedByLscpu() throws IOException {
        out.append("[[Start lscpu output]]\n");

        ProcessBuilder builder = new ProcessBuilder().command("lscpu");

        Process process;

        try {
            process = builder.start();
        } catch (IOException e) {
            System.out.println("Error running lscpu");
            out.append("Error running lscpu:\n");
            out.append(ExceptionUtils.getStackTrace(e));
            out.append("[[End lscpu output]]\n\n");
            return false;
        }

        try {
            if (process.waitFor() > 0) {
                out.append(String.format("lscpu exited with code %d\n",
                        process.exitValue()));
            }
        } catch (InterruptedException e) {
            System.exit(0);
        }

        boolean aesDetected = false;

        try (Scanner s = new Scanner(process.getInputStream())) {
            String line;
            while (s.hasNextLine()) {
                line = s.nextLine();
                out.append(line).append("\n");

                if (line.startsWith("Flags: ")) {
                    for (String flag : line.split("\\s+")) {
                        if (flag.equals("aes")) {
                            aesDetected = true;
                            break;
                        }
                    }
                }
            }
        }

        out.append("[[End lscpu output]]\n");
        out.append(String.format("[[lscpu detected aes: %b]]\n\n", aesDetected));

        return aesDetected;
    }

    private boolean hasSupportAsDetectedByProcCpuInfo() throws IOException {
        final String procFilePath = "/proc/cpuinfo";
        final File procFile = new File(procFilePath);

        out.append("[[Start ").append(procFilePath).append("]]\n");

        int cpuFlagCountLines = 0;
        int cpuFlagCountLinesWithAes = 0;

        try (Scanner s = new Scanner(procFile)) {
            String line;
            while (s.hasNextLine()) {
                line = s.nextLine();
                out.append(line).append("\n");

                if (line.startsWith("flags")) {
                    cpuFlagCountLines++;
                    String flagsLine = StringUtils.substringAfter(line, "\t\t: ");
                    for (String flag : StringUtils.split(flagsLine, " ")) {
                        if (flag.equals("aes")) {
                            cpuFlagCountLinesWithAes++;
                            break;
                        }
                    }
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("Could not find cpuinfo data at path: " + procFilePath);
            return false;
        }

        out.append("[[End ").append(procFilePath).append("]]\n");
        out.append(String.format("[[ cpus: %d cpus with aes: %d]]\n\n",
                cpuFlagCountLines, cpuFlagCountLinesWithAes));

        return cpuFlagCountLinesWithAes > 0 && cpuFlagCountLines == cpuFlagCountLinesWithAes;
    }

    private boolean hasSupportAsDetectedByProcCrypto() throws IOException {
        final String procFilePath = "/proc/crypto";
        final File procFile = new File(procFilePath);

        out.append("[[Start ").append(procFilePath).append("]]\n");

        boolean hasAesniIntel = false;
        boolean hasAes86_64 = false;

        try (Scanner s = new Scanner(procFile)) {
            String line;
            while (s.hasNextLine()) {
                line = s.nextLine();
                out.append(line).append("\n");

                if (line.endsWith(": aesni_intel")) {
                    hasAesniIntel = true;
                }
                if (line.endsWith(": aes_x86_64")) {
                    hasAes86_64 = true;
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("Could not find crypto data at path: " + procFilePath);
            return false;
        }

        out.append("[[End ").append(procFilePath).append("]]\n");
        out.append(String.format("[[ aesni_intel: %b aes_x86_64: %b]]\n\n",
                hasAesniIntel, hasAes86_64));

        return hasAesniIntel && hasAes86_64;
    }
}

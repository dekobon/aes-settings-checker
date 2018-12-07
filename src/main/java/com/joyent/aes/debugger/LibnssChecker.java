package com.joyent.aes.debugger;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;

public class LibnssChecker implements Checkable {
    private final Writer out;

    public LibnssChecker(final Writer writer) {
        this.out = writer;
    }

    @Override
    public void check() throws IOException {
        logLibNssPackage();
        System.out.printf("Libnss configured in java security settings: %b\n",
                detectLibNssInJavaSecuritySettings());
    }

    @SuppressWarnings("Duplicates")
    private void logLibNssPackage() throws IOException {
        out.append("[[Libnss package details]]\n");

        ProcessBuilder processBuilder = new ProcessBuilder()
                .command("dpkg", "-s", "libnss3");

        Process process;

        try {
            process = processBuilder.start();

            if (process.waitFor() > 0) {
                out.append(String.format("dpkg exited with code %d\n",
                        process.exitValue()));
            }

            IOUtils.copy(process.getInputStream(), out, StandardCharsets.UTF_8);

            out.append("[[End libnss package details]]\n\n");

            return;
        } catch (IOException e) {
            out.append("Error running dpkg:\n");
            out.append(ExceptionUtils.getStackTrace(e));
        } catch (InterruptedException e) {
            System.exit(0);
        }

        processBuilder = new ProcessBuilder()
                .command("yum", "info", "nss", "binutils");

        try {
            process = processBuilder.start();

            if (process.waitFor() > 0) {
                out.append(String.format("yum exited with code %d\n",
                        process.exitValue()));
            }

            IOUtils.copy(process.getInputStream(), out, StandardCharsets.UTF_8);

            out.append("[[End libnss package details]]\n\n");

            return;
        } catch (IOException e) {
            out.append("Error running yum:\n");
            out.append(ExceptionUtils.getStackTrace(e));
        } catch (InterruptedException e) {
            System.exit(0);
        }

        out.append("[[End libnss package details]]\n\n");
    }

    private boolean detectLibNssInJavaSecuritySettings() throws IOException {
        out.append("[[Security settings file]]\n");

        Optional<Path> settingsPath;

        try {
            settingsPath = findJavaSecurityFilePath();
        } catch (IOException | RuntimeException e) {
            out.append(String.format("Error finding java.security file\n"));
            out.append(ExceptionUtils.getStackTrace(e));
            out.append("\n");
            return false;
        }

        if (!settingsPath.isPresent()) {
            out.append(String.format("Couldn't find java.security file\n"));
            return false;
        }

        File settingsFile = settingsPath.get().toFile();

        if (!settingsFile.exists()) {
            out.append(String.format("%s doesn't exist\n", settingsFile));
            return false;
        }

        if (!settingsFile.canRead()) {
            out.append(String.format("Can't read: %s\n", settingsFile));
            return false;
        }

        boolean foundLibNssDefinition = false;
        int nssProviderRank = -1;
        List<NSSConfig> nssConfigs = new ArrayList<>();

        try (Scanner scanner = new Scanner(settingsFile)) {
            String line;
            while (scanner.hasNextLine()) {
                line = scanner.nextLine();
                out.append(line).append("\n");

                if (line.startsWith("#")) {
                    continue;
                }

                // First, see if a PKCS11 provider is specified
                if (line.contains("sun.security.pkcs11.SunPKCS11")) {
                    // See if we can parse the line
                    try {
                        ProviderLine providerLine = ProviderLine.parse(line);
                        // If it has a config specified, then it is probably a NSS provider
                        if (StringUtils.isNotBlank(providerLine.config)) {
                            NSSConfig nssConfig;

                            // Try to parse the config file to see if it is a NSS provider
                            try {
                                nssConfig = NSSConfig.parseFromFilePath(providerLine.config);
                            } catch (RuntimeException e) {
                                out.append("Error parsing NSS config file\n");
                                out.append(ExceptionUtils.getStackTrace(e));
                                continue;
                            }

                            // We always add it to the list of configs, so that we can dump its contents
                            nssConfigs.add(nssConfig);

                            foundLibNssDefinition = nssConfig.nssLibraryInstalled;

                            if (foundLibNssDefinition && nssProviderRank < 0) {
                                nssProviderRank = providerLine.rank;
                            }
                        } else {
                            foundLibNssDefinition = false;
                        }
                    } catch (RuntimeException e) {
                        out.append("Problem parsing provider\n");
                        out.append(ExceptionUtils.getStackTrace(e));
                    }
                }
            }
        }

        out.append("[[End security settings file]]\n\n");

        if (!nssConfigs.isEmpty()) {
            for (NSSConfig nssConfig : nssConfigs) {
                out.append(String.format("[[Start nss config: %s]]\n", nssConfig.file));
                out.append(Objects.toString(nssConfig.contents)).append("\n");
                out.append("[[End nss config]]\n");
                out.append(String.format("[[Start nss config detail: %s]]\n", nssConfig.file));
                out.append("\n\nNSS library information:\n\n");
                out.append(nssConfig.nssLibraryDetail);
                out.append(String.format("[[End nss config detail: %s]]\n", nssConfig.file));
            }
        }

        return foundLibNssDefinition && nssProviderRank == 1;
    }

    private static class ProviderLine {
        int rank;
        String name;
        String config;

        public ProviderLine(final int rank, final String name, final String config) {
            this.rank = rank;
            this.name = name;
            this.config = config;
        }

        static ProviderLine parse(final String line) {
            String afterPrefix = StringUtils.substringAfter(line, "security.provider.");
            String[] splitAtEqual = afterPrefix.split("=");
            String rank = splitAtEqual[0];
            String provider = StringUtils.substringBefore(splitAtEqual[1], " ");
            String config = StringUtils.substringAfter(afterPrefix, " ");

            return new ProviderLine(Integer.parseInt(rank), provider, config);
        }
    }

    private static class NSSConfig {
        String file;
        String name;
        String nssLibraryDirectory;
        String contents;
        String nssLibraryDetail;
        boolean nssLibraryInstalled;

        static NSSConfig parseFromFilePath(final String nssConfigPath) throws IOException {
            File file = new File(nssConfigPath);
            StringBuilder builder = new StringBuilder();

            NSSConfig config = new NSSConfig();
            config.file = nssConfigPath;

            try (Scanner scanner = new Scanner(file)) {
                String line;
                while (scanner.hasNextLine()) {
                    line = scanner.nextLine();
                    builder.append(line).append("\n");

                    if (line.startsWith("name ")) {
                        config.name = StringUtils.substringAfter(line, "=").trim();
                    }

                    if (line.startsWith("nssLibraryDirectory")) {
                        config.nssLibraryDirectory = StringUtils.substringAfter(line, "=").trim();
                    }
                }
            }

            config.contents = builder.toString();
            builder.setLength(0);

            if (StringUtils.isNotBlank(config.nssLibraryDirectory)) {
                config.nssLibraryInstalled = nssLibraryIsInstalled(builder, config.nssLibraryDirectory);
            } else {
                config.nssLibraryInstalled = false;
                config.nssLibraryDetail = "";
            }

            config.nssLibraryDetail = builder.toString();

            return config;
        }

        @SuppressWarnings("Duplicates")
        private static boolean nssLibraryIsInstalled(final StringBuilder builder,
                                                     final String nssLibraryDirectory) throws IOException {
            File nssLibDir = new File(nssLibraryDirectory);

            if (!nssLibDir.exists()) {
                builder.append(nssLibraryDirectory).append(" does not exist");
                return false;
            }

            if (!nssLibDir.canRead()) {
                builder.append("Can't read: ").append(nssLibraryDirectory);
                return false;
            }
            String libNssPath = nssLibraryDirectory + File.separator + "libnss3.so";
            File libNss = new File(libNssPath);

            if (!libNss.exists()) {
                builder.append(nssLibraryDirectory).append(" does not exist");
                return false;
            }

            if (!libNss.canRead()) {
                builder.append("Can't read: ").append(libNss);
                return false;
            }

            ProcessBuilder processBuilder = new ProcessBuilder().command("ldd", libNssPath);
            Process process;

            try {
                process = processBuilder.start();
            } catch (IOException e) {
                builder.append("Error running ldd:\n");
                builder.append(ExceptionUtils.getStackTrace(e));
                builder.append("[[End uname -a output]]\n\n");
                return false;
            }

            try {
                if (process.waitFor() > 0) {
                    builder.append(String.format("ldd exited with code %d\n",
                            process.exitValue()));
                }
            } catch (InterruptedException e) {
                System.exit(0);
            }

            try (Scanner scanner = new Scanner(process.getInputStream())) {
                while (scanner.hasNextLine()) {
                    builder.append(scanner.nextLine()).append("\n");
                }
            }

            return true;
        }
    }

    private Optional<Path> findJavaSecurityFilePath() throws IOException {
        final Path basepath = new File(SystemUtils.JAVA_HOME).toPath();
        final String filename = "java.security";

        return Files.find(basepath, 8, (p, b) -> {
            if (b.isDirectory()) {
                return false;
            }

            return p.endsWith(filename);
        }).findFirst();
    }
}

package com.joyent.aes.debugger;

import java.io.IOException;
import java.io.Writer;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;

public class AesJavaChecker implements Checkable {
    private final Writer out;

    public AesJavaChecker(final Writer writer) {
        this.out = writer;
    }

    @Override
    public void check() throws IOException {
        logJvmSystemProperties();
        logEnv();
        logSecurityProviders();
    }

    private void logJvmSystemProperties() throws IOException {
        out.append("[[Start Java System Properties]]\n");
        for (String key : System.getProperties().stringPropertyNames()) {
            String val = System.getProperty(key).toString();
            out.append(key).append(" : ").append(val).append("\n");
        }
        out.append("[[End Java System Properties]]\n\n");
    }

    private void logEnv() throws IOException {
        out.append("[[Start Environment]]\n");
        for (String key : System.getenv().keySet()) {
            String val = System.getenv(key);
            out.append(key).append(" : ").append(val).append("\n");
        }
        out.append("[[End Environment]]\n\n");
    }

    private void logSecurityProviders() throws IOException {
        out.append("[[Security Providers]]\n");
        for (Provider provider : Security.getProviders()) {
            String name = String.format("%s@%f:\n", provider.getName(),
                    provider.getVersion());
            out.append(name).append("----\n");
            out.append(provider.getInfo()).append("\n----\n");

            for (Object key: provider.keySet()) {
                String valAsString = Objects.toString(provider.get(key));
                out.append("    ").append(key.toString())
                   .append(" : ").append(valAsString).append("\n");
            }
            out.append("\n");
        }
        out.append("[[Security providers Environment]]\n\n");
    }
}

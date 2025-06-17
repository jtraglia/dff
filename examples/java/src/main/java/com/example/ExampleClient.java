package com.example;

import java.security.MessageDigest;

import com.github.jtraglia.dff.Client;
import com.github.jtraglia.dff.ProcessFunc;

/**
 * Example usage of the DFF Java client.
 *
 * This example demonstrates how to use the client to connect to a fuzzing server
 * and process inputs using the SHA256 method.
 */
public class ExampleClient {

    /**
     * Example processing function that supports the "sha" method.
     */
    private static class ExampleProcessFunc implements ProcessFunc {

        @Override
        public byte[] process(String method, byte[][] inputs) throws Exception {
            switch (method) {
                case "sha":
                    if (inputs.length == 0) {
                        throw new IllegalArgumentException("No inputs provided");
                    }
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    return digest.digest(inputs[0]);

                default:
                    throw new IllegalArgumentException("Unknown method: " + method);
            }
        }
    }

    public static void main(String[] args) {
        Client client = new Client("java", new ExampleProcessFunc());

        try {
            client.connect();
            client.run();
        } catch (Exception e) {
            System.err.printf("Error: %s%n", e.getMessage());
        } finally {
            client.close();
        }
    }
}

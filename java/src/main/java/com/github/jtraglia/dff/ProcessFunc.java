package com.github.jtraglia.dff;

/**
 * ProcessFunc defines the signature for functions that process fuzzing inputs.
 * Users of the library must provide an implementation of this interface.
 */
@FunctionalInterface
public interface ProcessFunc {
    /**
     * Process fuzzing inputs and return the result.
     * 
     * @param method the fuzzing method name received from the server
     * @param inputs array of input byte arrays to process
     * @return the processed result as a byte array
     * @throws Exception if processing fails
     */
    byte[] process(String method, byte[][] inputs) throws Exception;
}
package org.jvnet.libpam;

/**
 * Exception in PAM invocations.
 *
 * @author Kohsuke Kawaguchi
 */
public class PAMException extends Exception {
    public PAMException(String message) {
        super(message);
    }
}

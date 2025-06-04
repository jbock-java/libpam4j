package org.jvnet.libpam;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

@FieldOrder({"resp", "resp_retcode"})
public class StructPamResponse extends Structure {

    public static final int SIZE = new StructPamResponse().size();

    /**
     * This is really a string, but this field needs to be malloc-ed by the conversation
     * method, and to be freed by the caller, so I bind it to {@link Pointer} here.
     *
     * <p>The man page doesn't say that, but see
     * <a href="http://www.netbsd.org/docs/guide/en/chap-pam.html#pam-sample-conv">chap-pam.html</a>
     * This behavior is confirmed with a test, too; if I don't do strdup,
     * libpam crashes.
     */
    public Pointer resp;
    public int resp_retcode;

    /**
     * Attach to the memory region pointed by the given memory.
     */
    public StructPamResponse(Pointer src) {
        useMemory(src);
        read();
    }

    public StructPamResponse() {
    }

    /**
     * Sets the response code.
     */
    public void setResp(CLibrary libc, String msg) {
        this.resp = libc.strdup(msg);
    }
}

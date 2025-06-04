package org.jvnet.libpam;

import com.sun.jna.Callback;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

@FieldOrder({"conv", "__"})
public class StructPamConv extends Structure {
    public interface PamCallback extends Callback {
        /**
         * According to <a href="http://www.netbsd.org/docs/guide/en/chap-pam.html#pam-sample-conv">chap-pam.html</a>,
         * resp and its member string both needs to be allocated by malloc,
         * to be freed by the caller.
         */
        int callback(int num_msg, Pointer msg, Pointer resp, Pointer __);
    }

    public PamCallback conv;
    public Pointer __;

    public StructPamConv(PamCallback conv) {
        this.conv = conv;
    }
}

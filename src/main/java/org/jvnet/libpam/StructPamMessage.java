package org.jvnet.libpam;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

@FieldOrder({"msg_style", "msg"})
public class StructPamMessage extends Structure {
    public int msg_style;
    public String msg;

    /**
     * Attach to the memory region pointed by the given pointer.
     */
    public StructPamMessage(Pointer src) {
        useMemory(src);
        read();
    }
}

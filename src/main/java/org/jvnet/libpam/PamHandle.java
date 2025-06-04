package org.jvnet.libpam;

import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

// pam_handle_t
public class PamHandle extends PointerType {
    @SuppressWarnings("unused")
    public PamHandle() {
    }

    public PamHandle(Pointer pointer) {
        super(pointer);
    }
}

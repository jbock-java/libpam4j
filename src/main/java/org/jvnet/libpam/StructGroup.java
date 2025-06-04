package org.jvnet.libpam;

import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

@FieldOrder({"gr_name"})
public class StructGroup extends Structure {
    public String gr_name;
    // ... the rest of the field is not interesting for us
}

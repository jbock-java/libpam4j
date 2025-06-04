package org.jvnet.libpam;

import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;

/**
 * Comparing <a href="http://linux.die.net/man/3/getpwnam">getpwnam</a>
 * and my Mac OS X reveals that the structure of this field isn't very portable.
 * In particular, we cannot read the real name reliably.
 */
@FieldOrder({"pw_name", "pw_passwd", "pw_uid", "pw_gid", "pw_gecos", "pw_dir", "pw_shell"})
public class StructPasswd extends Structure {

    /**
     * User name.
     */
    public String pw_name;
    /**
     * Encrypted password.
     */
    public String pw_passwd;
    public int pw_uid;
    public int pw_gid;

    /* Honeywell login info */
    public String pw_gecos;

    /* home directory */
    public String pw_dir;

    /* default shell */
    public String pw_shell;

    // ... there are a lot more fields

    public String getPwName() {
        return pw_name;
    }

    public String getPwPasswd() {
        return pw_passwd;
    }

    public int getPwUid() {
        return pw_uid;
    }

    public int getPwGid() {
        return pw_gid;
    }

    public String getPwGecos() {
        return pw_gecos;
    }

    public String getPwDir() {
        return pw_dir;
    }

    public String getPwShell() {
        return pw_shell;
    }
}

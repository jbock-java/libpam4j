package org.jvnet.libpam;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * @author Kohsuke Kawaguchi
 */
public interface CLibrary extends Library {

    Pointer calloc(int count, int size);

    Pointer strdup(String s);

    StructPasswd getpwnam(String username);

    int getpwnam_r(String username, Pointer pwdStruct, Pointer buf, int bufSize, PointerByReference result);

    /**
     * Lists up group IDs of the given user. On Linux and most BSDs, but not on Solaris.
     * See <a href="http://www.gnu.org/software/hello/manual/gnulib/getgrouplist.html">getgrouplist.html</a>
     */
    int getgrouplist(String user, int/*gid_t*/ group, Memory groups, IntByReference ngroups);

    StructGroup getgrgid(int/*gid_t*/ gid);

    StructGroup getgrnam(String name);

    // other user/group related functions that are likely useful
    // see http://www.gnu.org/software/libc/manual/html_node/Users-and-Groups.html#Users-and-Groups
}

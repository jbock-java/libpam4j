package org.jvnet.libpam;

import com.sun.jna.Memory;
import com.sun.jna.ptr.IntByReference;

import java.util.HashSet;
import java.util.Set;

/**
 * Represents an Unix user. Immutable.
 *
 * @author Kohsuke Kawaguchi
 */
public class UnixUser {
    private final String userName;
    private final String gecos;
    private final String dir;
    private final String shell;
    private final int uid;
    private final int gid;
    private final Set<String> groups;

    UnixUser(CLibrary libc, String userName, StructPasswd pwd) throws PAMException {
        this.userName = userName;
        this.gecos = pwd.getPwGecos();
        this.dir = pwd.getPwDir();
        this.shell = pwd.getPwShell();
        this.uid = pwd.getPwUid();
        this.gid = pwd.getPwGid();

        int sz = 4; /*sizeof(gid_t)*/

        int ngroups = 64;
        Memory m = new Memory(ngroups * sz);
        IntByReference pngroups = new IntByReference(ngroups);
        if (libc.getgrouplist(userName, pwd.getPwGid(), m, pngroups) < 0) {
            // allocate a bigger memory
            m = new Memory((long) pngroups.getValue() * sz);
            if (libc.getgrouplist(userName, pwd.getPwGid(), m, pngroups) < 0)
                // shouldn't happen, but just in case.
                throw new PAMException("getgrouplist failed");
        }
        ngroups = pngroups.getValue();

        groups = new HashSet<>();
        for (int i = 0; i < ngroups; i++) {
            int gid = m.getInt((long) i * sz);
            StructGroup grp = libc.getgrgid(gid);
            if (grp == null) {
                continue;
            }
            groups.add(grp.gr_name);
        }
    }

    /**
     * Gets the unix account name. Never null.
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Gets the UID of this user.
     */
    public int getUID() {
        return uid;
    }

    /**
     * Gets the GID of this user.
     */
    public int getGID() {
        return gid;
    }

    /**
     * Gets the gecos (the real name) of this user.
     */
    public String getGecos() {
        return gecos;
    }

    /**
     * Gets the home directory of this user.
     */
    public String getDir() {
        return dir;
    }

    /**
     * Gets the shell of this user.
     */
    public String getShell() {
        return shell;
    }

    /**
     * Gets the groups that this user belongs to.
     *
     * @return
     *      never null.
     */
    public Set<String> getGroups() {
        return groups;
    }
}

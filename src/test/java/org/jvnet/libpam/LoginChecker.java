package org.jvnet.libpam;

public class LoginChecker {

    public static void main(String[] args) {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expecting 2 parameters: user, password");
        }
        try {
            UnixUser u = new PAM("login", args[0], args[1]).authenticate();
            System.out.println("uid:    " + u.getUID());
            System.out.println("gid:    " + u.getGID());
            System.out.println("name:   " + u.getUserName());
            System.out.println("groups: " + u.getGroups());
            System.out.println("gecos:  " + u.getGecos());
            System.out.println("dir:    " + u.getDir());
            System.out.println("shell:  " + u.getShell());
        } catch (PAMException e) {
            System.err.println("PAM Exception: " + e.getMessage());
            System.exit(1);
        }
    }
}

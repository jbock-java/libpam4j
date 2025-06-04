package org.jvnet.libpam;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import static com.sun.jna.Native.POINTER_SIZE;
import static org.jvnet.libpam.PAMLibrary.PAM_PROMPT_ECHO_OFF;
import static org.jvnet.libpam.PAMLibrary.PAM_SUCCESS;
import static org.jvnet.libpam.PAMLibrary.PAM_USER;

/**
 * PAM authenticator.
 *
 * <p>
 * Instances are thread unsafe. An instance cannot be reused
 * to authenticate multiple users.
 *
 * <p>
 * For an overview of PAM programming, refer to the following resources:
 *
 * <ul>
 * <li><a href="http://www.netbsd.org/docs/guide/en/chap-pam.html">NetBSD PAM programming guide</a>
 * <li><a href="http://www.kernel.org/pub/linux/libs/pam/">Linux PAM</a>
 * </ul>
 *
 * @author Kohsuke Kawaguchi
 */
public class PAM {

    private PamHandle handle;
    private int ret;

    private final String serviceName;
    private final String username;
    private final String password;

    private final PAMLibrary libpam = Native.load("pam", PAMLibrary.class);
    private final CLibrary libc = Native.load("c", CLibrary.class);

    /**
     * Creates a new authenticator.
     *
     * @param serviceName
     *      PAM service name. This corresponds to the service name that shows up
     *      in the PAM configuration,
     */
    public PAM(String serviceName, String username, String password) throws PAMException {
        this.serviceName = serviceName;
        this.username = username;
        this.password = password;
    }

    private void check(int ret, String msg) throws PAMException {
        this.ret = ret;
        if (ret != 0) {
            if (handle != null) {
                throw new PAMException(msg + " : " + libpam.pam_strerror(handle, ret));
            } else {
                throw new PAMException(msg);
            }
        }
    }

    /**
     * Authenticate the user with a password.
     *
     * @return
     *      Upon a successful authentication, return information about the user.
     * @throws PAMException
     *      If the authentication fails.
     */
    public UnixUser authenticate() throws PAMException {
        PointerByReference pointer = new PointerByReference();
        check(libpam.pam_start(serviceName, null, new StructPamConv((num_msg, msg, resp, __) -> {
            // allocates pam_response[num_msg]. the caller will free this
            Pointer m = libc.calloc(StructPamResponse.SIZE, num_msg);
            resp.setPointer(0, m);
            for (int i = 0; i < num_msg; i++) {
                StructPamMessage pm = new StructPamMessage(msg.getPointer((long) POINTER_SIZE * i));
                if (pm.msg_style == PAM_PROMPT_ECHO_OFF) {
                    StructPamResponse r = new StructPamResponse(m.share((long) StructPamResponse.SIZE * i));
                    r.setResp(libc, password);
                    r.write(); // write to (*resp)[i]
                }
            }
            return PAM_SUCCESS;
        }), pointer), "pam_start failed");
        handle = new PamHandle(pointer.getValue());
        check(libpam.pam_set_item(handle, PAM_USER, username), "pam_set_item failed");
        check(libpam.pam_authenticate(handle, 0), "pam_authenticate failed");
        check(libpam.pam_setcred(handle, 0), "pam_setcred failed");
        // several different error code seem to be used to represent authentication failures
        check(libpam.pam_acct_mgmt(handle, 0), "pam_acct_mgmt failed");

        PointerByReference r = new PointerByReference();
        check(libpam.pam_get_item(handle, PAM_USER, r), "pam_get_item failed");
        String userName = r.getValue().getString(0);
        StructPasswd pwd = libc.getpwnam(userName);
        if (pwd == null) {
            throw new PAMException("Authentication succeeded but no user information is available");
        }
        check(libpam.pam_end(handle, ret), "pam_end failed");
        return new UnixUser(libc, userName, pwd);
    }
}

package org.jvnet.libpam;

import com.sun.jna.Library;
import com.sun.jna.ptr.PointerByReference;


/**
 * libpam.so binding.
 *
 * <p>
 * See <a href="http://www.opengroup.org/onlinepubs/008329799/apdxa.htm">apdxa.htm</a>
 * for the online reference of pam_appl.h
 *
 * @author Kohsuke Kawaguchi
 */
public interface PAMLibrary extends Library {

    int pam_start(String service, String user, StructPamConv conv, PointerByReference/* pam_handle_t** */ pamh_p);

    int pam_end(PamHandle handle, int pam_status);

    int pam_set_item(PamHandle handle, int item_type, String item);

    int pam_get_item(PamHandle handle, int item_type, PointerByReference item);

    int pam_authenticate(PamHandle handle, int flags);

    int pam_setcred(PamHandle handle, int flags);

    int pam_acct_mgmt(PamHandle handle, int flags);

    String pam_strerror(PamHandle handle, int pam_error);

    int PAM_USER = 2;

    // error code
    int PAM_SUCCESS = 0;
    int PAM_CONV_ERR = 6;


    int PAM_PROMPT_ECHO_OFF = 1; /* Echo off when getting response */
    int PAM_PROMPT_ECHO_ON = 2; /* Echo on when getting response */
    int PAM_ERROR_MSG = 3; /* Error message */
    int PAM_TEXT_INFO = 4; /* Textual information */

}

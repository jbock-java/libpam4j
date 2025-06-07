/* Andrew Morgan (morgan@parc.power.net) -- a self contained `blank'
 * application
 *
 * I am not very proud of this code.  It makes use of a possibly ill-
 * defined pamh pointer to call pam_strerror() with.  The reason that
 * I was sloppy with this is historical (pam_strerror, prior to 0.59,
 * did not require a pamh argument) and if this program is used as a
 * model for anything, I should wish that you will take this error into
 * account.
 */

#include <stdio.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static int bail_out(pam_handle_t *pamh, int code, const char *fn)
{
  fprintf(stderr, "==> called %s()\n  got: `%s'\n", fn,
      pam_strerror(pamh, code));
  pam_end(pamh, PAM_SUCCESS);
  return 1;
}

int main(int argc, char **argv)
{
  pam_handle_t *pamh = NULL;
  char *username = NULL;
  int retcode;
  struct pam_conv conv = {
    misc_conv,
    NULL
  };

  /* did the user call with a username as an argument ? */
  if (argc == 2) {
    username = argv[1];
  } else {
    fprintf(stderr, "usage: %s [username]\n", argv[0]);
    return 1;
  }

  /* initialize the Linux-PAM library */
  retcode = pam_start("login", username, &conv, &pamh);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_start");
  }

  /* authenticate the user --- `0' here, could have been PAM_SILENT
   *  | PAM_DISALLOW_NULL_AUTHTOK */
  retcode = pam_authenticate(pamh, 0);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_authenticate");
  }

  /* `0' could be as above */
  retcode = pam_setcred(pamh, PAM_ESTABLISH_CRED);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_setcred1");
  }

  /* open a session for the user --- `0' could be PAM_SILENT */
  retcode = pam_open_session(pamh, 0);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_open_session");
  }

  fprintf(stdout, "The user has been authenticated and `logged in'\n");

  /* close a session for the user --- `0' could be PAM_SILENT */
  retcode = pam_close_session(pamh, 0);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_close_session");
  }

  retcode = pam_setcred(pamh, PAM_DELETE_CRED);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_setcred2");
  }

  /* close the Linux-PAM library */
  pam_end(pamh, PAM_SUCCESS);

  return 0;
}

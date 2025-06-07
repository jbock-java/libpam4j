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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define INPUTSIZE PAM_MISC_CONV_BUFSIZE      /* maximum length of input+1 */
#define CONV_ECHO_ON  1                            /* types of echo state */
#define CONV_ECHO_OFF 0

static int bail_out(pam_handle_t *pamh, int code, const char *fn)
{
  fprintf(stderr, "==> called %s()\n  got: `%s'\n", fn,
      pam_strerror(pamh, code));
  pam_end(pamh, PAM_SUCCESS);
  return 1;
}

char* password = NULL;

int my_conv(int num_msg, const struct pam_message **msgm,
    struct pam_response **response, void *appdata_ptr) {
  struct pam_response *reply;

  if (num_msg <= 0) {
    return PAM_CONV_ERR;
  }

  reply = (pam_response*) calloc(num_msg, sizeof(struct pam_response));
  if (reply == NULL) {
    fprintf(stderr, "no memory for responses\n");
    return PAM_CONV_ERR;
  }

  reply[0].resp_retcode = 0;
  reply[0].resp = password;

  *response = reply;
  reply = NULL;

  return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
  pam_handle_t *pamh = NULL;
  char *username = NULL;
  int retcode;
  struct pam_conv conv = {
    my_conv,
    NULL
  };

  /* did the user call with a username as an argument ? */
  if (argc == 3) {
    username = argv[1];
    password = (char*) malloc(strlen(argv[2]) * sizeof(char));
    strcpy(password, argv[2]);
  } else {
    fprintf(stderr, "usage: %s [username] [password]\n", argv[0]);
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

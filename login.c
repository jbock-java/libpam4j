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
#include <pwd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static int bail_out(pam_handle_t *pamh, int code, const char *fn) {
  fprintf(stderr, "==> called %s()\n  got: `%s'\n", fn,
      pam_strerror(pamh, code));
  pam_end(pamh, PAM_SUCCESS);
  return 1;
}

int my_conv(
    int num_msg,
    const struct pam_message **msgm,
    struct pam_response **response,
    void *appdata_ptr) {
  if (num_msg <= 0) {
    return PAM_CONV_ERR;
  }
  struct pam_response *reply;
  reply = (pam_response*) calloc(num_msg, sizeof(struct pam_response));
  if (reply == NULL) {
    fprintf(stderr, "no memory for responses\n");
    return PAM_CONV_ERR;
  }
  for (int count = 0; count < num_msg; count++) {
    int style = msgm[count]->msg_style;
    switch (style) {
      case PAM_PROMPT_ECHO_OFF:
      case PAM_PROMPT_ECHO_ON:
        reply[count].resp_retcode = 0;
        reply[count].resp = (char*) appdata_ptr;
        break;
      case PAM_ERROR_MSG:
        fprintf(stderr, "PAM_ERROR: %s\n", msgm[count]->msg);
        break;
      case PAM_TEXT_INFO:
        fprintf(stdout, "PAM_INFO: %s\n", msgm[count]->msg);
        break;
      default:
        fprintf(stdout, "ignoring msg_style %d\n", style);
        break;
    }
  }
  *response = reply;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  pam_handle_t *pamh = NULL;
  char *username = NULL;
  int retcode;

  /* did the user call with a username as an argument ? */
  if (argc != 3) {
    fprintf(stderr, "usage: %s [username] [password]\n", argv[0]);
    return 1;
  }
  username = argv[1];
  char* password = (char*) malloc(strlen(argv[2]) * sizeof(char));
  strcpy(password, argv[2]);
  struct pam_conv conv = {
    my_conv,
    password /* this is the `appdata_ptr' */
  };

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

  retcode = pam_acct_mgmt(pamh, 0);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_acct_mgmt");
  }

  const void *item = NULL;
  retcode = pam_get_item(pamh, PAM_USER, &item);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_get_item");
  }
  char *user_name = (char*) item;
  struct passwd *pwd = getpwnam(user_name);
  fprintf(stdout, "user:      %s\n", pwd->pw_name);
  fprintf(stdout, "uid:       %d\n", pwd->pw_uid);
  fprintf(stdout, "gid:       %d\n", pwd->pw_gid);
  fprintf(stdout, "homedir:   %s\n", pwd->pw_dir);
  fprintf(stdout, "shell:     %s\n", pwd->pw_shell);

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

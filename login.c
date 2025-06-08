/* starting point: linux-pam examples/blank.c */

#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define INPUTSIZE 4096 /* maximum length of input+1 */

static int bail_out(pam_handle_t *pamh, int code, const char *fn) {
  fprintf(stderr, "==> called %s()\n  got: `%s'\n", fn,
      pam_strerror(pamh, code));
  pam_end(pamh, PAM_SUCCESS);
  return 1;
}

void read_string(char **retstr) {
  char line[INPUTSIZE];
  /* set echo off */
  struct termios term_before, term_tmp;
  tcgetattr(STDIN_FILENO, &term_before);
  memcpy(&term_tmp, &term_before, sizeof(term_tmp));
  term_tmp.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &term_tmp);
  /* read password */
  int nc = read(STDIN_FILENO, line, INPUTSIZE - 1);
  /* set echo on */
  tcsetattr(STDIN_FILENO, TCSANOW, &term_before);
  if (nc <= 0) {
    *retstr = NULL;
  } else {
    if (line[nc - 1] == '\n') {     /* <NUL> terminate */
      line[nc - 1] = '\0';
    }
    *retstr = strdup(line);
  }
}

int my_conv(
    int num_msg,
    const struct pam_message **msgm,
    struct pam_response **response,
    void *appdata_ptr) {
  char *password;
  if (appdata_ptr == NULL) {
    fprintf(stdout, "Password: ");
    fflush(stdout);
    read_string(&password);
    fprintf(stdout, "\n");
  } else {
    password = (char*) appdata_ptr;
  }
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
        reply[count].resp = password;
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
  char *username;
  char* password;
  int retcode;

  /* did the user call with a username as an argument ? */
  if (argc == 2) {
    password = NULL;
  } else if (argc == 3) {
    password = (char*) malloc(strlen(argv[2]) * sizeof(char));
    strcpy(password, argv[2]);
  } else {
    fprintf(stderr, "usage: %s username [password]\n", argv[0]);
    return 1;
  }
  username = argv[1];
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

  retcode = pam_setcred(pamh, PAM_DELETE_CRED);
  if (retcode != PAM_SUCCESS) {
    return bail_out(pamh, retcode, "pam_setcred2");
  }

  /* close the Linux-PAM library */
  pam_end(pamh, PAM_SUCCESS);

  return 0;
}

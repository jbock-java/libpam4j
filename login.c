/* starting point: linux-pam examples/blank.c */

#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define INPUTSIZE 4096 /* maximum length of input+1 */

static void die(pam_handle_t *m_handle, int retval, const char *fn) {
	fprintf(stderr, "==> called %s()\n  got: %s (%d)\n", fn,
		pam_strerror(m_handle, retval), retval);
	pam_end(m_handle, retval);
	exit(1);
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

struct login_data {
	int count;
	char message[32];
};

int my_conv(
		int num_msg,
		const struct pam_message **msgm,
		struct pam_response **response,
		void *appdata_ptr) {
	struct login_data *data = (login_data*) appdata_ptr;
	char *password;
	fprintf(stderr, "Message: %s (%d)\n", data->message, data->count++);
	fprintf(stderr, "Password: ");
	fflush(stderr);
	read_string(&password);
	fprintf(stderr, "\n");
	if (num_msg == 0) {
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
				fprintf(stderr, "PAM_ERROR_MSG: %s\n", msgm[count]->msg);
				break;
			case PAM_TEXT_INFO:
				fprintf(stderr, "PAM_TEXT_INFO: %s\n", msgm[count]->msg);
				break;
			default:
				fprintf(stderr, "ignoring msg_style %d\n", style);
				break;
		}
	}
	*response = reply;
	return PAM_SUCCESS;
}

int main(int argc, char **argv) {
	pam_handle_t *m_handle = NULL;
	char *username;
	char* password;
	int retval;

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
	struct login_data data;
	data.count = 0;
	strcpy(data.message, "initial message");

	struct pam_conv conv = {
		my_conv,
		&data /* this is the `appdata_ptr' */
	};

	/* initialize the Linux-PAM library */
	retval = pam_start("dummy", username, &conv, &m_handle);
	strcpy(data.message, "calling pam_start");
	if (retval != PAM_SUCCESS) {
		die(m_handle, retval, "pam_start");
	}

	/* authenticate the user --- `0' here, could have been PAM_SILENT
	 *  | PAM_DISALLOW_NULL_AUTHTOK */
	strcpy(data.message, "calling pam_authenticate");
	retval = pam_authenticate(m_handle, 0);
	if (retval != PAM_SUCCESS) {
		die(m_handle, retval, "pam_authenticate");
	}

	retval = pam_acct_mgmt(m_handle, PAM_SILENT);       /* permitted access? */
	if (retval == PAM_NEW_AUTHTOK_REQD) {
		strcpy(data.message, "calling pam_chauthtok");
		retval = pam_chauthtok(m_handle, PAM_CHANGE_EXPIRED_AUTHTOK);
	}
	if (retval != PAM_SUCCESS) {
		die(m_handle, retval, "pam_acct_mngt");
	}

	strcpy(data.message, "calling pam_setcred");
	retval = pam_setcred(m_handle, PAM_ESTABLISH_CRED);
	if (retval != PAM_SUCCESS) {
		die(m_handle, retval, "pam_setcred");
	}

	const void *item = NULL;
	strcpy(data.message, "calling pam_get_item");
	retval = pam_get_item(m_handle, PAM_USER, &item);
	if (retval != PAM_SUCCESS) {
		die(m_handle, retval, "pam_get_item");
	}

	char *user_name = (char*) item;
	struct passwd *pwd = getpwnam(user_name);
	fprintf(stdout, "user:      %s\n", pwd->pw_name);
	fprintf(stdout, "uid:       %d\n", pwd->pw_uid);
	fprintf(stdout, "gid:       %d\n", pwd->pw_gid);
	fprintf(stdout, "homedir:   %s\n", pwd->pw_dir);
	fprintf(stdout, "shell:     %s\n", pwd->pw_shell);

	/* close the Linux-PAM library */
	pam_end(m_handle, retval);

	return 0;
}

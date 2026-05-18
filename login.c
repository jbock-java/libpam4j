/* starting point: linux-pam examples/blank.c */

#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define INPUTSIZE 32 /* maximum length of input+1 */

static void die(pam_handle_t *m_handle, int retval, const char *fn) {
	fprintf(stderr, "==> called %s()\n  got: %s (%d)\n", fn,
		pam_strerror(m_handle, retval), retval);
	pam_end(m_handle, retval);
	exit(1);
}

void read_string(char** retstr) {
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

	/* Holds the result of the previous pam call. */
	int retval = PAM_SUCCESS;

	/* When retval == PAM_NEW_AUTHTOK_REQD, the conversation gets called thrice.
	 * Then this keeps track of the round we're currently in. Otherwise 0. */
	int count = 0;

	/* Used as password except when retval == PAM_NEW_AUTHTOK_REQD */
	char oldpw[INPUTSIZE];

	/* Used as password when retval == PAM_NEW_AUTHTOK_REQD and count >= 1 */
	char newpw[INPUTSIZE];
};

int my_conv(
		int num_msg,
		const struct pam_message **msgm,
		struct pam_response **response,
		void *appdata_ptr) {
	struct login_data *data = (login_data*) appdata_ptr;
	char *password;

	if (data->retval == PAM_NEW_AUTHTOK_REQD) {
		if (data->count == 0) {
			password = strdup(data->oldpw);
		} else {
			password = strdup(data->newpw);
		}
		data->count++;
	} else {
		password = strdup(data->oldpw);
		data->count = 0;
	}
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

	if (argc != 2) {
		fprintf(stderr, "usage: %s username\n", argv[0]);
		return 1;
	}
	username = argv[1];
	struct login_data data;
	memset(data.oldpw, 0, sizeof data.oldpw);
	memset(data.newpw, 0, sizeof data.newpw);

	struct pam_conv conv = {
		my_conv,
		&data /* this is the `appdata_ptr' */
	};

	/* initialize the Linux-PAM library */
	data.retval = pam_start("dummy", username, &conv, &m_handle);
	if (data.retval != PAM_SUCCESS) {
		die(m_handle, data.retval, "pam_start");
	}

	/* `UI' start */
	fprintf(stderr, "password for auth: ");
	fflush(stderr);
	read_string(&password);
	strcpy(data.oldpw, password);
	fprintf(stderr, "\n");
	/* `UI' end */

	data.retval = pam_authenticate(m_handle, 0);
	if (data.retval != PAM_SUCCESS) {
		die(m_handle, data.retval, "pam_authenticate");
	}

	data.retval = pam_acct_mgmt(m_handle, PAM_SILENT);

	if (data.retval == PAM_NEW_AUTHTOK_REQD) {

		/* `UI' start */
		fprintf(stderr, "You are required to change your password immediately.\n");
		while (true) {
			fprintf(stderr, "New password: ");
			fflush(stderr);
			read_string(&password);
			strcpy(data.newpw, password);
			fprintf(stderr, "\nRetype new password: ");
			fflush(stderr);
			read_string(&password);
			fprintf(stderr, "\n");
			if (strcmp(password, data.newpw) == 0) {
				break;
			} else {
				fprintf(stderr, "Sorry, inputs don't match.\n");
			}
		}
		/* `UI' end */

		data.retval = pam_chauthtok(m_handle, PAM_CHANGE_EXPIRED_AUTHTOK);
		if (data.retval == PAM_SUCCESS) {
			fprintf(stderr, "The password was changed successfully.\n");
		} else {
			die(m_handle, data.retval, "pam_chauthtok");
		}
		data.count = 0;
	} else {
		die(m_handle, data.retval, "pam_acct_mngt");
	}

	data.retval = pam_setcred(m_handle, PAM_ESTABLISH_CRED);
	if (data.retval != PAM_SUCCESS) {
		die(m_handle, data.retval, "pam_setcred");
	}

	const void *item = NULL;
	data.retval = pam_get_item(m_handle, PAM_USER, &item);
	if (data.retval != PAM_SUCCESS) {
		die(m_handle, data.retval, "pam_get_item");
	}

	char *user_name = (char*) item;
	struct passwd *pwd = getpwnam(user_name);

	fprintf(stdout, "user:      %s\n", pwd->pw_name);
	fprintf(stdout, "uid:       %d\n", pwd->pw_uid);
	fprintf(stdout, "gid:       %d\n", pwd->pw_gid);
	fprintf(stdout, "homedir:   %s\n", pwd->pw_dir);
	fprintf(stdout, "shell:     %s\n", pwd->pw_shell);

	/* close the Linux-PAM library */
	pam_end(m_handle, data.retval);

	return 0;
}

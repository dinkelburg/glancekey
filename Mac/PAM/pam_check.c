// pam-check: runs PAM authentication, to check pam_faceunlock before sudo relies on it.
//
//   pam-check <service> <user>              pam_start + pam_authenticate with /etc/pam.d/<service> (needs root)
//   pam-check --direct <module> [args...]   loads the module itself and calls it as sudo would (no root needed;
//                                           for testing against a checker run with --approvers/--socket)
//
// Messages from the modules are printed; password prompts are refused. Exits 0 if authentication succeeded.

#include <dlfcn.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int conversation(int count, const struct pam_message **messages, struct pam_response **responses, void *data) {
    *responses = calloc(count, sizeof(struct pam_response));
    if (*responses == NULL) return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        switch (messages[i]->msg_style) {
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            printf("%s\n", messages[i]->msg);
            fflush(stdout);
            break;
        default:
            free(*responses);
            *responses = NULL;
            return PAM_CONV_ERR;
        }
    }
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *pamh = NULL;
    int result;

    if (argc >= 3 && strcmp(argv[1], "--direct") == 0) {
        struct passwd *account = getpwuid(getuid());
        if (account == NULL) return 2;
        const char *user = account->pw_name;
        if ((result = pam_start("sudo", user, &conv, &pamh)) != PAM_SUCCESS) {
            fprintf(stderr, "pam_start: %d\n", result);
            return 2;
        }
        const char *tty = ttyname(STDIN_FILENO);
        if (tty != NULL) pam_set_item(pamh, PAM_TTY, tty);
        void *module = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (module == NULL) {
            fprintf(stderr, "dlopen: %s\n", dlerror());
            return 2;
        }
        int (*authenticate)(pam_handle_t *, int, int, const char **) = dlsym(module, "pam_sm_authenticate");
        if (authenticate == NULL) {
            fprintf(stderr, "no pam_sm_authenticate\n");
            return 2;
        }
        result = authenticate(pamh, 0, argc - 3, (const char **)argv + 3);
    } else if (argc == 3) {
        if ((result = pam_start(argv[1], argv[2], &conv, &pamh)) != PAM_SUCCESS) {
            fprintf(stderr, "pam_start(%s): %s\n", argv[1], pam_strerror(pamh, result));
            return 2;
        }
        result = pam_authenticate(pamh, 0);
    } else {
        fprintf(stderr, "usage: pam-check <service> <user>\n       pam-check --direct <module> [args...]\n");
        return 64;
    }
    printf("%s\n", result == PAM_SUCCESS ? "authenticated" : pam_strerror(pamh, result));
    pam_end(pamh, result);
    return result == PAM_SUCCESS ? 0 : 1;
}

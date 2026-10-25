// pam_faceunlock: lets sudo on the Mac wait for an approval from the FaceUnlock iPhone app.
//
// macOS has no pam_exec, so this does what pam_exec does on Linux: it runs the root-owned checker
// (`faceunlock-agent pam`, see linux/checker.go) with the PAM details in its environment, shows the checker's
// output in the terminal and succeeds only if the checker exits 0. The checker verifies the iPhone's signature
// itself. Anything else falls through to the next module, normally the password prompt.
//
// /etc/pam.d/sudo_local:  auth  sufficient  /usr/local/lib/pam/pam_faceunlock.so.2 [/path/to/checker] [checker options]

#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/openpam.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_CHECKER "/usr/local/libexec/faceunlock/faceunlock-agent"
#define MAX_ARGS 16

static const char *item(pam_handle_t *pamh, int type) {
    const void *value = NULL;
    if (pam_get_item(pamh, type, &value) != PAM_SUCCESS || value == NULL) return "";
    return value;
}

static char *env_entry(const char *name, const char *value) {
    char *entry = NULL;
    if (asprintf(&entry, "%s=%s", name, value) < 0) return NULL;
    return entry;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *checker = DEFAULT_CHECKER;
    int first = 0;
    if (argc > 0 && argv[0][0] == '/') {
        checker = argv[0];
        first = 1;
    }
    const char *user = NULL;
    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS || user == NULL || user[0] == '\0') return PAM_IGNORE;

    char *args[MAX_ARGS + 3] = {(char *)checker, "pam"};
    int count = 2;
    for (int i = first; i < argc && count < MAX_ARGS + 2; i++) args[count++] = (char *)argv[i];
    args[count] = NULL;

    char *env[] = {
        env_entry("PAM_USER", user),
        env_entry("PAM_SERVICE", item(pamh, PAM_SERVICE)),
        env_entry("PAM_TTY", item(pamh, PAM_TTY)),
        env_entry("PAM_RHOST", item(pamh, PAM_RHOST)),
        env_entry("PAM_RUSER", item(pamh, PAM_RUSER)),
        "PAM_TYPE=auth",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL,
    };
    for (int i = 0; i < 5; i++) {
        if (env[i] == NULL) return PAM_BUF_ERR;
    }

    int result = PAM_AUTH_ERR;
    int output[2];
    if (pipe(output) != 0) goto done;
    pid_t pid = fork();
    if (pid < 0) {
        close(output[0]);
        close(output[1]);
        goto done;
    }
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR);
        dup2(null, STDIN_FILENO);
        dup2(output[1], STDOUT_FILENO);
        dup2(null, STDERR_FILENO);
        int limit = getdtablesize();
        for (int fd = STDERR_FILENO + 1; fd < limit && fd < 4096; fd++) close(fd);
        execve(checker, args, env);
        _exit(127);
    }

    close(output[1]);
    FILE *lines = fdopen(output[0], "r");
    if (lines != NULL) {
        char line[512];
        while (fgets(line, sizeof line, lines) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0] != '\0' && !(flags & PAM_SILENT)) pam_info(pamh, "%s", line);
        }
        fclose(lines);
    } else {
        close(output[0]);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) goto done;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) result = PAM_SUCCESS;

done:
    for (int i = 0; i < 5; i++) free(env[i]);
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

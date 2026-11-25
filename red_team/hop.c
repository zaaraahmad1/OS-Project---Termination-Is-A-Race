/*
 * Attack technique 3: Session / process-group hopping
 *
 * How it works:
 * - Normally, a forked child stays in the same process group (and
 *   session) as its parent. A defender using "process-group kill"
 *   (e.g. kill(-pgid, SIGKILL)) can wipe out an entire group at once.
 * - This attacker forks a child, and the child immediately calls
 *   setsid(). That call makes the child the leader of a BRAND NEW
 *   session and process group, completely detached from the
 *   original one.
 * - A process-group kill aimed at the original group will miss this
 *   child entirely, because it now belongs to a different group.
 *
 * Usage:
 *   ./hop --fork-rate 10 --duration 30 --tag myrun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>

int fork_rate = 10;
int duration = 30;
char tag[256] = "attack_default";

void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fork-rate") == 0 && i + 1 < argc) {
            fork_rate = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) {
            strncpy(tag, argv[++i], sizeof(tag) - 1);
        }
    }
}

/* the child that hops into its own session/group */
void child_behavior() {
    setenv("MARK", tag, 1);

    /* this is the key line: become leader of a new session and a new
     * process group, detached from the parent's group */
    pid_t new_sid = setsid();
    if (new_sid == -1) {
        perror("setsid failed");
    } else {
        printf("[hop] pid=%d hopped into new session/group sid=%d\n",
               getpid(), new_sid);
    }

    while (1) {
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    setenv("MARK", tag, 1);

    printf("[hop] starting, tag=%s fork_rate=%d duration=%d\n",
           tag, fork_rate, duration);

    time_t start_time = time(NULL);
    long min_gap_usec = 1000000 / (fork_rate > 0 ? fork_rate : 1);

    while (time(NULL) - start_time < duration) {
        pid_t child_pid = fork();

        if (child_pid == 0) {
            child_behavior();
            exit(0); /* never reached */
        } else if (child_pid > 0) {
            int status;
            waitpid(child_pid, &status, 0);
            printf("[hop] child %d died, spawning a new one...\n", child_pid);
            usleep(min_gap_usec);
        } else {
            perror("fork failed");
            sleep(1);
        }
    }

    printf("[hop] duration reached, exiting cleanly\n");
    return 0;
}

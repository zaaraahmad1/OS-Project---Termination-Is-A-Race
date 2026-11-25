/*
 * Attack technique 2: Double-fork escape
 *
 * How it works:
 * - The original process forks a child (child A).
 * - Child A immediately forks its own child (child B), then child A
 *   exits right away.
 * - Because child A is gone, child B becomes an orphan and gets
 *   "reparented" to init (PID 1) by the kernel.
 * - This means child B is no longer anywhere under the original
 *   process's subtree. A defender that only walks the process tree
 *   starting from the original PID will never find child B.
 *
 * Usage:
 *   ./doublefork --fork-rate 10 --duration 30 --tag myrun
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

/* child B: the one that escapes. it just marks itself and sleeps. */
void grandchild_behavior() {
    setenv("MARK", tag, 1);
    printf("[doublefork] grandchild pid=%d now orphaned (escaped tree)\n",
           getpid());
    while (1) {
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    setenv("MARK", tag, 1);

    printf("[doublefork] starting, tag=%s fork_rate=%d duration=%d\n",
           tag, fork_rate, duration);

    time_t start_time = time(NULL);
    long min_gap_usec = 1000000 / (fork_rate > 0 ? fork_rate : 1);

    while (time(NULL) - start_time < duration) {
        pid_t child_a_pid = fork();

        if (child_a_pid == 0) {
            /*child A */
            pid_t child_b_pid = fork();

            if (child_b_pid == 0) {
                /*child B (the grandchild) - this is the one
                 * that escapes */
                grandchild_behavior();
                exit(0); /* never reached */
            }

            /* child A exits immediately, orphaning child B so it gets
             * reparented to init */
            exit(0);
        } else if (child_a_pid > 0) {
            /* original process: just wait for child A to exit (it does
             * so almost instantly), then loop to spawn another pair */
            int status;
            waitpid(child_a_pid, &status, 0);
            usleep(min_gap_usec);
        } else {
            perror("fork failed");
            sleep(1);
        }
    }

    printf("[doublefork] duration reached, exiting cleanly\n");
    return 0;
}

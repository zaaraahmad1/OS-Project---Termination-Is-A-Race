/*
 * Attack technique 1: Fork-respawn racing
 *
 * How it works:
 * - The program sets an environment variable (the "tag") on itself so we
 *   can find it later in /proc, no matter how many times it respawns.
 * - It forks a child.
 * - The PARENT just waits for the child to die (using waitpid).
 * - As soon as the child dies (for any reason, including being killed),
 *   the parent immediately forks a NEW child to replace it.
 * - This repeats until --duration seconds have passed.
 *
 * The "race" is: if a defender kills the child, how fast can the parent
 * notice and spawn a replacement, versus how fast the defender can kill
 * the new one too?
 *
 * Usage:
 *   ./respawn --fork-rate 50 --duration 30 --tag myrun
 *
 * --fork-rate here just controls the MAX forks per second as a safety
 * cap, so it doesn't runaway faster than that even if children die instantly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>

/* Turn command-line args into variables we can use */
int fork_rate = 10;      /* default: 10 forks per second max */
int duration = 30;       /* default: run for 30 seconds */
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

/* This is what each CHILD process runs. It just marks itself with the
 * tag (so it shows up in /proc/<pid>/environ) and then sleeps, waiting
 * to be killed. */
void child_behavior() {
    /* set an env var so this process can be found/counted later */
    setenv("MARK", tag, 1);

    /* just sleep forever - we're waiting to be killed by the defender */
    while (1) {
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    /* also mark the parent itself, in case someone tries to kill it too */
    setenv("MARK", tag, 1);

    printf("[respawn] starting, tag=%s fork_rate=%d duration=%d\n",
           tag, fork_rate, duration);

    time_t start_time = time(NULL);
    long min_gap_usec = 1000000 / (fork_rate > 0 ? fork_rate : 1);

    while (time(NULL) - start_time < duration) {
        pid_t child_pid = fork();

        if (child_pid == 0) {
            /* child */
            child_behavior();
            exit(0); /* never reached */
        } else if (child_pid > 0) {
            /* parent: wait for this child to die, then loop
             * around and fork a new one */
            int status;
            waitpid(child_pid, &status, 0);
            printf("[respawn] child %d died, respawning...\n", child_pid);

            /* small sleep so we don't fork faster than fork_rate allows */
            usleep(min_gap_usec);
        } else {
            perror("fork failed");
            sleep(1);
        }
    }

    printf("[respawn] duration reached, exiting cleanly\n");
    return 0;
}

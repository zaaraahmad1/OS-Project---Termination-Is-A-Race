/*
 * Attack technique 4: Paired watchdogs
 *
 * How it works:
 * - This program starts TWO processes: A and B.
 * - A's job is to watch B. If B dies, A immediately respawns it.
 * - B's job is to watch A. If A dies, B immediately respawns it.
 * - So killing just one of them doesn't work: the other one notices
 *   and brings it back. A defender has to kill BOTH at (almost) the
 *   same instant, or the pair just keeps regenerating itself.
 *
 * Usage:
 *   ./watchdog --fork-rate 10 --duration 30 --tag myrun
 *
 * Note: here --fork-rate is reused as "how often each watchdog checks
 * if its partner is still alive" (checks per second), since this
 * attack doesn't fork rapidly like the others.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

int fork_rate = 10;   /* used as "checks per second" for this technique */
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

/* Each watchdog process runs this. partner_pid is who it's watching.
 * role is just "A" or "B" for printing. */
void watchdog_behavior(pid_t partner_pid, const char *role) {
    setenv("MARK", tag, 1);
    long check_gap_usec = 1000000 / (fork_rate > 0 ? fork_rate : 1);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < duration) {
        /* Checking if the partner is dead
         *
         * If partner_pid is OWN CHILD,
         * then when it's killed it becomes a ZOMBIE until we reap it
         * with wait()/waitpid(). A zombie still "exists" in the
         * process table, so kill(pid, 0) keeps reporting it as alive
         * waitpid(..., WNOHANG) both detects the death
         * AND reaps it in one call.
         *
         * But if partner_pid is NOT our own child , waitpid() can't be used at
         * all - it fails with ECHILD. In that one case we fall back
         * to a plain kill(pid, 0) existence check instead. */
        int partner_dead = 0;
        pid_t wp = waitpid(partner_pid, NULL, WNOHANG);
        if (wp == partner_pid) {
            partner_dead = 1; /* it just died, and we reaped it */
        } else if (wp == -1 && errno == ECHILD) {
            /* not our own child - fall back to existence check */
            if (kill(partner_pid, 0) == -1) {
                partner_dead = 1;
            }
        }
        /* if wp == 0, partner is still alive and running - do nothing */
        if (partner_dead) {
            printf("[watchdog-%s] partner %d is gone, respawning it\n",
                   role, partner_pid);

            /* capture our own pid BEFORE forking. If we call
             * getpid() after forking, inside the child, it returns the
             * CHILD's new pid, not ours - which would make the new
             * partner watch itself (a bug we hit during testing). */
            pid_t my_pid = getpid();

            pid_t new_partner = fork();
            if (new_partner == 0) {
                /* the new partner becomes a fresh watchdog, watching US
                 * (the process that just noticed its old partner die) */
                watchdog_behavior(my_pid, role[0] == 'A' ? "B" : "A");
                exit(0); /* never reached */
            } else if (new_partner > 0) {
                partner_pid = new_partner;
            }
        }
        usleep(check_gap_usec);
    }
}

int main(int argc, char *argv[]) {
    /* without this, printf output sits in a buffer and doesn't show up
     * until the process exits - makes debugging very confusing */
    setvbuf(stdout, NULL, _IOLBF, 0);

    parse_args(argc, argv);
    setenv("MARK", tag, 1);

    printf("[watchdog] starting pair, tag=%s duration=%d\n", tag, duration);

    /* fork once to create watchdog B, then this (original) process
     * becomes watchdog A watching B */
    pid_t pid_b = fork();

    if (pid_b == 0) {
        /* this is watchdog B, watching A (our parent) */
        watchdog_behavior(getppid(), "B");
        exit(0);
    } else if (pid_b > 0) {
        /* this is watchdog A, watching B */
        watchdog_behavior(pid_b, "A");
    } else {
        perror("fork failed");
        exit(1);
    }

    printf("[watchdog] duration reached, exiting cleanly\n");
    return 0;
}

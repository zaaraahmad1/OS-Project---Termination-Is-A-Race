/*
 * defender.c -- implements the 6 termination strategies compared by
 * "Termination Is a Race":
 *   pid       per-PID SIGKILL (baseline, how Part 3 defenders responded)
 *   pgrp      process-group kill
 *   tree      recursive process-tree walk (follow children via /proc)
 *   stopkill  stop-all-then-kill (SIGSTOP the whole tree first, then
 *             SIGKILL everything, so nothing can fork a replacement
 *             in the gap between discovering a process and killing it)
 *   pidfd     pidfd-based signalling (race-free: a pidfd pins the
 *             identity of a specific PID, so you can never accidentally
 *             signal a recycled PID)
 *   cgroup    quarantine cgroup v2: move the suspect (and everything we
 *             can find of its tree) into a fresh cgroup, then write to
 *             cgroup.freeze and cgroup.kill
 *
 * Usage:
 *   ./defender --strategy [pid|pgrp|tree|stopkill|pidfd|cgroup] \
 *              --target-pid <PID> \
 *              --delay-ms <MS> \
 *              --llm-mode [off|small|medium|large] \
 *              [--cgroup-root <PATH-PREFIX>] [--benign-pids p1,p2,...] \
 *              [--phase all|move|kill]
 *
 * --phase (cgroup strategy only):
 *   all   (default) move into quarantine, freeze, kill -- in one go
 *   move  ONLY move the suspect's current tree into the quarantine
 *         cgroup and return. Used for "quarantine at detection time":
 *         the harness calls --phase move the instant the suspect is
 *         flagged, waits out the inference delay, then calls
 *         --phase kill. Every child forked during the delay is born
 *         INSIDE the quarantine cgroup (Hypothesis 4's exception).
 *   kill  ONLY freeze + kill an existing quarantine cgroup.
 *   The quarantine cgroup is <cgroup-root>_<target-pid>, so both
 *   phases find the same group as long as they get the same target.
 *
 * --llm-mode off: sleep --delay-ms before acting (scripted delay, used
 * for most runs so the OS-level comparison isn't muddied by the LLM's
 * varying answer time).
 * --llm-mode small|medium|large: this binary does NOT itself call an
 * LLM -- it expects the CALLER (run_harness.sh) to have already measured
 * the real decision time from the Part 3 blue_team agent and pass that
 * measured time in as --delay-ms, while still recording --llm-mode in
 * the CSV for which model produced it. This keeps defender.c's own job
 * single-purpose (apply a termination strategy, given a delay), and
 * keeps the LLM integration entirely in the harness layer, where the
 * Part 3 agent code actually lives.
 *
 * All timing is measured from this process's own start, in milliseconds,
 * and printed as a single machine-readable summary line on exit:
 *
 *   RESULT strategy=<s> target=<pid> delay_ms=<d> \
 *          kill_issued_ms=<k> benign_pids_checked=<n> benign_pids_killed=<m> \
 *          fallback=<0|1>
 *
 * fallback=1 means the requested strategy could NOT be applied (e.g. the
 * quarantine cgroup could not be created) and a weaker strategy was used
 * instead. run_harness.sh treats such a run as invalid and says so.
 * Everything else defender.c prints is for a human reading the log.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

/* pidfd_open() has no glibc wrapper on older glibc versions; call the
 * syscall directly so this builds on whatever glibc the grading
 * machine has. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
static int my_pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(__NR_pidfd_open, pid, flags);
}
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
static int my_pidfd_send_signal(int pidfd, int sig, void *info, unsigned int flags) {
    return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

#define MAX_PIDS 4096
#define QUARANTINE_ROOT "/sys/fs/cgroup/quarantine"  /* pure cgroup v2 (WSL2, modern distros); override with --cgroup-root */

char strategy[32] = "";
pid_t target_pid = -1;
long delay_ms = 0;
char llm_mode[16] = "off";
char cgroup_root[256] = QUARANTINE_ROOT;
char phase[16] = "all";
int fallback_used = 0;   /* set if the requested strategy could not be applied */

/* benign PIDs the harness wants us to NEVER touch, so we can report
 * whether a broad strategy (pgrp/cgroup) overreached. Passed as a
 * comma-separated list: --benign-pids 1234,1235,1236 */
pid_t benign_pids[MAX_PIDS];
int n_benign = 0;

long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--strategy") == 0 && i + 1 < argc) {
            strncpy(strategy, argv[++i], sizeof(strategy) - 1);
        } else if (strcmp(argv[i], "--target-pid") == 0 && i + 1 < argc) {
            target_pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--delay-ms") == 0 && i + 1 < argc) {
            delay_ms = atol(argv[++i]);
        } else if (strcmp(argv[i], "--llm-mode") == 0 && i + 1 < argc) {
            strncpy(llm_mode, argv[++i], sizeof(llm_mode) - 1);
        } else if (strcmp(argv[i], "--phase") == 0 && i + 1 < argc) {
            strncpy(phase, argv[++i], sizeof(phase) - 1);
        } else if (strcmp(argv[i], "--cgroup-root") == 0 && i + 1 < argc) {
            strncpy(cgroup_root, argv[++i], sizeof(cgroup_root) - 1);
        } else if (strcmp(argv[i], "--benign-pids") == 0 && i + 1 < argc) {
            char *tok = strtok(argv[++i], ",");
            while (tok && n_benign < MAX_PIDS) {
                benign_pids[n_benign++] = atoi(tok);
                tok = strtok(NULL, ",");
            }
        }
    }
}

/* Returns the one-letter state from /proc/<pid>/stat ('R','S','Z',...),
 * or 0 if the process does not exist. */
char proc_state(pid_t p) {
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", p);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);
    char *rparen = strrchr(line, ')');
    if (!rparen || rparen[1] == '\0') return 0;
    return rparen[2];
}

/* A zombie has already been killed -- it is only waiting for its parent
 * to reap it -- so it counts as dead, not alive. */
int pid_alive(pid_t p) {
    char st = proc_state(p);
    return st != 0 && st != 'Z';
}

/* --- /proc helpers shared by tree, stopkill, and cgroup --- */

pid_t get_pgid_of(pid_t p) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", p);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int pid_, ppid_, pgrp_;
    char comm[256];
    /* stat format: pid (comm) state ppid pgrp ... -- comm can contain
     * spaces/parens, so skip to the LAST ')' before reading the rest */
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    char *rparen = strrchr(line, ')');
    if (!rparen) return -1;
    /* after ')', fields are: state ppid pgrp ... */
    int got = sscanf(rparen + 2, "%*c %d %d", &ppid_, &pgrp_);
    (void)pid_; (void)comm;
    if (got < 2) return -1;
    return pgrp_;
}

pid_t get_ppid_of(pid_t p) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", p);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    char *rparen = strrchr(line, ')');
    if (!rparen) return -1;
    int ppid_;
    if (sscanf(rparen + 2, "%*c %d", &ppid_) < 1) return -1;
    return ppid_;
}

/* Recursively walk /proc to find every CURRENT descendant of root_pid
 * by following ppid links. This is a point-in-time snapshot -- a
 * descendant that forks again between our scan and our kill is exactly
 * the escape window the fork-respawn race is testing. */
int find_descendants(pid_t root_pid, pid_t *out, int max_out) {
    int n = 0;
    out[n++] = root_pid;

    DIR *d = opendir("/proc");
    if (!d) return n;

    /* repeat passes until no new descendants are found, since /proc
     * iteration order isn't guaranteed to visit parents before children */
    int changed = 1;
    while (changed && n < max_out) {
        changed = 0;
        rewinddir(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            pid_t p = atoi(de->d_name);
            int already = 0;
            for (int i = 0; i < n; i++) if (out[i] == p) { already = 1; break; }
            if (already) continue;
            pid_t ppid = get_ppid_of(p);
            for (int i = 0; i < n; i++) {
                if (out[i] == ppid && n < max_out) {
                    out[n++] = p;
                    changed = 1;
                    break;
                }
            }
        }
    }
    closedir(d);
    return n;
}

/* --- strategy implementations --- */

void strat_pid(void) {
    printf("[defender] strategy=pid: SIGKILL %d\n", target_pid);
    kill(target_pid, SIGKILL);
}

void strat_pgrp(void) {
    pid_t pgid = get_pgid_of(target_pid);
    if (pgid <= 0) {
        printf("[defender] strategy=pgrp: couldn't read pgid of %d, falling back to pid kill\n", target_pid);
        strat_pid();
        return;
    }
    /* Safety: never signal our OWN process group (that would kill the
     * defender and whatever launched it, e.g. the harness) or init's. */
    if (pgid <= 1 || pgid == getpgrp()) {
        printf("[defender] strategy=pgrp: REFUSING killpg(%d) -- it is the defender's own "
               "process group (attacker was not started in its own group); falling back to pid kill\n", pgid);
        fallback_used = 1;
        strat_pid();
        return;
    }
    printf("[defender] strategy=pgrp: killpg(%d)\n", pgid);
    killpg(pgid, SIGKILL);
}

void strat_tree(void) {
    pid_t pids[MAX_PIDS];
    int n = find_descendants(target_pid, pids, MAX_PIDS);
    printf("[defender] strategy=tree: found %d descendant(s) of %d\n", n, target_pid);
    for (int i = 0; i < n; i++) {
        printf("[defender]   killing %d\n", pids[i]);
        kill(pids[i], SIGKILL);
    }
}

void strat_stopkill(void) {
    /* Pass 1: SIGSTOP everything we can currently see, as fast as
     * possible, so nothing still running can fork a replacement while
     * we're busy killing earlier PIDs. Pass 2: SIGKILL the same set. A
     * second descendant-scan after the stop pass catches anything that
     * forked in the gap between pass-1 members being found. */
    pid_t pids[MAX_PIDS];
    int n = find_descendants(target_pid, pids, MAX_PIDS);
    printf("[defender] strategy=stopkill: pass1 STOP on %d descendant(s)\n", n);
    for (int i = 0; i < n; i++) kill(pids[i], SIGSTOP);

    /* re-scan: anything stopped can no longer fork, but something that
     * forked in the microseconds before its own SIGSTOP landed might
     * now exist and not be in our first list */
    pid_t pids2[MAX_PIDS];
    int n2 = find_descendants(target_pid, pids2, MAX_PIDS);
    for (int i = 0; i < n2; i++) kill(pids2[i], SIGSTOP);

    printf("[defender] strategy=stopkill: pass2 KILL on %d descendant(s)\n", n2);
    for (int i = 0; i < n2; i++) kill(pids2[i], SIGKILL);
}

void strat_pidfd(void) {
    int pfd = my_pidfd_open(target_pid, 0);
    if (pfd < 0) {
        printf("[defender] strategy=pidfd: pidfd_open(%d) failed (%s), falling back to pid kill\n",
               target_pid, strerror(errno));
        fallback_used = 1;
        strat_pid();
        return;
    }
    printf("[defender] strategy=pidfd: pidfd_send_signal on fd=%d (pid=%d)\n", pfd, target_pid);
    if (my_pidfd_send_signal(pfd, SIGKILL, NULL, 0) < 0) {
        printf("[defender] strategy=pidfd: pidfd_send_signal failed (%s)\n", strerror(errno));
    }
    close(pfd);
    /* pidfd only ever pins ONE pid -- it is race-free against PID
     * reuse for that pid specifically, but (like plain pid kill) it
     * says nothing about descendants forked after we opened it. */
}

int write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t w = write(fd, content, strlen(content));
    close(fd);
    return (w == (ssize_t)strlen(content)) ? 0 : -1;
}

void quarantine_path(char *out, size_t n) {
    snprintf(out, n, "%s_%d", cgroup_root, target_pid);
}

/* Phase 1: create the quarantine cgroup and move every descendant we can
 * currently see into it. Returns 0 on success, -1 if the cgroup could
 * not be created. Each PID is its own write(), since cgroup.procs only
 * accepts one PID per write(). Anything forked AFTER this snapshot but
 * before its parent was moved is exactly the escape window Hypothesis 3
 * is about; anything forked by an already-moved process is born inside
 * the quarantine group automatically. */
int cgroup_move(void) {
    char qpath[512];
    quarantine_path(qpath, sizeof(qpath));
    if (mkdir(qpath, 0755) != 0 && errno != EEXIST) {
        printf("[defender] strategy=cgroup: mkdir(%s) failed (%s)\n", qpath, strerror(errno));
        return -1;
    }
    printf("[defender] strategy=cgroup: quarantine group at %s\n", qpath);

    char procs_path[600];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", qpath);

    pid_t pids[MAX_PIDS];
    int n = find_descendants(target_pid, pids, MAX_PIDS);
    int moved = 0;
    for (int i = 0; i < n; i++) {
        char pidstr[16];
        snprintf(pidstr, sizeof(pidstr), "%d", pids[i]);
        if (write_file(procs_path, pidstr) == 0) moved++;
    }
    printf("[defender] strategy=cgroup: moved %d/%d descendant(s) into quarantine\n", moved, n);
    return 0;
}

/* Phase 2: freeze the quarantine group (nothing inside can run or fork
 * any more), then kill every process in it in one kernel operation. */
int cgroup_kill(void) {
    char qpath[512];
    quarantine_path(qpath, sizeof(qpath));
    struct stat st;
    if (stat(qpath, &st) != 0) {
        printf("[defender] strategy=cgroup: quarantine group %s does not exist\n", qpath);
        return -1;
    }
    char freeze_path[600], kill_path[600];
    snprintf(freeze_path, sizeof(freeze_path), "%s/cgroup.freeze", qpath);
    snprintf(kill_path, sizeof(kill_path), "%s/cgroup.kill", qpath);

    if (write_file(freeze_path, "1") == 0)
        printf("[defender] strategy=cgroup: froze quarantine group\n");
    else
        printf("[defender] strategy=cgroup: WARNING could not write cgroup.freeze (%s)\n", strerror(errno));

    if (write_file(kill_path, "1") != 0) {
        printf("[defender] strategy=cgroup: cgroup.kill failed (%s) -- kernel older than 5.14?\n", strerror(errno));
        return -1;
    }
    printf("[defender] strategy=cgroup: issued cgroup.kill\n");
    /* the directory can only be removed once the kernel has finished
     * reaping everything inside it; the harness retries this later */
    rmdir(qpath);
    return 0;
}

void strat_cgroup(void) {
    if (cgroup_move() != 0 || cgroup_kill() != 0) {
        printf("[defender] strategy=cgroup: FALLING BACK to tree kill -- this run is NOT a real cgroup result\n");
        fallback_used = 1;
        strat_tree();
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    if (target_pid <= 0 || strategy[0] == '\0') {
        fprintf(stderr, "usage: %s --strategy [pid|pgrp|tree|stopkill|pidfd|cgroup] "
                        "--target-pid <PID> --delay-ms <MS> --llm-mode [off|small|medium|large]\n",
                argv[0]);
        return 2;
    }

    long t_start = now_ms();
    printf("[defender] strategy=%s target=%d delay_ms=%ld llm_mode=%s phase=%s\n",
           strategy, target_pid, delay_ms, llm_mode, phase);

    if (strcmp(phase, "all") != 0) {
        if (strcmp(strategy, "cgroup") != 0) {
            fprintf(stderr, "--phase move/kill only applies to --strategy cgroup\n");
            return 2;
        }
        int rc;
        if (strcmp(phase, "move") == 0) {
            rc = cgroup_move();
        } else if (strcmp(phase, "kill") == 0) {
            if (delay_ms > 0) usleep(delay_ms * 1000);
            rc = cgroup_kill();
        } else {
            fprintf(stderr, "unknown --phase: %s (expected all|move|kill)\n", phase);
            return 2;
        }
        if (rc != 0) fallback_used = 1;
        printf("RESULT strategy=cgroup phase=%s target=%d delay_ms=%ld kill_issued_ms=%ld "
               "benign_pids_checked=0 benign_pids_killed=0 fallback=%d\n",
               phase, target_pid, delay_ms, now_ms() - t_start, fallback_used);
        return rc == 0 ? 0 : 1;
    }

    if (delay_ms > 0) usleep(delay_ms * 1000);

    if (!pid_alive(target_pid)) {
        printf("[defender] target %d is already gone before we acted\n", target_pid);
    } else if (strcmp(strategy, "pid") == 0) {
        strat_pid();
    } else if (strcmp(strategy, "pgrp") == 0) {
        strat_pgrp();
    } else if (strcmp(strategy, "tree") == 0) {
        strat_tree();
    } else if (strcmp(strategy, "stopkill") == 0) {
        strat_stopkill();
    } else if (strcmp(strategy, "pidfd") == 0) {
        strat_pidfd();
    } else if (strcmp(strategy, "cgroup") == 0) {
        strat_cgroup();
    } else {
        fprintf(stderr, "unknown strategy: %s\n", strategy);
        return 2;
    }

    long t_kill_issued = now_ms();

    /* report which benign PIDs (if any) got caught in the blast radius */
    int benign_killed = 0;
    for (int i = 0; i < n_benign; i++) {
        if (!pid_alive(benign_pids[i])) benign_killed++;
    }

    printf("RESULT strategy=%s target=%d delay_ms=%ld kill_issued_ms=%ld "
           "benign_pids_checked=%d benign_pids_killed=%d fallback=%d\n",
           strategy, target_pid, delay_ms, t_kill_issued - t_start,
           n_benign, benign_killed, fallback_used);

    return 0;
}

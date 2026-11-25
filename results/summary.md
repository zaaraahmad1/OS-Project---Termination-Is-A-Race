# Termination Is a Race: results summary

Valid runs per phase: A: 84, B: 72, C: 72, D: 72, E: 48, F: 48.  Cells show **eradicated runs / total runs** unless stated otherwise. Target = parent, fork rate 10, idle CPU, no delay unless the table says otherwise.

## A. Baseline: every attack against every strategy (H1, H2, H3)

| technique | pid | pgrp | tree | stopkill | pidfd | cgroup | cgroup_early |
|---|---|---|---|---|---|---|---|
| respawn | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 |
| doublefork | 0/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| hop | 0/3 | 0/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 |
| watchdog | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 |


Mean time to clear (ms, successful runs only):


| technique | pid | pgrp | tree | stopkill | pidfd | cgroup | cgroup_early |
|---|---|---|---|---|---|---|---|
| respawn | - | 24 | 25 | 27 | - | 44 | 26 |
| doublefork | - | 26 | - | - | - | - | - |
| hop | - | - | 29 | 30 | - | 47 | 30 |
| watchdog | - | 28 | 33 | 34 | - | 55 | 32 |


Mean attack processes still alive at the end (survivors_at_end):


| technique | pid | pgrp | tree | stopkill | pidfd | cgroup | cgroup_early |
|---|---|---|---|---|---|---|---|
| respawn | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| doublefork | 4.0 | 0.0 | 4.0 | 4.3 | 4.0 | 4.0 | 4.0 |
| hop | 1.0 | 1.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| watchdog | 2.0 | 0.0 | 0.0 | 0.0 | 2.0 | 0.0 | 0.0 |


Overall eradication rate per strategy (all four attacks):


| strategy | eradicated | rate |
|---|---|---|
| pid | 0/12 | 0% |
| pgrp | 9/12 | 75% |
| tree | 9/12 | 75% |
| stopkill | 9/12 | 75% |
| pidfd | 0/12 | 0% |
| cgroup | 9/12 | 75% |
| cgroup_early | 9/12 | 75% |


## B. Fork rate (H1)


**respawn**: eradicated/total (mean survivors at end)


| strategy | 2/s | 10/s | 50/s |
|---|---|---|---|
| pid | 0/3 (1.0) | 0/3 (1.0) | 0/3 (1.0) |
| tree | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |
| stopkill | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |
| cgroup | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |


**doublefork**: eradicated/total (mean survivors at end)


| strategy | 2/s | 10/s | 50/s |
|---|---|---|---|
| pid | 0/3 (1.0) | 0/3 (4.0) | 0/3 (18.7) |
| tree | 0/3 (1.0) | 0/3 (4.0) | 0/3 (19.0) |
| stopkill | 0/3 (1.0) | 0/3 (4.3) | 0/3 (19.3) |
| cgroup | 0/3 (1.0) | 0/3 (4.0) | 0/3 (20.0) |


**watchdog**: eradicated/total (mean survivors at end)


| strategy | 2/s | 10/s | 50/s |
|---|---|---|---|
| pid | 0/3 (2.0) | 0/3 (2.0) | 0/3 (2.0) |
| tree | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |
| stopkill | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |
| cgroup | 3/3 (0.0) | 3/3 (0.0) | 3/3 (0.0) |


## C. CPU contention (scheduling)


Eradicated/total, then mean time to clear in ms for successful runs.


| technique | strategy | idle | medium | high |
|---|---|---|---|---|
| respawn | tree | 3/3, 25 ms | 3/3, 48 ms | 3/3, 93 ms |
| respawn | stopkill | 3/3, 27 ms | 3/3, 51 ms | 3/3, 105 ms |
| respawn | cgroup | 3/3, 44 ms | 3/3, 74 ms | 3/3, 110 ms |
| doublefork | tree | 0/3, - | 0/3, - | 0/3, - |
| doublefork | stopkill | 0/3, - | 0/3, - | 0/3, - |
| doublefork | cgroup | 0/3, - | 0/3, - | 0/3, - |
| hop | tree | 3/3, 29 ms | 3/3, 50 ms | 3/3, 99 ms |
| hop | stopkill | 3/3, 30 ms | 3/3, 48 ms | 3/3, 91 ms |
| hop | cgroup | 3/3, 47 ms | 3/3, 60 ms | 3/3, 115 ms |
| watchdog | tree | 3/3, 33 ms | 3/3, 48 ms | 2/3, 134 ms |
| watchdog | stopkill | 3/3, 34 ms | 3/3, 48 ms | 3/3, 104 ms |
| watchdog | cgroup | 3/3, 55 ms | 3/3, 65 ms | 3/3, 124 ms |


## D. Inference delay (H4)


Eradicated/total; then processes alive when the kill landed -> still alive at the end (means).


| technique | strategy | none | small (36.068 s) | medium (171.481 s) | large (336.088 s) |
|---|---|---|---|---|---|
| respawn | pgrp | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 |
| respawn | tree | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 |
| respawn | cgroup | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 |
| respawn | cgroup_early | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 | 3/3; 2 -> 0 |
| doublefork | pgrp | 3/3; 5 -> 0 | 3/3; 363 -> 0 | 3/3; 1705 -> 0 | 3/3; 1999 -> 0 |
| doublefork | tree | 0/3; 5 -> 4 | 0/3; 363 -> 362 | 0/3; 1693 -> 1698 | 0/3; 1999 -> 1998 |
| doublefork | cgroup | 0/3; 5 -> 4 | 0/3; 362 -> 362 | 0/3; 1702 -> 1703 | 0/3; 1999 -> 1998 |
| doublefork | cgroup_early | 0/3; 5 -> 4 | 0/3; 363 -> 4 | 0/3; 1701 -> 4 | 0/3; 2004 -> 393 |


## E. Collateral damage (H5)


Benign processes killed / benign processes started, summed over all runs.


| technique | strategy | benign separate (A) | benign shared (E) | eradicated (E) |
|---|---|---|---|---|
| respawn | pid | 0/9 | 0/9 | 0/3 |
| respawn | pgrp | 0/9 | 9/9 | 3/3 |
| respawn | tree | 0/9 | 9/9 | 3/3 |
| respawn | cgroup | 0/9 | 9/9 | 3/3 |
| doublefork | pid | 0/9 | 0/9 | 0/3 |
| doublefork | pgrp | 0/9 | 9/9 | 3/3 |
| doublefork | tree | 0/9 | 9/9 | 0/3 |
| doublefork | cgroup | 0/9 | 9/9 | 0/3 |
| hop | pid | 0/9 | 0/9 | 0/3 |
| hop | pgrp | 0/9 | 9/9 | 0/3 |
| hop | tree | 0/9 | 9/9 | 3/3 |
| hop | cgroup | 0/9 | 9/9 | 3/3 |
| watchdog | pid | 0/9 | 0/9 | 0/3 |
| watchdog | pgrp | 0/9 | 9/9 | 3/3 |
| watchdog | tree | 0/9 | 9/9 | 3/3 |
| watchdog | cgroup | 0/9 | 9/9 | 3/3 |


## F. Which PID the detector flags (sensitivity)

| technique | strategy | target = parent (A) | target = newest (F) |
|---|---|---|---|
| respawn | pid | 0/3 | 0/3 |
| respawn | tree | 3/3 | 0/3 |
| respawn | stopkill | 3/3 | 0/3 |
| respawn | cgroup | 3/3 | 0/3 |
| doublefork | pid | 0/3 | 0/3 |
| doublefork | tree | 0/3 | 0/3 |
| doublefork | stopkill | 0/3 | 0/3 |
| doublefork | cgroup | 0/3 | 0/3 |
| hop | pid | 0/3 | 0/3 |
| hop | tree | 3/3 | 0/3 |
| hop | stopkill | 3/3 | 0/3 |
| hop | cgroup | 3/3 | 0/3 |
| watchdog | pid | 0/3 | 0/3 |
| watchdog | tree | 3/3 | 0/3 |
| watchdog | stopkill | 3/3 | 0/3 |
| watchdog | cgroup | 3/3 | 0/3 |

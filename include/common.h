#ifndef COMMON_H
#define COMMON_H

// System stuff we'll need - kept getting segfaults until I added most of these
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>

// Constants
#define BUFFER_SIZE 4096 // 4KB chunks
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define PATH_MAX 4096 // system path limit
#define OPER_TRUNC 15 // operation message truncation
#define TS_LEN 19
#define PATH_TRUNC 70 // truncate long paths in output
#define ERR_TRUNC 30 // error message truncation

// Sync context - keeps track of directory pairs
typedef struct SyncInfo {
    char *source_dir;
    char *target_dir;
    time_t last_sync;
    int active;
    int error_count;
    int wd; // inotify watch descriptor
    struct SyncInfo *next;
} SyncInfo;

// Worker process metadata - helps track parallel ops
typedef struct WorkerInfo {
    int pipe_fd;
    pid_t pid;
    char *source_dir;
    char *target_dir;
    char *operation;
    struct WorkerInfo *next;  
} WorkerInfo;

typedef struct PendingSync {
    char *source_dir;
    char *target_dir;
    char *filename;
    char *operation;
    struct PendingSync *next;
} PendingSync;

#endif
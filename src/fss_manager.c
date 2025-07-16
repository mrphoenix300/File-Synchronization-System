#include <common.h>

// Globals get lonely up here, let's keep them company
volatile sig_atomic_t shutdown_requested = 0; // Shutdown handler flag
SyncInfo *sync_info_mem_store = NULL; 
WorkerInfo *active_workers = NULL; // Active worker processes
PendingSync *pending_syncs = NULL; // Pending sync tasks queue
int worker_limit = 5;
int inotify_fd; // File watching magic
char *manager_logfile;
int fss_in, fss_out; 

// Function prototypes
void log_message(const char *message);
void add_sync_info(const char *source, const char *target, int wd);
SyncInfo *find_sync_info(const char *source, const char *target);
SyncInfo *find_sync_info_by_wd(int wd);
void remove_sync_info(const char *source);
void start_worker(const char *source, const char *target, const char *filename, const char *operation);
void process_worker_report(int pipe_fd, const char *source, const char *target, const char *operation, pid_t pid);
void handle_inotify_event(struct inotify_event *event);
void handle_command(const char *command);
void cleanup_resources();
void handle_signal(int sig);



int main(int argc, char *argv[]) {
    int option;
    char *config_file = NULL;
    manager_logfile = "manager.log";
    worker_limit = 5;

    // Parse command line arguments
    while ((option = getopt(argc, argv, "l:c:n:")) != -1) {
        switch (option) {
            case 'l': manager_logfile = optarg; break;
            case 'c': config_file = optarg; break;
            case 'n': worker_limit = atoi(optarg); break;
            default: 
                fprintf(stderr, "Usage: %s -l <logfile> -c <config> -n <workers>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Set up communication pipes
    unlink("fss_in"); // Cleanup previous runs
    unlink("fss_out");
    unlink(manager_logfile);
    mkfifo("fss_in", 0666); // Create new pipes
    mkfifo("fss_out", 0666);

    fss_in = open("fss_in", O_RDONLY | O_NONBLOCK);
    fss_out = open("fss_out", O_WRONLY);

    // Initialize inotify for directory watching
    inotify_fd = inotify_init();
    fcntl(inotify_fd, F_SETFL, O_NONBLOCK); // Avoid blocking on reads

    // Set up signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (config_file) {
        FILE *conf = fopen(config_file, "r");
        if (conf) {
            char source[PATH_MAX], target[PATH_MAX];
            // Read source-destination pairs
            while (fscanf(conf, "%255s %255s", source, target) == 2) {
                int wd = inotify_add_watch(inotify_fd, source, IN_CREATE | IN_MODIFY | IN_DELETE);
                if (wd != -1) {
                    char cmd_buffer[2 * PATH_MAX + 10];
                    snprintf(cmd_buffer, sizeof(cmd_buffer), "add %s %s", source, target);
                    handle_command(cmd_buffer);
                }
            }
            fclose(conf);
        }
    }

    // Main event loop
    while (!shutdown_requested) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(inotify_fd, &read_fds); // Watch for file changes
        FD_SET(fss_in, &read_fds); // Watch for commands

        struct timeval timeout = {.tv_sec = 1}; // Check every second
        int ready = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);

        if (ready == -1 && errno != EINTR) {
            perror("select() had a bad day");
            break;
        }

        // Handle file system events
        if (FD_ISSET(inotify_fd, &read_fds)) {
            char event_buffer[BUF_LEN];
            ssize_t bytes_read = read(inotify_fd, event_buffer, BUF_LEN);
            for (char *ptr = event_buffer; ptr < event_buffer + bytes_read; ) {
                struct inotify_event *event = (struct inotify_event *)ptr;
                handle_inotify_event(event);
                ptr += EVENT_SIZE + event->len;
            }
        }

        // Handle incoming commands
        if (FD_ISSET(fss_in, &read_fds)) {
            char cmd[256];
            ssize_t bytes = read(fss_in, cmd, sizeof(cmd));
            if (bytes > 0) {
                cmd[bytes] = '\0';
                handle_command(cmd);
            }
        }

        WorkerInfo **worker_ptr = &active_workers;
        while (*worker_ptr) {
            int status;
            pid_t result = waitpid((*worker_ptr)->pid, &status, WNOHANG);
            
            if (result > 0) {
                // Worker completed
                process_worker_report(
                    (*worker_ptr)->pipe_fd,
                    (*worker_ptr)->source_dir,
                    (*worker_ptr)->target_dir,
                    (*worker_ptr)->operation,
                    (*worker_ptr)->pid // Add PID
                );
                
                // Remove from active workers
                WorkerInfo *completed = *worker_ptr;
                *worker_ptr = completed->next;
                
                // Free resources
                free(completed->source_dir);
                free(completed->target_dir);
                free(completed->operation);
                free(completed);
            } else {
                // Move to next worker
                worker_ptr = &(*worker_ptr)->next;
            }
        }

        // Process pending sync tasks if slots are available
        while (pending_syncs != NULL) {
            // Count active workers
            int active_count = 0;
            WorkerInfo *w = active_workers;
            while (w) {
                active_count++;
                w = w->next;
            }

            if (active_count >= worker_limit) break;

            // Dequeue the oldest pending sync (FIFO)
            PendingSync *current = pending_syncs;
            PendingSync *prev = NULL;
            while (current->next != NULL) {
                prev = current;
                current = current->next;
            }

            // Start the worker
            start_worker(current->source_dir, current->target_dir, current->filename, current->operation);

            // Remove from queue
            if (prev) prev->next = NULL;
            else pending_syncs = NULL;

            // Free memory
            free(current->source_dir);
            free(current->target_dir);
            free(current->filename);
            free(current->operation);
            free(current);
        }
    }

    cleanup_resources();
    return EXIT_SUCCESS;
}

/* Helper to write log entries with timestamps */
void log_message(const char *message) {

    FILE *log = fopen(manager_logfile, "a");
    if (log) {
        fprintf(log, "%s", message);
        fclose(log);
    }
}

void add_sync_info(const char *source, const char *target, int wd) {
    SyncInfo *new_entry = malloc(sizeof(SyncInfo));
    new_entry->source_dir = strdup(source);
    new_entry->target_dir = strdup(target);
    new_entry->last_sync = time(NULL);
    new_entry->active = 1;
    new_entry->error_count = 0;
    new_entry->wd = wd;
    new_entry->next = sync_info_mem_store;
    sync_info_mem_store = new_entry;
}

/* Find a sync job by its source-target directory */
SyncInfo *find_sync_info(const char *source, const char *target) {
    SyncInfo *current = sync_info_mem_store;
    while (current) {
        if (strcmp(current->source_dir, source) == 0 && 
            (target == NULL || strcmp(current->target_dir, target) == 0)) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* Find sync job by watch ID  */
SyncInfo *find_sync_info_by_wd(int wd) {
    SyncInfo *current = sync_info_mem_store;
    while (current) {
        if (current->wd == wd) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* Spin up a new worker process  */
void start_worker(const char *source, const char *target, const char *filename, const char *operation) {
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) { // Child process
        close(pipe_fd[0]); // Don't need read end
        dup2(pipe_fd[1], STDOUT_FILENO); // Redirect stdout to pipe
        close(pipe_fd[1]);

        execl("./bin/worker", "worker", source, target, filename, operation, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else if (pid > 0) { // Parent process
        close(pipe_fd[1]); // Close write end

        // Track the new worker
        WorkerInfo *new_worker = malloc(sizeof(WorkerInfo));
        new_worker->pipe_fd = pipe_fd[0];
        new_worker->pid = pid;
        new_worker->source_dir = strdup(source);
        new_worker->target_dir = strdup(target);
        new_worker->operation = strdup(operation);
        new_worker->next = active_workers;
        active_workers = new_worker;

    } else {
        perror("fork");
    }
}

/* Process worker's final report - detective work */
void process_worker_report(int pipe_fd, const char *source, const char *target, const char *operation, pid_t pid) {

    char report[BUFFER_SIZE];
    ssize_t bytes_read = read(pipe_fd, report, sizeof(report) - 1);
    SyncInfo *job = find_sync_info(source, NULL);
    time_t now = time(NULL);
    char timestamp[TS_LEN + 1];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (bytes_read > 0) {
        report[bytes_read] = '\0';
        char *status = "UNKNOWN";
        char details[512] = "No details";
        
        // Parse the worker's report
        char *line = strtok(report, "\n");
        while (line != NULL) {
            if (strncmp(line, "STATUS: ", 7) == 0) {
                status = line + 7;  // Skip prefix
            } else if (strncmp(line, "DETAILS: ", 9) == 0) {
                strncpy(details, line + 9, sizeof(details) - 1);
            }
            line = strtok(NULL, "\n");
        }

        // Log the drama
        FILE *log = fopen(manager_logfile, "a");
        if (log) {
            fprintf(log, "[%s] [%s] [%s] [%d] [%s] [%s] [%s]\n", 
                    timestamp, source, target, pid, operation, status, details);
            fclose(log);
        }
    }

    if (job) {
        job->last_sync = now;
        if (strstr(report, "ERROR") || strstr(report, "PARTIAL")) {
            // Count errors
            char *error_start = strstr(report, "ERRORS:");
            if (error_start) {
                char *line = strtok(error_start, "\n");
                while (line) {
                    job->error_count++;
                    line = strtok(NULL, "\n");
                }
            }
        }
    }
    
    close(pipe_fd);
}

/* Handle signals - don't ignore the universe */
void handle_signal(int sig) {
    switch(sig) {
        case SIGCHLD:
            // Reap zombie children while we can
            while (waitpid(-1, NULL, WNOHANG) > 0);
            break;
        case SIGINT:
        case SIGTERM:
            shutdown_requested = 1; // Polite shutdown request
            break;
    }
}

/* React to filesystem drama */
void handle_inotify_event(struct inotify_event *event) {
    SyncInfo *job = find_sync_info_by_wd(event->wd);
    if (!job || !job->active) return;

    const char *operation = NULL;
    if (event->mask & IN_CREATE) operation = "ADDED";
    else if (event->mask & IN_MODIFY) operation = "MODIFIED";
    else if (event->mask & IN_DELETE) operation = "DELETED";

    if (operation && event->len > 0) {
        start_worker(job->source_dir, job->target_dir, event->name, operation);
        job->last_sync = time(NULL); // Fresh sync timestamp
    }
}

/* Handle incoming commands - like a very specific text adventure */
void handle_command(const char *command) {
    char cmd[256], source[PATH_MAX], target[PATH_MAX];
    char timestamp[TS_LEN + 1];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Try to parse the command - sometimes users surprise us
    if (sscanf(command, "%255s", cmd) != 1) {
        write(fss_out, "Invalid status command format\n", 31);
        return;
    }

    /*------- Add New Sync Job -------*/
    if (strcmp(cmd, "add") == 0) {
        // Parse source and target paths
        if (sscanf(command + 4, "%255s %255s", source, target) != 2) {
            write(fss_out, "Invalid add command format\n", 28);
            return;
        }

        // Check if the source-target pair already exists
        SyncInfo *existing = find_sync_info(source, target);
        if (existing) {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Already in queue: %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
            return;
        }
        // Attempt to watch the new directory
        int watch_id = inotify_add_watch(inotify_fd, source, IN_CREATE | IN_MODIFY | IN_DELETE);
        if (watch_id == -1) {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Failed to monitor %.*s: %s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source, strerror(errno));
            write(fss_out, response, strlen(response));
            return;
        }

        // Add to sync info
        add_sync_info(source, target, watch_id);

        // Start initial sync (check worker limit)
        int active_count = 0;
        WorkerInfo *w = active_workers;
        while (w) {
            active_count++;
            w = w->next;
        }

        if (active_count < worker_limit) {
            start_worker(source, target, "ALL", "FULL");
        } else {
            // Add to pending queue
            PendingSync *new_pending = malloc(sizeof(PendingSync));
            new_pending->source_dir = strdup(source);
            new_pending->target_dir = strdup(target);
            new_pending->filename = strdup("ALL");
            new_pending->operation = strdup("FULL");
            new_pending->next = pending_syncs;
            pending_syncs = new_pending;
        }

        // Log success
        char response[256];
        snprintf(response, sizeof(response), 
                "[%.*s] Added directory: %.*s -> %.*s\n",
                TS_LEN, timestamp, PATH_TRUNC, source, PATH_TRUNC, target);
        write(fss_out, response, strlen(response));
        log_message(response);

        snprintf(response, sizeof(response), 
                "[%.*s] Monitoring started for %.*s\n",
                TS_LEN, timestamp, PATH_TRUNC, source);
        write(fss_out, response, strlen(response));
        log_message(response);
    } else if (strcmp(cmd, "cancel") == 0) {
        if (sscanf(command + 6, "%255s", source) != 1) {
            write(fss_out, "Invalid status command format\n", 31);
            return;
        }

        SyncInfo *job = find_sync_info(source, NULL);
        if (job && job->active) {
            inotify_rm_watch(inotify_fd, job->wd);
            job->active = 0; // Mark as inactive

            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Monitoring stopped for %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
            log_message(response);
        } else {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Directory not monitored: %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
        }

    /*------- Status Check -------*/
    } else if (strcmp(cmd, "status") == 0) {
        if (sscanf(command + 6, "%255s", source) != 1) {
            write(fss_out, "Invalid status command format\n", 31);
            return;
        }

        SyncInfo *job = find_sync_info(source, NULL);
        if (job) {
            char last_sync[TS_LEN + 1];
            strftime(last_sync, sizeof(last_sync), "%Y-%m-%d %H:%M:%S", localtime(&job->last_sync));
            
            char response[512];
            snprintf(response, sizeof(response),
                "[%.*s] Status requested for %.*s\n"
                "Directory: %.*s\n"
                "Target: %.*s\n"
                "Last Sync: %.*s\n"
                "Errors: %d\n"
                "Status: %s\n",
                TS_LEN, timestamp,
                PATH_TRUNC, source,
                PATH_TRUNC, source,
                PATH_TRUNC, job->target_dir,
                TS_LEN, last_sync,
                job->error_count,
                job->active ? "Active" : "Inactive");
            
            write(fss_out, response, strlen(response));
        } else {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Directory not monitored: %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
        }

    /*------- Manual Sync Trigger -------*/
    } else if (strcmp(cmd, "sync") == 0) {
        if (sscanf(command + 4, "%255s", source) != 1) {
            write(fss_out, "Invalid command format\n", 24);
            return;
        }
    
        SyncInfo *job = find_sync_info(source, NULL);
        if (!job) {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Directory not monitored: %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
            return;
        }
    
        // Check if a worker is already active for this source
        int in_progress = 0;
        WorkerInfo *w = active_workers;
        while (w) {
            if (strcmp(w->source_dir, source) == 0) {
                in_progress = 1;
                break;
            }
            w = w->next;
        }
    
        if (in_progress) {
            char response[256];
            snprintf(response, sizeof(response), 
                    "[%.*s] Sync already in progress %.*s\n",
                    TS_LEN, timestamp, PATH_TRUNC, source);
            write(fss_out, response, strlen(response));
        } else {
            // Check worker limit
            int active_count = 0;
            w = active_workers;
            while (w) {
                active_count++;
                w = w->next;
            }
    
            if (active_count < worker_limit) {
                char response[512];
                snprintf(response, sizeof(response), 
                        "[%.*s] Syncing directory: %.*s -> %.*s\n",
                        TS_LEN, timestamp, 
                        PATH_TRUNC, job->source_dir, 
                        PATH_TRUNC, job->target_dir);
                write(fss_out, response, strlen(response));
                log_message(response);
                start_worker(job->source_dir, job->target_dir, "ALL", "FULL");
                snprintf(response, sizeof(response),
                    "[%s] Sync completed %s -> %s Errors:%d\n",
                    timestamp, job->source_dir, job->target_dir, job->error_count);
                write(fss_out, response, strlen(response));
                log_message(response);
            } else {
                // Add to pending queue
                PendingSync *new_pending = malloc(sizeof(PendingSync));
                new_pending->source_dir = strdup(job->source_dir);
                new_pending->target_dir = strdup(job->target_dir);
                new_pending->filename = strdup("ALL");
                new_pending->operation = strdup("FULL");
                new_pending->next = pending_syncs;
                pending_syncs = new_pending;
            }
        }
    /* --------- Shutdown Command -------------*/
    } else if (strcmp(cmd, "shutdown") == 0) {
        shutdown_requested = 1;
        char response[512];
        snprintf(response, sizeof(response),
                "[%.*s] Shutting down manager...\n"
                "[%.*s] Waiting for all active workers to finish\n"
                "[%.*s] Processing remaining queued tasks\n"
                "[%.*s] Manager shutdown complete.\n",
                TS_LEN, timestamp, 
                TS_LEN, timestamp, 
                TS_LEN, timestamp,
                TS_LEN, timestamp);
        write(fss_out, response, strlen(response));

    /*------- Unknown Command -------*/
    } else {
        char response[256];
        snprintf(response, sizeof(response), 
                "[%.*s] Unknown command: %.*s\n",
                TS_LEN, timestamp, PATH_TRUNC, cmd);
        write(fss_out, response, strlen(response));
    }
}

/* Tidy up before leaving */
void cleanup_resources() {
    // Fire all workers
    WorkerInfo *current_worker = active_workers;
    while (current_worker) {
        close(current_worker->pipe_fd);
        kill(current_worker->pid, SIGTERM); // Polite termination request
        waitpid(current_worker->pid, NULL, 0);
        WorkerInfo *next = current_worker->next;
        free(current_worker->source_dir);
        free(current_worker->target_dir);
        free(current_worker->operation);
        free(current_worker);
        current_worker = next;
    }

    // Clear sync jobs
    SyncInfo *current_sync = sync_info_mem_store;
    while (current_sync) {
        inotify_rm_watch(inotify_fd, current_sync->wd);
        SyncInfo *next = current_sync->next;
        free(current_sync->source_dir);
        free(current_sync->target_dir);
        free(current_sync);
        current_sync = next;
    }

    // Clean pending sync tasks
    PendingSync *current_pending = pending_syncs;
    while (current_pending != NULL) {
        PendingSync *next = current_pending->next;
        free(current_pending->source_dir);
        free(current_pending->target_dir);
        free(current_pending->filename);
        free(current_pending->operation);
        free(current_pending);
        current_pending = next;
    }

    // Close everything that's open
    close(inotify_fd);
    close(fss_in);
    close(fss_out);
    unlink("fss_in"); // Remove FIFOs
    unlink("fss_out");
}
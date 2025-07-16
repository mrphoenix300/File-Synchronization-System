/* A bit rough around the edges, but gets the job done */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // POSIX stuff
#include <fcntl.h> // file control
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h> // error codes
#include <time.h> // timestamping
#include <signal.h> // ctrl+c handling

#define PIPE_IN "fss_in"
#define PIPE_OUT "fss_out"
#define BUFFER_SIZE 1024

// Global state - yeah I know, globals are evil but practical
int running = 1;
int pipe_in_fd = -1;
int pipe_out_fd = -1;
FILE *log_file = NULL;

void get_timestamp(char *buffer, size_t size);
void log_command(const char *command);
void log_response(const char *response);
void cleanup();
void handle_signal(int sig);
int open_pipes();
int send_command(const char *command);
int read_response(char *buffer, size_t size);



int main(int argc, char *argv[]) {
    char *log_filename = "console.log";
    int opt;
    
    // Handle command line options
    while ((opt = getopt(argc, argv, "l:")) != -1) {
        switch (opt) {
            case 'l':
                log_filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -l <logfile>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Set up signal handlers for clean exits
    signal(SIGINT, handle_signal); // ctrl+c
    signal(SIGTERM, handle_signal); // kill command

    // Open log file
    remove(log_filename);
    log_file = fopen(log_filename, "a");
    if (!log_file) {
        perror("Error opening log file");
        exit(EXIT_FAILURE);
    }

    // Open communication pipes
    if (open_pipes() == -1) {
        cleanup();
        exit(EXIT_FAILURE);
    }

    printf("FileSync Console\n");
    printf("Type 'help' for available commands\n");

    char user_input[BUFFER_SIZE];
    char system_output[BUFFER_SIZE];
    
    while (running) {
        

        // Read responses until we get nothing back
        while (1) {
            int bytes = read_response(system_output, BUFFER_SIZE);
            if (bytes == -1) break;
            if (bytes > 0) {
                printf("%s", system_output); 
                log_response(system_output);
            }
            else break;
        }

        printf("\n> ");
        fflush(stdout);

        // Read user input
        if (!fgets(user_input, BUFFER_SIZE, stdin)) {
            if (feof(stdin)) {  // Handle Ctrl+D
                printf("\n");
                running = 0;
                continue;
            }
            perror("Error reading input");
            continue;
        }

        // Remove newline and trim whitespace
        user_input[strcspn(user_input, "\n")] = '\0';
        char *trimmed_cmd = user_input + strspn(user_input, " ");
        if (*trimmed_cmd == '\0') continue;

        // Log it 
        log_command(trimmed_cmd);
        // Ship it to the manager
        if (send_command(trimmed_cmd) == -1) {
            fprintf(stderr, "Failed to send command to manager\n");
            continue;
        }

        // Handle shutdown command
        if (strncmp(trimmed_cmd, "shutdown", 8) == 0) {
            running = 0;
            while (1) {
                int bytes = read_response(system_output, BUFFER_SIZE);
                if (bytes == -1) break;
                if (bytes > 0) {
                    printf("%s", system_output); 
                    log_response(system_output);
                }
                else break;
            }
        }
    }

    cleanup();
    return EXIT_SUCCESS;
}

/* Makes a nice timestamp for logging */
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* Write command to log with timestamp */
void log_command(const char *command) {
    char timestamp[20];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "[%s] Command: %s\n", timestamp, command);
    fflush(log_file);
}

/* Record system responses */
void log_response(const char *response) {
    fprintf(log_file, "%s", response);
    fflush(log_file);
}

/* Clean up resources - important for pipes! */
void cleanup() {
    if (pipe_in_fd != -1) close(pipe_in_fd);
    if (pipe_out_fd != -1) close(pipe_out_fd);
    if (log_file) fclose(log_file);
}

/* Handle signals for graceful exit */
void handle_signal(int sig) {
    running = 0;
    printf("\nShutting down console...\n");
}

/* Connect to our named pipes */
int open_pipes() {
    // Open outgoing pipe (to manager)
    pipe_in_fd = open(PIPE_IN, O_WRONLY | O_NONBLOCK);
    if (pipe_in_fd == -1) {
        perror("Error opening input pipe");
        return -1;
    }

    // Open incoming pipe (from manager)
    pipe_out_fd = open(PIPE_OUT, O_RDONLY | O_NONBLOCK);
    if (pipe_out_fd == -1) {
        perror("Error opening output pipe");
        close(pipe_in_fd);
        return -1;
    }

    return 0;
}

/* Send command through pipe */
int send_command(const char *command) {
    ssize_t bytes_written = write(pipe_in_fd, command, strlen(command));
    if (bytes_written == -1) {
        perror("Error writing to pipe");
        return -1;
    }
    return 0;
}

/* Read response with timeout */
int read_response(char *buffer, size_t size) {
    fd_set read_fds;
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    int ready;

    FD_ZERO(&read_fds);
    FD_SET(pipe_out_fd, &read_fds);

    do {
        ready = select(pipe_out_fd + 1, &read_fds, NULL, NULL, &timeout);
    } while (ready == -1 && errno == EINTR);

    if (ready == -1) {
        perror("select() error");
        return -1;
    }

    if (FD_ISSET(pipe_out_fd, &read_fds)) {
        ssize_t bytes_read = read(pipe_out_fd, buffer, size - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            return bytes_read;
        }
    }
    return 0;
}
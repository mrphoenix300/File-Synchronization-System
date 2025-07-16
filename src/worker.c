#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#define BUFFER_SIZE 4096
#define MAX_ERRORS 500 // max errors before we give up
#define ERROR_MSG_SIZE 512 // error string limit
#define PATH_MAX 4096
#define PATH_TRUNC 180
#define ERR_TRUNC 60

 // main report container
typedef struct {
    int files_copied;
    int files_skipped;
    char errors[MAX_ERRORS][ERROR_MSG_SIZE];
    int error_count;
} SyncReport;

void copy_file(const char *src, const char *dest, SyncReport *report);
void full_sync(const char *source, const char *target, SyncReport *report);
void generate_report(const SyncReport *report, const char *operation, const char *filename);
void create_target_directory(const char *path);



int main(int argc, char *argv[]) {
    if (argc != 5) { // arg check
        fprintf(stderr, "Usage: %s <source> <target> <filename> <operation>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    SyncReport report = {0}; // init report
    const char *operation = argv[4];
    
    create_target_directory(argv[2]); // make sure target exists

    if (strcmp(operation, "FULL") == 0) { // full sync mode
        full_sync(argv[1], argv[2], &report);
    } else { // single file operation
        char src_path[PATH_MAX], dest_path[PATH_MAX];
        snprintf(src_path, PATH_MAX, "%s/%s", argv[1], argv[3]);
        snprintf(dest_path, PATH_MAX, "%s/%s", argv[2], argv[3]);

        if (strcmp(operation, "DELETED") == 0) { // delete operation
            if (unlink(dest_path) == -1) { // try remove
                char err_buf[128];
                strerror_r(errno, err_buf, sizeof(err_buf));
                snprintf(report.errors[report.error_count++], ERROR_MSG_SIZE,
                       "Delete failed: %.*s (%.*s)",
                       PATH_TRUNC, dest_path,
                       ERR_TRUNC, err_buf);
            }
        } else { // copy/update
            copy_file(src_path, dest_path, &report);
        }
    }

    generate_report(&report, operation, argv[3]);
    return report.error_count > 0 ? EXIT_FAILURE : EXIT_SUCCESS; // exit code based on errors
}

 /* The meat - copy file contents */
void copy_file(const char *src, const char *dest, SyncReport *report) {
    int src_fd = open(src, O_RDONLY);
    if (src_fd == -1) {
        char err_buf[128];
        strerror_r(errno, err_buf, sizeof(err_buf));
        snprintf(report->errors[report->error_count++], ERROR_MSG_SIZE,
               "Open failed: %.*s (%.*s)", 
               PATH_TRUNC, src, 
               ERR_TRUNC, err_buf);
        if (report->error_count >= MAX_ERRORS) return;
        return;
    }

    int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644); // rw-r--r--
    if (dest_fd == -1) {
        char err_buf[128];
        strerror_r(errno, err_buf, sizeof(err_buf));
        snprintf(report->errors[report->error_count++], ERROR_MSG_SIZE,
               "Create failed: %.*s (%.*s)", 
               PATH_TRUNC, dest, 
               ERR_TRUNC, err_buf);
        close(src_fd);
        if (report->error_count >= MAX_ERRORS) return;
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;
    
    while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) { // read chunks
        bytes_written = write(dest_fd, buffer, bytes_read);
        // printf("Copied %zd bytes...\n", bytes_out);  // debug
        if (bytes_written != bytes_read) { // write mismatch
            char err_buf[128];
            strerror_r(errno, err_buf, sizeof(err_buf));
            snprintf(report->errors[report->error_count++], ERROR_MSG_SIZE,
                   "Write failed: %.*s (%.*s)",
                   PATH_TRUNC, dest,
                   ERR_TRUNC, err_buf);
            if (report->error_count >= MAX_ERRORS) break;
        }
    }

    close(src_fd);
    close(dest_fd); // cleanup
    
    if (bytes_read == -1) { 
        char err_buf[128];
        strerror_r(errno, err_buf, sizeof(err_buf));
        snprintf(report->errors[report->error_count++], ERROR_MSG_SIZE,
               "Read failed: %.*s (%.*s)",
               PATH_TRUNC, src,
               ERR_TRUNC, err_buf);
    } else if (bytes_written >= 0) {
        report->files_copied++; // increment only if no errors
    }
}

/* Handle full directory sync */
void full_sync(const char *source, const char *target, SyncReport *report) {
    DIR *dir = opendir(source);
    if (!dir) {
        char err_buf[128];
        strerror_r(errno, err_buf, sizeof(err_buf));
        snprintf(report->errors[report->error_count++], ERROR_MSG_SIZE,
               "Dir open failed: %.*s (%.*s)",
               PATH_TRUNC, source,
               ERR_TRUNC, err_buf);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue; // skip dirs/symlinks
        
        char src_path[PATH_MAX], dest_path[PATH_MAX];
        snprintf(src_path, PATH_MAX, "%s/%s", source, entry->d_name);
        snprintf(dest_path, PATH_MAX, "%s/%s", target, entry->d_name);
        
        int prev_errors = report->error_count;
        copy_file(src_path, dest_path, report);
        
        if (report->error_count > prev_errors) {
            report->files_skipped++; // tally skips
        }
        if (report->error_count >= MAX_ERRORS) break; // bail if too many errors
    }
    closedir(dir);
}

 /* Generate the final output report */
void generate_report(const SyncReport *report, const char *operation, const char *filename) {
    printf("EXEC_REPORT_START\n");
    
    // Determine STATUS
    const char *status;
    if (report->error_count == 0) {
        status = "SUCCESS";
    } else if (report->files_copied > 0 || report->files_skipped < report->error_count) {
        status = "PARTIAL";
    } else {
        status = "ERROR";
    }
    printf("STATUS: %s\n", status);

    // Build details line
    printf("DETAILS: ");
    if (strcmp(operation, "FULL") == 0) { // full sync report
        printf("%d files copied", report->files_copied);
        if (report->files_skipped > 0) { // add skips if any
            printf(", %d skipped", report->files_skipped);
        }
    } else { // single file op
        printf("File: %s", filename);
        if (report->error_count > 0) {
            // Append first error (truncated to ERR_TRUNC)
            printf(" - %.*s", ERR_TRUNC, report->errors[0]);
        }
    }
    printf("\n");

    // Dump errors if any
    if (report->error_count > 0) {
        printf("ERRORS:\n");
        for (int i = 0; i < report->error_count; i++) {
            printf("- %s\n", report->errors[i]);
        }
    }

    printf("EXEC_REPORT_END\n");
}

/* Create target dir if needed */
void create_target_directory(const char *path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory: %s\n", path);
    }
}
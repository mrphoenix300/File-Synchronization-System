#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

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

/* Never write beyond the fixed-size error report. */
static void record_error(SyncReport *report, const char *kind,
                         const char *path, int error_number) {
    if (report->error_count >= MAX_ERRORS) return;

    snprintf(report->errors[report->error_count], ERROR_MSG_SIZE,
             "%s: %.*s (%.*s)", kind, PATH_TRUNC, path,
             ERR_TRUNC, strerror(error_number));
    report->error_count++;
}

/* Single-file events must stay within the configured directories. */
static int valid_filename(const char *name) {
    return name[0] != '\0' && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static int make_file_path(char *out, size_t size,
                          const char *dir, const char *name) {
    int n = snprintf(out, size, "%s/%s", dir, name);
    return n >= 0 && (size_t)n < size;
}

/*
 * Walk every directory component without following symlinks. Keep the final
 * directory fd open and use *at() operations so path replacement cannot
 * redirect file operations after validation.
 */
static int open_safe_directory(const char *path, int create_last) {
    if (!path || !*path) { errno = EINVAL; return -1; }
    size_t len = strlen(path);
    if (len >= PATH_MAX) { errno = ENAMETOOLONG; return -1; }

    char *copy = strdup(path);
    if (!copy) return -1;

    int dirfd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) { free(copy); return -1; }

    char *saveptr = NULL;
    char *part = strtok_r(copy, "/", &saveptr);
    while (part) {
        if (strcmp(part, "..") == 0) {
            errno = EINVAL;
            goto failed;
        }
        if (strcmp(part, ".") == 0) {
            part = strtok_r(NULL, "/", &saveptr);
            continue;
        }

        char *next = strtok_r(NULL, "/", &saveptr);
        int fd = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 && errno == ENOENT && create_last && !next) {
            if (mkdirat(dirfd, part, 0755) < 0 && errno != EEXIST) goto failed;
            fd = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (fd < 0) goto failed;
        close(dirfd);
        dirfd = fd;
        part = next;
    }

    free(copy);
    return dirfd;

failed:;
    int saved_errno = errno;
    close(dirfd);
    free(copy);
    errno = saved_errno;
    return -1;
}

void copy_file(int source_dirfd, int target_dirfd, const char *filename,
               const char *src, const char *dest, SyncReport *report);
void full_sync(int source_dirfd, int target_dirfd, const char *source,
               const char *target, SyncReport *report);
void generate_report(const SyncReport *report, const char *operation, const char *filename);




int main(int argc, char *argv[]) {
    if (argc != 5) { // arg check
        fprintf(stderr, "Usage: %s <source> <target> <filename> <operation>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    SyncReport report = {0}; // init report
    const char *operation = argv[4];
    
    int source_dirfd = open_safe_directory(argv[1], 0);
    if (source_dirfd < 0) {
        record_error(&report, "Unsafe source directory", argv[1], errno);
        generate_report(&report, operation, argv[3]);
        return EXIT_FAILURE;
    }
    int target_dirfd = open_safe_directory(argv[2], 1);
    if (target_dirfd < 0) {
        record_error(&report, "Unsafe target directory", argv[2], errno);
        close(source_dirfd);
        generate_report(&report, operation, argv[3]);
        return EXIT_FAILURE;
    }

    if (strcmp(operation, "FULL") == 0) { // full sync mode
        full_sync(source_dirfd, target_dirfd, argv[1], argv[2], &report);
    } else { // single file operation
        char src_path[PATH_MAX], dest_path[PATH_MAX];
        if (!valid_filename(argv[3]) ||
            !make_file_path(src_path, sizeof(src_path), argv[1], argv[3]) ||
            !make_file_path(dest_path, sizeof(dest_path), argv[2], argv[3])) {
            record_error(&report, "Invalid filename or path", argv[3], EINVAL);
            close(source_dirfd);
            close(target_dirfd);
            generate_report(&report, operation, argv[3]);
            return EXIT_FAILURE;
        }

        if (strcmp(operation, "DELETED") == 0) { // delete operation
            if (unlinkat(target_dirfd, argv[3], 0) == -1) { // try remove
                record_error(&report, "Delete failed", dest_path, errno);
            }
        } else { // copy/update
            copy_file(source_dirfd, target_dirfd, argv[3], src_path, dest_path, &report);
        }
    }

    close(source_dirfd);
    close(target_dirfd);
    generate_report(&report, operation, argv[3]);
    return report.error_count > 0 ? EXIT_FAILURE : EXIT_SUCCESS; // exit code based on errors
}

 /* The meat - copy file contents */
void copy_file(int source_dirfd, int target_dirfd, const char *filename,
               const char *src, const char *dest, SyncReport *report) {
    int src_fd = openat(source_dirfd, filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (src_fd == -1) {
        record_error(report, "Open failed", src, errno);
        if (report->error_count >= MAX_ERRORS) return;
        return;
    }

    struct stat src_stat;
    if (fstat(src_fd, &src_stat) == -1 || !S_ISREG(src_stat.st_mode)) {
        record_error(report, "Source is not a regular file", src, EINVAL);
        close(src_fd);
        return;
    }

    int dest_fd = openat(target_dirfd, filename,
                         O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0644); // rw-r--r--
    if (dest_fd == -1) {
        record_error(report, "Create failed", dest, errno);
        close(src_fd);
        if (report->error_count >= MAX_ERRORS) return;
        return;
    }

    struct stat dest_stat;
    if (fstat(dest_fd, &dest_stat) == -1 || !S_ISREG(dest_stat.st_mode)) {
        record_error(report, "Destination is not a regular file", dest, EINVAL);
        close(src_fd);
        close(dest_fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;
    
    while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) { // read chunks
        bytes_written = write(dest_fd, buffer, bytes_read);
        // printf("Copied %zd bytes...\n", bytes_out);  // debug
        if (bytes_written != bytes_read) { // write mismatch
            record_error(report, "Write failed", dest, errno);
            if (report->error_count >= MAX_ERRORS) break;
        }
    }

    close(src_fd);
    close(dest_fd); // cleanup
    
    if (bytes_read == -1) { 
        record_error(report, "Read failed", src, errno);
    } else if (bytes_written >= 0) {
        report->files_copied++; // increment only if no errors
    }
}

/* Handle full directory sync */
void full_sync(int source_dirfd, int target_dirfd, const char *source,
               const char *target, SyncReport *report) {
    DIR *dir = fdopendir(dup(source_dirfd));
    if (!dir) {
        record_error(report, "Dir open failed", source, errno);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue; // skip dirs/symlinks
        
        char src_path[PATH_MAX], dest_path[PATH_MAX];
        if (!valid_filename(entry->d_name) ||
            !make_file_path(src_path, sizeof(src_path), source, entry->d_name) ||
            !make_file_path(dest_path, sizeof(dest_path), target, entry->d_name)) {
            record_error(report, "Invalid filename or path", entry->d_name, EINVAL);
            report->files_skipped++;
            if (report->error_count >= MAX_ERRORS) break;
            continue;
        }

        int prev_errors = report->error_count;
        copy_file(source_dirfd, target_dirfd, entry->d_name, src_path, dest_path, report);
        
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
    } else if (report->files_copied > 0) {
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


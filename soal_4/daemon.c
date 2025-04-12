#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define MAX_PROCESS_NAME 256

void log_process_status(const char *pid, const char *status) {
    FILE *log_file = fopen("debugmon.log", "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(log_file, "[%02d:%02d:%d]-%02d:%02d:%02d_%s_STATUS(%s)\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
            tm.tm_hour, tm.tm_min, tm.tm_sec, pid, status);

    fclose(log_file);
}

void list_processes(const char *user) {
    DIR *dir;
    struct dirent *entry;
    char pid_path[512];
    FILE *fp;
    char line[256];
    char pid[10];
    char name[MAX_PROCESS_NAME];

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            snprintf(pid_path, sizeof(pid_path), "/proc/%s/status", entry->d_name);
            fp = fopen(pid_path, "r");
            if (fp == NULL) continue;

            while (fgets(line, sizeof(line), fp) != NULL) {
                if (strncmp(line, "Uid:", 4) == 0) {
                    int uid;
                    sscanf(line, "Uid:\t%d", &uid);
                    if (uid == getuid()) {
                        printf("PID: %s, Command: %s", entry->d_name, entry->d_name);
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
}

void stop_processes(const char *user) {
    DIR *dir;
    struct dirent *entry;
    char pid_path[512];
    FILE *fp;
    char line[256];
    char pid[10];
    char name[MAX_PROCESS_NAME];

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            snprintf(pid_path, sizeof(pid_path), "/proc/%s/status", entry->d_name);
            fp = fopen(pid_path, "r");
            if (fp == NULL) continue;

            while (fgets(line, sizeof(line), fp) != NULL) {
                if (strncmp(line, "Uid:", 4) == 0) {
                    int uid;
                    sscanf(line, "Uid:\t%d", &uid);
                    if (uid == getuid()) {
                        printf("Stopping process %s (PID: %s)\n", entry->d_name, entry->d_name);
                        pid_t pid = atoi(entry->d_name);
                        kill(pid, SIGKILL);  
                        log_process_status(entry->d_name, "FAILED");
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
}

void revert_processes(const char *user) {
    DIR *dir;
    struct dirent *entry;
    char pid_path[512];
    FILE *fp;
    char line[256];
    char pid[10];
    char name[MAX_PROCESS_NAME];

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            snprintf(pid_path, sizeof(pid_path), "/proc/%s/status", entry->d_name);
            fp = fopen(pid_path, "r");
            if (fp == NULL) continue;

            while (fgets(line, sizeof(line), fp) != NULL) {
                if (strncmp(line, "Uid:", 4) == 0) {
                    int uid;
                    sscanf(line, "Uid:\t%d", &uid);
                    if (uid == getuid()) {
                        printf("Reverting process %s (PID: %s)\n", entry->d_name, entry->d_name);
                        log_process_status(entry->d_name, "RUNNING");
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
}

void daemon_mode(const char *user) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("Failed to fork process");
        exit(1);
    }

    if (pid > 0) {
        exit(0);  
    }

    if (setsid() < 0) {
        perror("Failed to create new session");
        exit(1);
    }

    umask(0);  
    chdir("/");

   
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    while (1) {
        list_processes(user);  
        sleep(10); 
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <command> <user>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        list_processes(argv[2]);
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_processes(argv[2]);
    } else if (strcmp(argv[1], "daemon") == 0) {
        daemon_mode(argv[2]);
    } else if (strcmp(argv[1], "revert") == 0) {
        revert_processes(argv[2]);
    } else if (strcmp(argv[1], "fail") == 0) {
        stop_processes(argv[2]);  
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
    }

    return 0;
}


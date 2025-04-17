#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

void log_status(const char *process_name, const char *status) {
    FILE *log_file = fopen("debugmon.log", "a");
    if (!log_file) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(log_file, "[%02d:%02d:%04d]-[%02d:%02d:%02d]_%s_%s\n",
            t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,
            t->tm_hour, t->tm_min, t->tm_sec,
            process_name, status);
    fclose(log_file);
}

void list_process(const char *user) {
    char command[256];
    snprintf(command, sizeof(command), "ps -u %s -o pid,comm,%%cpu,%%mem", user);
    system(command);
}

void daemon_mode(const char *user) {
    if (fork() == 0) {
        while (1) {
            char command[256];
            snprintf(command, sizeof(command), "ps -u %s -o comm=", user);
            FILE *fp = popen(command, "r");
            if (fp) {
                char proc[100];
                while (fgets(proc, sizeof(proc), fp)) {
                    proc[strcspn(proc, "\n")] = 0;
                    log_status(proc, "RUNNING");
                }
                pclose(fp);
            }
            sleep(5);
        }
        exit(0);
    }
}

void stop_monitoring(const char *user) {
    char command[256];
    snprintf(command, sizeof(command), "pkill -f \"debugmon daemon %s\"", user);
    system(command);
}

void fail_process(const char *user) {
    char command[256];
    snprintf(command, sizeof(command), "ps -u %s -o pid=,comm=", user);
    FILE *fp = popen(command, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            int pid;
            char proc[100];
            sscanf(line, "%d %s", &pid, proc);
            kill(pid, SIGKILL);
            log_status(proc, "FAILED");
        }
        pclose(fp);
    }
    FILE *lock = fopen("debugmon.lock", "w");
    fprintf(lock, "%s", user);
    fclose(lock);
}

void revert_process(const char *user) {
    FILE *lock = fopen("debugmon.lock", "r");
    if (lock) {
        char locked_user[100];
        fgets(locked_user, sizeof(locked_user), lock);
        fclose(lock);
        locked_user[strcspn(locked_user, "\n")] = 0;
        if (strcmp(locked_user, user) == 0) {
            remove("debugmon.lock");
        }
    }
}

int is_locked(const char *user) {
    FILE *lock = fopen("debugmon.lock", "r");
    if (lock) {
        char locked_user[100];
        fgets(locked_user, sizeof(locked_user), lock);
        fclose(lock);
        locked_user[strcspn(locked_user, "\n")] = 0;
        return strcmp(locked_user, user) == 0;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;

    const char *command = argv[1];
    const char *user = argv[2];

    if (strcmp(command, "list") == 0) {
        list_process(user);
    } else if (strcmp(command, "daemon") == 0) {
        daemon_mode(user);
    } else if (strcmp(command, "stop") == 0) {
        stop_monitoring(user);
    } else if (strcmp(command, "fail") == 0) {
        fail_process(user);
    } else if (strcmp(command, "revert") == 0) {
        revert_process(user);
    } else {
        printf("Unknown command\n");
    }

    return 0;
}

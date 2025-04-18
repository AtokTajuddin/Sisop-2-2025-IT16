#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define ZIP_URL "https://drive.google.com/uc?export=download&id=1_5GxIGfQr3mNKuavJbte_AoRkEQLXSKS"
#define ZIP_FILE "starterkit.zip"
#define STARTER_KIT_DIR "starter_kit"
#define QUARANTINE_DIR "quarantine"
#define LOG_FILE "activity.log"
#define PID_FILE "daemon.pid"
#define MAX_PATH 1024

void log_activity(const char *operation, const char *filename, int pid) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "[%d-%m-%Y][%H:%M:%S]", t);

    if (strcmp(operation, "Decrypt") == 0) {
        fprintf(log, "%s - Successfully started decryption process with PID %d\n", timestamp, pid);
    } else if (strcmp(operation, "Quarantine") == 0) {
        fprintf(log, "%s - %s - Successfully moved to quarantine directory\n", timestamp, filename);
    } else if (strcmp(operation, "Return") == 0) {
        fprintf(log, "%s - %s - Successfully returned to starter kit directory\n", timestamp, filename);
    } else if (strcmp(operation, "Eradicate") == 0) {
        fprintf(log, "%s - %s - Successfully deleted\n", timestamp, filename);
    } else if (strcmp(operation, "Shutdown") == 0) {
        fprintf(log, "%s - Successfully shut off decryption process with PID %d\n", timestamp, pid);
    }

    fclose(log);
}

char* base64_decode(const char *input) {
    BIO *bio, *b64;
    int len = strlen(input);
    char *buffer = (char *)malloc(len + 1);
    if (!buffer) return NULL;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf((void*)input, len);
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, buffer, len);
    if (decoded_len < 0) decoded_len = 0;
    buffer[decoded_len] = '\0';

    BIO_free_all(bio);
    return buffer;
}

void start_decrypt_daemon() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    setsid();

    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d", getpid());
        fclose(pf);
    }

    log_activity("Decrypt", NULL, getpid());

    while (1) {
        DIR *dir = opendir(QUARANTINE_DIR);
        struct dirent *entry;

        if (!dir) {
            perror("Failed to open quarantine directory");
            sleep(1);
            continue;
        }

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                char *decoded = base64_decode(entry->d_name);
                if (!decoded || strlen(decoded) == 0) {
                    free(decoded);
                    continue;
                }

                char old_path[MAX_PATH], new_path[MAX_PATH];
                snprintf(old_path, sizeof(old_path), "%s/%s", QUARANTINE_DIR, entry->d_name);
                snprintf(new_path, sizeof(new_path), "%s/%s", QUARANTINE_DIR, decoded);

                if (rename(old_path, new_path) == 0) {
                    // Rename success
                }
                free(decoded);
            }
        }
        closedir(dir);
        sleep(1);
    }
}

void move_files(const char *src_dir, const char *dest_dir, const char *operation) {
    DIR *dir = opendir(src_dir);
    if (!dir) {
        perror("Failed to open source directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char src_path[MAX_PATH], dest_path[MAX_PATH];
            snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
            snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, entry->d_name);

            if (rename(src_path, dest_path) == 0) {
                log_activity(operation, entry->d_name, 0);
            }
        }
    }
    closedir(dir);
}

void eradicate_files() {
    DIR *dir = opendir(QUARANTINE_DIR);
    if (!dir) {
        perror("Failed to open quarantine directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", QUARANTINE_DIR, entry->d_name);

            if (remove(path) == 0) {
                log_activity("Eradicate", entry->d_name, 0);
            }
        }
    }
    closedir(dir);
}

void shutdown_daemon() {
    FILE *pf = fopen(PID_FILE, "r");
    if (!pf) {
        perror("Failed to read PID file");
        return;
    }

    int pid;
    fscanf(pf, "%d", &pid);
    fclose(pf);

    if (kill(pid, SIGTERM) == 0) {
        remove(PID_FILE);
        log_activity("Shutdown", NULL, pid);
    } else {
        perror("Failed to terminate daemon");
    }
}

void download_and_unzip() {
    printf("Downloading zip file...\n");
    char cmd[2048];

    snprintf(cmd, sizeof(cmd), "wget -q --show-progress -O %s \"%s\"", ZIP_FILE, ZIP_URL);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to download file.\n");
        exit(EXIT_FAILURE);
    }

    mkdir(STARTER_KIT_DIR, 0755);

    printf("Extracting zip...\n");
    snprintf(cmd, sizeof(cmd), "unzip -o -q %s -d %s", ZIP_FILE, STARTER_KIT_DIR);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to unzip file.\n");
        exit(EXIT_FAILURE);
    }

    remove(ZIP_FILE);
    printf("Starter kit downloaded and extracted to %s.\n", STARTER_KIT_DIR);
}

int main(int argc, char *argv[]) {
    mkdir(STARTER_KIT_DIR, 0755);
    mkdir(QUARANTINE_DIR, 0755);

    if (argc == 1) {
        download_and_unzip();
        return 0;
    }

    if (argc != 2) {
        printf("Usage: %s [--decrypt|--quarantine|--return|--eradicate|--shutdown]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--decrypt") == 0) {
        start_decrypt_daemon();
    } else if (strcmp(argv[1], "--quarantine") == 0) {
        move_files(STARTER_KIT_DIR, QUARANTINE_DIR, "Quarantine");
    } else if (strcmp(argv[1], "--return") == 0) {
        move_files(QUARANTINE_DIR, STARTER_KIT_DIR, "Return");
    } else if (strcmp(argv[1], "--eradicate") == 0) {
        eradicate_files();
    } else if (strcmp(argv[1], "--shutdown") == 0) {
        shutdown_daemon();
    } else {
        printf("Unknown option: %s\n", argv[1]);
        printf("Usage: %s [--decrypt|--quarantine|--return|--eradicate|--shutdown]\n", argv[0]);
        return 1;
    }

    return 0;
}
   



   
    

   


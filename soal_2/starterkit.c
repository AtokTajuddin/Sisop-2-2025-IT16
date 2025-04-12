#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/inotify.h>
#include <libgen.h>
#include <stdbool.h>

#define ZIP_NAME "starterkit.zip"
#define ZIP_URL "https://drive.google.com/uc?id=1_5GxIGfQr3mNKuavJbte_AoRkEQLXSKS&export=download"
#define QUARANTINE_DIR "karantina"
#define BUF_LEN 4096

void download_and_extract() {
    printf("Mengunduh starterkit...\n");
    char command[512];
    snprintf(command, sizeof(command), "wget -q --show-progress \"%s\" -O %s", ZIP_URL, ZIP_NAME);
    system(command);

    printf("Mengekstrak starterkit...\n");
    snprintf(command, sizeof(command), "unzip -q %s", ZIP_NAME);
    system(command);

    printf("Menghapus file ZIP...\n");
    remove(ZIP_NAME);
}

char *base64_decode(const char *encoded) {
    FILE *fp_in = tmpfile();
    FILE *fp_out = tmpfile();
    if (!fp_in || !fp_out) return NULL;

    fwrite(encoded, 1, strlen(encoded), fp_in);
    rewind(fp_in);

    char command[256];
    snprintf(command, sizeof(command), "base64 -d");
    FILE *pipe = popen(command, "w");
    if (!pipe) return NULL;

    fwrite(encoded, 1, strlen(encoded), pipe);
    pclose(pipe);

    char *decoded = malloc(256);
    fread(decoded, 1, 255, fp_out);
    decoded[255] = '\0';

    fclose(fp_in);
    fclose(fp_out);
    return decoded;
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    setsid();
    chdir("/");

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) close(x);

    openlog("starterkit-daemon", LOG_PID, LOG_DAEMON);
}

void decrypt_names_daemon() {
    daemonize();

    mkdir(QUARANTINE_DIR, 0755);

    int fd = inotify_init();
    if (fd < 0) {
        syslog(LOG_ERR, "Gagal inisialisasi inotify");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, QUARANTINE_DIR, IN_CREATE | IN_MOVED_TO);
    if (wd == -1) {
        syslog(LOG_ERR, "Gagal menambahkan watch di %s", QUARANTINE_DIR);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Daemon karantina berjalan...");

    char buf[BUF_LEN] __attribute__((aligned(8)));
    while (1) {
        int length = read(fd, buf, BUF_LEN);
        if (length < 0) break;

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];
            if (event->len && (event->mask & (IN_CREATE | IN_MOVED_TO))) {
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", QUARANTINE_DIR, event->name);

                char *decoded_name = base64_decode(event->name);
                if (decoded_name) {
                    char new_path[512];
                    snprintf(new_path, sizeof(new_path), "%s/%s", QUARANTINE_DIR, decoded_name);
                    rename(path, new_path);
                    syslog(LOG_INFO, "Renamed: %s -> %s", event->name, decoded_name);
                    free(decoded_name);
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    closelog();
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        download_and_extract();
    } else if (argc == 2 && strcmp(argv[1], "--decrypt") == 0) {
        decrypt_names_daemon();
    } else {
        printf("Penggunaan:\n");
        printf("  ./starterkit           # Download & extract starter kit\n");
        printf("  ./starterkit --decrypt # Jalankan daemon karantina\n");
    }
    return 0;
}

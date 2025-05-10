#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_PATH 1024

void download_and_extract() {
    struct stat st = {0};

    if (stat("Clues", &st) == 0) {
        printf("Folder 'Clues' sudah ada. Melewati download...\n");
        return;
    }

    printf("Mengunduh Clues.zip...\n");
    system("wget -q --show-progress https://drive.google.com/uc?id=1xFn1OBJUuSdnApDseEczKhtNzyGekauK -O Clues.zip");

    printf("Mengekstrak Clues.zip...\n");
    system("unzip -q Clues.zip");
    remove("Clues.zip");
}

void filter_files() {
    const char *clue_dirs[] = {"Clues/ClueA", "Clues/ClueB", "Clues/ClueC", "Clues/ClueD"};
    const int num_dirs = 4;
    const char *filtered_dir = "Filtered";

    struct stat st = {0};
    if (stat(filtered_dir, &st) == -1) {
        mkdir(filtered_dir, 0755);
    }

    for (int i = 0; i < num_dirs; i++) {
        DIR *dp = opendir(clue_dirs[i]);
        if (!dp) {
            perror("Gagal membuka folder Clue");
            continue;
        }

        struct dirent *dir;
        char src[MAX_PATH], dest[MAX_PATH];

        while ((dir = readdir(dp)) != NULL) {
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
                continue;

            if (strlen(dir->d_name) == 5 &&
                isalnum(dir->d_name[0]) &&
                strcmp(&dir->d_name[1], ".txt") == 0) {

                snprintf(src, sizeof(src), "%s/%s", clue_dirs[i], dir->d_name);
                snprintf(dest, sizeof(dest), "%s/%s", filtered_dir, dir->d_name);

                if (rename(src, dest) != 0) {
                    perror("Gagal memindahkan file");
                }
            } else {
                char filepath[MAX_PATH];
                snprintf(filepath, sizeof(filepath), "%s/%s", clue_dirs[i], dir->d_name);
                remove(filepath);
            }
        }
        closedir(dp);
    }

    printf("File .txt berhasil difilter ke folder 'Filtered'\n");
}

int is_digit_filename(const char *filename) {
    return isdigit(filename[0]);
}

int is_letter_filename(const char *filename) {
    return isalpha(filename[0]);
}

int compare_files(const void *a, const void *b) {
    const char **fa = (const char **)a;
    const char **fb = (const char **)b;
    return strcmp(*fa, *fb);
}

void combine_files() {
    DIR *dp = opendir("Filtered");
    if (!dp) {
        perror("Tidak bisa membuka folder Filtered");
        return;
    }

    char *digits[100], *letters[100];
    int dcount = 0, lcount = 0;

    struct dirent *dir;
    while ((dir = readdir(dp)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
            continue;

        if (is_digit_filename(dir->d_name))
            digits[dcount++] = strdup(dir->d_name);
        else if (is_letter_filename(dir->d_name))
            letters[lcount++] = strdup(dir->d_name);
    }
    closedir(dp);

    qsort(digits, dcount, sizeof(char *), compare_files);
    qsort(letters, lcount, sizeof(char *), compare_files);

    FILE *combined = fopen("Combined.txt", "w");
    if (!combined) {
        perror("Gagal membuat Combined.txt");
        return;
    }

    int di = 0, li = 0;
    while (di < dcount || li < lcount) {
        if (di < dcount) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "Filtered/%s", digits[di]);
            FILE *f = fopen(path, "r");
            if (f) {
                char c;
                while ((c = fgetc(f)) != EOF)
                    fputc(c, combined);
                fclose(f);
            }
            remove(path);
            free(digits[di++]);
        }
        if (li < lcount) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "Filtered/%s", letters[li]);
            FILE *f = fopen(path, "r");
            if (f) {
                char c;
                while ((c = fgetc(f)) != EOF)
                    fputc(c, combined);
                fclose(f);
            }
            remove(path);
            free(letters[li++]);
        }
    }

    fclose(combined);
    printf("Isi file berhasil digabung ke 'Combined.txt'\n");
}

char rot13_char(char c) {
    if ('a' <= c && c <= 'z')
        return (c - 'a' + 13) % 26 + 'a';
    if ('A' <= c && c <= 'Z')
        return (c - 'A' + 13) % 26 + 'A';
    return c;
}

void decode_file() {
    FILE *in = fopen("Combined.txt", "r");
    FILE *out = fopen("Decoded.txt", "w");

    if (!in || !out) {
        perror("Gagal membuka file untuk decode");
        return;
    }

    char c;
    while ((c = fgetc(in)) != EOF)
        fputc(rot13_char(c), out);

    fclose(in);
    fclose(out);

    printf("Hasil decode ditulis ke 'Decoded.txt'\n");
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        download_and_extract();
    } else if (argc == 3 && strcmp(argv[1], "-m") == 0) {
        if (strcmp(argv[2], "Filter") == 0)
            filter_files();
        else if (strcmp(argv[2], "Combine") == 0)
            combine_files();
        else if (strcmp(argv[2], "Decode") == 0)
            decode_file();
        else
            printf("Argumen tidak dikenali: %s\n", argv[2]);
    } else {
        printf("Usage:\n");
        printf("  ./action               # Download & unzip Clues.zip\n");
        printf("  ./action -m Filter     # Filter file ke folder Filtered\n");
        printf("  ./action -m Combine    # Gabungkan isi ke Combined.txt\n");
        printf("  ./action -m Decode     # Decode ROT13 ke Decoded.txt\n");
    }

    return 0;
}

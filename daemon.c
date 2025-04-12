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

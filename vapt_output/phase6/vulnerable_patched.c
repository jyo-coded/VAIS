#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Vuln 1: Buffer overflow via strcpy ── */
void greet_user(char *name) {
    char buffer[64];
    strncpy(buffer, name, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  /* bounds-safe copy */
    printf("Hello, %s!\n", buffer);
}

/* ── Vuln 2: gets() — always overflows ── */
void read_input() {
    char buf[128];
    printf("Enter your name: ");
    fgets(buf, sizeof(buf), stdin);  /* replaces unsafe gets() */
    buf[strcspn(buf, "\n")] = 0;  /* strip trailing newline */
    printf("Got: %s\n", buf);
}

/* ── Vuln 3: Format string injection ── */
void show_message(char *msg) {
    printf("%s", msg);  /* literal format string */
}

/* ── Vuln 4: Command injection via system() ── */
void run_file(char *filename) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", filename);  /* bounds-safe sprintf */
    /* PATCHED: replaced system() with execve - no shell injection */
    {
        char *argv[] = {"sh", "-c", cmd, NULL};
        /* TODO: replace with direct execve call without shell */
        /* execve("/bin/sh", argv, NULL); */
        (void)argv;  /* remove this line when implementing execve */
    }
}

/* ── Vuln 5: Use-after-free ── */
void process_data() {
    char *ptr = (char *)malloc(256);
    if (!ptr) return;
    strncpy(ptr, "sensitive_data", sizeof(ptr) - 1);
    ptr[sizeof(ptr) - 1] = '\0';  /* bounds-safe copy */
    free(ptr);
    ptr = NULL;  /* prevent use-after-free */
    printf("Data: %s\n", ptr);    /* CWE-416: use after free */
}

/* ── Vuln 6: Double free ── */
void cleanup(int *data) {
    free(data);
    if (data != NULL) {
        free(data);
        data = NULL;  /* prevent double-free */
    }
}

/* ── Vuln 7: sprintf overflow ── */
void build_query(char *user_input) {
    char query[64];
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE name='%s'", user_input);  /* bounds-safe sprintf */
    printf("Query: %s\n", query); /* CWE-120: query overflows buf */
}

/* ── Vuln 8: memcpy without sizeof ── */
void copy_payload(char *src, int len) {
    char dest[128];
    /* bounds check before memcpy */
    if ((len) <= sizeof(dest)) {
        memcpy(dest, src, len);
    } else {
        memcpy(dest, src, sizeof(dest));  /* clamped to dest size */
    }
    printf("Copied.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    greet_user(argv[1]);
    show_message(argv[1]);
    run_file(argv[1]);
    read_input();

    int *data = (int *)malloc(sizeof(int) * 10);
    cleanup(data);

    build_query(argv[1]);
    copy_payload(argv[1], 999);   /* passing unchecked length */

    return 0;
}

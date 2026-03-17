#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Vuln 1: Buffer overflow via strcpy ── */
void greet_user(char *name) {
    char buffer[64];
    strcpy(buffer, name);          /* CWE-120: no bounds check */
    printf("Hello, %s!\n", buffer);
}

/* ── Vuln 2: gets() — always overflows ── */
void read_input() {
    char buf[128];
    printf("Enter your name: ");
    gets(buf);                     /* CWE-120: removed from C11 */
    printf("Got: %s\n", buf);
}

/* ── Vuln 3: Format string injection ── */
void show_message(char *msg) {
    printf(msg);                   /* CWE-134: user controls format */
}

/* ── Vuln 4: Command injection via system() ── */
void run_file(char *filename) {
    char cmd[256];
    sprintf(cmd, "cat %s", filename);
    system(cmd);                   /* CWE-78: shell injection */
}

/* ── Vuln 5: Use-after-free ── */
void process_data() {
    char *ptr = (char *)malloc(256);
    if (!ptr) return;
    strcpy(ptr, "sensitive_data");
    free(ptr);
    printf("Data: %s\n", ptr);    /* CWE-416: use after free */
}

/* ── Vuln 6: Double free ── */
void cleanup(int *data) {
    free(data);
    free(data);                    /* CWE-415: double free */
}

/* ── Vuln 7: sprintf overflow ── */
void build_query(char *user_input) {
    char query[64];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", user_input);
    printf("Query: %s\n", query); /* CWE-120: query overflows buf */
}

/* ── Vuln 8: memcpy without sizeof ── */
void copy_payload(char *src, int len) {
    char dest[128];
    memcpy(dest, src, len);        /* CWE-125: len not bounded */
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
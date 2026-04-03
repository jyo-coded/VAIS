#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function_1(char *input) {
    char buffer[50];
    // Buffer Overflow
    strcpy(buffer, input);
    strcat(buffer, input);
}

void vulnerable_function_2() {
    char buffer[100];
    // gets unbounded input
    gets(buffer);
}

void vulnerable_function_3(char *user_data) {
    char buffer[20];
    // sprintf without bounds
    sprintf(buffer, "User: %s", user_data);
}

void vulnerable_function_4() {
    char buf[10];
    // scanf unbounded string
    scanf("%s", buf);
}

void vulnerable_function_5(char *user_fmt) {
    // format string injection
    printf(user_fmt);
    sprintf(user_fmt);
}

void vulnerable_function_6(char *cmd) {
    // command injection
    system(cmd);
    popen(cmd, "r");
}

void vulnerable_function_7() {
    char *ptr = malloc(100);
    free(ptr);
    // Use-After-Free & Double-Free
    strcpy(ptr, "bad data");
    free(ptr);
}

void vulnerable_function_8(char *src, int len) {
    char dest[50];
    // memcpy without bounds derived from dest
    memcpy(dest, src, len);
}

int main(int argc, char **argv) {
    if(argc > 1) {
        vulnerable_function_1(argv[1]);
        vulnerable_function_3(argv[1]);
        vulnerable_function_5(argv[1]);
        vulnerable_function_6(argv[1]);
        vulnerable_function_8(argv[1], 100);
    }
    vulnerable_function_2();
    vulnerable_function_4();
    vulnerable_function_7();
    return 0;
}
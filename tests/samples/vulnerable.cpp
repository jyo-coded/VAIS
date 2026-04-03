#include <iostream>
#include <cstring>
#include <cstdlib>

using namespace std;

void bad_buffer_copy(const char* input) {
    char buffer[50];
    // Unchecked buffer copy (CWE-120)
    strcpy(buffer, input);
    cout << "Buffer contains: " << buffer << endl;
}

void bad_system_call(const char* user_input) {
    char cmd[100];
    snprintf(cmd, sizeof(cmd), "ls -l %s", user_input);
    // Command Injection (CWE-78)
    system(cmd);
}

void bad_gets_call() {
    char buf[100];
    cout << "Enter text: ";
    // Dangerous function (CWE-242)
    gets(buf);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        bad_buffer_copy(argv[1]);
        bad_system_call(argv[1]);
    }
    
    bad_gets_call();
    
    // Test memory allocation tracking (CWE-416)
    char* ptr = new char[100];
    delete[] ptr;
    // Note: use after free logic checks `free()` not `delete` currently,
    // so this is just to ensure it parses without crashing.
    
    return 0;
}

#include <iostream>
#include <string>

using namespace std;

void cpp_vuln_function_1() {
    int* ptr = new int[100];
    // Memory leak via raw new (no delete)
}

void cpp_vuln_function_2() {
    char* data = new char[50];
    delete[] data;
    // Use after delete
    data[0] = 'a';
}

void cpp_vuln_function_3(int* user_controlled_ptr) {
    // Null pointer dereference (uncaught)
    int val = *user_controlled_ptr;
}

void cpp_vuln_function_4() {
    // Fixed char array instead of string
    char buffer[256];
}

void cpp_vuln_function_5(const char* user_fmt) {
    // printf with non-literal format string
    printf(user_fmt);
    fprintf(stdout, user_fmt);
}

void cpp_vuln_function_6(const string& user_input) {
    // system() with string concat (command injection)
    string cmd = "ls " + user_input;
    system(cmd.c_str());
}

void cpp_vuln_function_7(int count) {
    // int overflow in array size
    int* data = new int[count * sizeof(int)];
}

void cpp_vuln_function_8() {
    // ofstream incorrect permissions
    ofstream ofs("secret.txt");
    ofs << "secret";
}

int main() {
    cpp_vuln_function_1();
    cpp_vuln_function_2();
    cpp_vuln_function_4();
    cpp_vuln_function_6("test");
    cpp_vuln_function_7(999999);
    cpp_vuln_function_8();
    return 0;
}

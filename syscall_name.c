#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 256

// Function to retrieve the system call name based on the system call number
const char* syscall_name(int syscall_number) {
    static char buffer[MAX_LINE_LENGTH];
    char line[MAX_LINE_LENGTH];

    // Open the file that contains the system call names
    FILE *f = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "r"); // Use the appropriate path for your system

    if (f == NULL) {
        perror("Error opening syscall table file");
        exit(EXIT_FAILURE);
    }

    // Search for the line containing the system call number
    while (fgets(line, sizeof(line), f)) {
        int number;
        char name[MAX_LINE_LENGTH];

        if (sscanf(line, "#define __NR_%s %d", name, &number) == 2) {
            if (number == syscall_number) {
                fclose(f);
                snprintf(buffer, sizeof(buffer), "%s", name);
                return buffer;
            }
        }
    }

    fclose(f);
    return NULL;
}

int main() {
    int syscall_number = 1; // Replace with the system call number you want to look up
    const char *name = syscall_name(syscall_number);

    if (name != NULL) {
        printf("System call number %d corresponds to '%s'\n", syscall_number, name);
    } else {
        printf("System call number %d not found in the table\n", syscall_number);
    }

    return 0;
}

#include <stdio.h>

int main() {
    //print pid
    printf("PID: %d\n", getpid());
    while (1) {
        FILE *file = fopen("test_file.txt", "w");
        if (file == NULL) {
            printf("File not found\n");
            return 1;
        }
        //print file descriptor
        printf("File descriptor: %d\n", fileno(file));
        //write to file
        fprintf(file, "Hello, World!\n");
        //close file
        fclose(file);
        //sleep for 5 second
        sleep(5);
    }
    return 0;
}

/*
 * Example vulnerable C program with Buffer Overflow
 * For demonstration and security research purposes only
 */

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    
    // VULNERABILITY: No bounds checking - classic buffer overflow
    strcpy(buffer, input);
    
    printf("Data copied: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    
    return 0;
}

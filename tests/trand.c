#include <stdio.h>
#include <openssl/rand.h>

int main(void)
{
    unsigned char buffer[16];

    // Generate random bytes (first call)
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed on the first call.\n");
        return 1;
    }

    printf("Random bytes (call 1): ");
    for (size_t i = 0; i < sizeof(buffer); i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // Generate random bytes (second call)
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed on the second call.\n");
        return 1;
    }

    printf("Random bytes (call 2): ");
    for (size_t i = 0; i < sizeof(buffer); i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    return 0;
}

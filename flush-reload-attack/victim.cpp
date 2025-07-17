#include <stdint.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <map>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <bitset>

// ******** FDP demo ********
// encryption key for AES
unsigned char key[] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0xff, 0x00, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
};
// ***********************************

AES_KEY key_struct;

unsigned char ciphertext[16];

void run_encryption_service(int sockfd)
{
    unsigned char buff[16];
    int n;
    // infinite loop for victim
    for (;;) {
        bzero(buff, 16);
        bzero(ciphertext, 16);

        // ******** FDP demo ********
        // read the message from attacker and copy it in buffer
        read(sockfd, buff, 16);
        // Encrypt the 16B plaintext received
        AES_encrypt(buff, ciphertext, &key_struct);
        // and send ciphertext to attacker
        write(sockfd, ciphertext, 16);
        // ***********************************
    }
}

int main()
{
    int sockfd, connfd;
    unsigned int len;
    struct sockaddr_in victim_addr, cli;

    printf("Key used for encryption:\n\n");
    for (int i = 0; i < 16; i++) {
        printf("0x%02x, ", key[i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    // AES key expansion for encryption
    AES_set_encrypt_key(key, 128, &key_struct);

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        // printf("socket creation failed...\n");
        exit(0);
    }
    // else
    //     printf("socket successfully created..\n");
    bzero(&victim_addr, sizeof(victim_addr));

    // assign IP, PORT
    victim_addr.sin_family = AF_INET;
    victim_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    victim_addr.sin_port = htons(10000);

    // binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr*)&victim_addr, sizeof(victim_addr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    // else
    //     printf("socket successfully binded..\n");

    // now victim is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    // else
    //     printf("victim listening..\n");
    len = sizeof(cli);

    // accept the data packet from attacker and verification
    connfd = accept(sockfd, (struct sockaddr*)&cli, &len);
    if (connfd < 0) {
        printf("victim acccept failed...\n");
        exit(0);
    }
    // else
    //     printf("victim acccept the attacker...\n");

    run_encryption_service(connfd);
    close(sockfd);
}

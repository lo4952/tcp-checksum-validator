#define __USE_BSD
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>

// Pseudoheader
typedef struct pseudoheader {
    u_int32_t src;
    u_int32_t dst;
    u_char zero;
    u_char protocol;
    u_int16_t tcplen;
} tcp_phdr_t;

// Isolate the provided tcp header checksum



// Manually calculate tcp header checksum



// Compare the calculated and given checksums



int main(int argc, char* argv[]) {
    char err_buf[PCAP_ERRBUF_SIZE];
    memset(err_buf, 0, PCAP_ERRBUF_SIZE);


    if (argc != 2) {
        printf("Usage: tcp_checksum <interface>\n");
        exit(1);
    }
    
    // Open network device
    pcap_t* capture = NULL;
    capture = pcap_open_live(argv[1], 2048, 1, 512, err_buf);
    if (capture == NULL) {
        fprintf(stderr, "Err: pcap_open_live(): %s\n", err_buf);
        exit(1);
    }
    
    // Capture from network device
    int count = 0;
    struct ip* iphdr = NULL;
    struct tcphdr* tcphdr = NULL;
    struct pcap_pkthdr pkthdr;
    const unsigned char* packet = NULL;
    while(1) {
        if ((packet = pcap_next(capture, &pkthdr)) == NULL) {
            fprintf(stderr, "Err: pcap_next(): %s\n", err_buf);
            exit(1);
        }
        iphdr = (struct ip*)(packet + 14);
        tcphdr = (struct tcphdr*)(packet + 14 + 20);
        printf("Recieved packet no. %d\n", ++count);
    }
    
    return 1;
}

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
} __attribute__((packed)); 

// Manually calculate tcp header checksum
// Specific implementation from https://www.winpcap.org/pipermail/winpcap-users/2007-July/001984.html
unsigned short CheckSum(u_short *buffer, int size)
{
    unsigned long cksum = 0;
    while(size >1) {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if(size) {
        cksum += *(unsigned char*)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (u_short)(~cksum);
}


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
        fprintf(stderr, "Err: pcap_open_live() failed: %s\n", err_buf);
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
            fprintf(stderr, "Err: pcap_next() failed: %s\n", err_buf);
            exit(1);
        }
        iphdr = (struct ip*)(packet + 14);
        tcphdr = (struct tcphdr*)(packet + 14 + 20);

        // Isolate provided tcp header checksum
        printf("Given checksum: %d\n", tcphdr->check);

        // Create pseudo header and checksum it
        struct pseudoheader pseudo;
        pseudo.src = iphdr->ip_src.s_addr;
        pseudo.dst = iphdr->ip_dst.s_addr;
        pseudo.zero = 0;
        pseudo.protocol = 6;
        unsigned ip_hdr_len = iphdr->ip_hl * 4;
        unsigned ip_packet_len = ntohs(iphdr->ip_len);
        pseudo.tcplen = htons(ip_packet_len - ip_hdr_len);

        // Checksum pseudoheader
        u_short csum = CheckSum((unsigned short*)&pseudo, (unsigned)sizeof(pseudo));

        printf("Calculated checksum: %d\n", csum);

        // Compare checksums
        printf("%s checksum!\n", (tcphdr->check == csum) ? "Valid" : "Invalid");
    }
    
    return 1;
}

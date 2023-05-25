#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Before run this code, execute the command below 
// $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
// c 입장에서 SYNACK을 받으면 kernel이 reset packet을 보냄 -> connection 확립X 위의 코드 실행시, reset packet을 보내지X

// pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
};

#define DATAGRAM_LEN 4096

// TODO: Implement checksum function which returns unsigned short value 
unsigned short checksum(unsigned short *buffer, unsigned short size)
{
        unsigned short word16;
        unsigned short sum = 0;
        unsigned short i;

        for( i = 0; i < size; i += 2 )
        {
                word16 = ((buffer[i] << 8 ) & 0xFF00) + ((buffer[i+1] << 8 ) & 0xFF00);
                sum += word16;
        }

        while( sum >> 16 )
        {
                sum = (sum & 0xFFFF) + ( sum >> 16 );
        }

        sum = ~sum;

        return sum;


}

void create_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
        printf("iph->saddr: %d\n", src->sin_addr.s_addr);
	printf("iph->daddr: %d\n", dst->sin_addr.s_addr);
	printf("src port: %d\n", src->sin_port);
	printf("dst port: %d\n", dst->sin_port);
	// datagram to represent the packet
        char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

        // required structs for IP and TCP header
        struct iphdr *iph = (struct iphdr*)datagram;
        struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
        struct pseudo_header psh;

        // TODO: IP header configuration
        //ihl : 4bits header length
    iph->ihl = 5;
    iph->version = 4;
        //type of service ; 8bits
    iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(rand() % 65535); // id of this packet
        iph->frag_off = 0;
        // ttl 적당한 값 써주기
    iph->ttl = 60;
    // 프로토콜 ID ; 상위 프로토콜 = tcpsms 6
    iph->protocol = 6;
        iph->saddr = src->sin_addr.s_addr;
        iph->daddr = dst->sin_addr.s_addr;

        // TODO: TCP header configuration
        tcph->source = htons(src->sin_port);
        tcph->dest = htons(dst->sin_port);
        tcph->seq = htonl((long)rand() % 4294967295);
    tcph->ack_seq = 0; // SYN에서는 0을 사용하면 됨 -> 시작하는 것이닌깐
        // doff Data Offset: tcp 헤더 사이즈를 32bits word 단위로 나타냄
    tcph->doff = 5; // 4bytes 단위로 data unit이 들어가니깐 5 x 4하기에 5
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
        tcph->window = htons(5840); // window size
    tcph->urg_ptr = 0;

        // TCP pseudo header for checksum calculation
        psh.source_address = src->sin_addr.s_addr;
        psh.dest_address = dst->sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr); //pseudo_hdr + tcphdr

        // fill pseudo packet
        char* pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    // SYN or ACK 은 payload 신경 쓸 필요X
    tcph->check = checksum((unsigned short*)pseudogram, psize); // TODO: call checksum() with pseudogram
        iph->check = checksum((unsigned short*)datagram, iph->tot_len);
    //iph->check = checksum(datagram, sizeof(struct iphdr) + sizeof(struct tcphdr)); // TODO: call checksum() with datagram

        *out_packet = datagram;
        *out_packet_len = iph->tot_len;

        free(pseudogram);
}

void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
        // datagram to represent the packet
        char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

        // required structs for IP and TCP header
        struct iphdr *iph = (struct iphdr*)datagram;
        struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
        struct pseudo_header psh;

        // TODO: IP header configuration
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(rand() % 65535); // id of this packet
        iph->frag_off = 0;
        iph->ttl = 60;
        iph->protocol = 6;
        iph->saddr = src->sin_addr.s_addr;
        iph->daddr = dst->sin_addr.s_addr;

        // TODO: TCP header configuration
        tcph->source = htons(src->sin_port);
        tcph->dest = htons(dst->sin_port);
        tcph->seq = seq;
        tcph->ack_seq = ack_seq;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 0;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 1;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->urg_ptr = 0;

        // TODO: TCP pseudo header for checksum calculation
        psh.source_address = src->sin_addr.s_addr;
        psh.dest_address = dst->sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);

        // fill pseudo packet
        char* pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((unsigned short*)pseudogram, psize); // TODO: call checksum() with pseudogram
        iph->check = checksum((unsigned short*)datagram, iph->tot_len); // TODO: call checksum() with datagram 

        *out_packet = datagram;
        *out_packet_len = iph->tot_len;

        free(pseudogram);
}

void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack)
{
        // read sequence number
        uint32_t seq_num;
        memcpy(&seq_num, packet + 24, 4);

        // read acknowledgement number
        uint32_t ack_num;
        memcpy(&ack_num, packet + 28, 4);

        // convert network to host byte order
        *seq = ntohl(seq_num);
        *ack = ntohl(ack_num);

        printf("sequence number: %lu\n", (unsigned long)*seq);
        printf("acknowledgement number: %lu\n", (unsigned long)*seq);
}

int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst)
{
        unsigned short dst_port;
        int received;
        do
        {
                received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
                //printf("received: %d\n", received);
                if (received > 0)
                        break;
                memcpy(&dst_port, buffer + 22, sizeof(dst_port));
        } while (dst_port != dst->sin_port);
        printf("received bytes: %d\n", received);
        printf("destination port: %d\n", ntohs(dst->sin_port));
        return received;
}

int main(int argc, char *argv[])
{
        if (argc != 4)
        {
                printf("Usage: %s <Source IP> <Destination IP> <Destination Port>\n", argv[0]);
                return 1;
        }

        srand(time(NULL));

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); //raw socket 생성
        if (sock == -1)
        {
                perror("socket");
        exit(EXIT_FAILURE);
        }

        // Source IP
        struct sockaddr_in saddr;
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(rand() % 65535); // random client port
        if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
        {
                perror("Source IP configuration failed\n");
                exit(EXIT_FAILURE);
        }

        // Destination IP and Port 
        struct sockaddr_in daddr;
        daddr.sin_family = AF_INET;
        daddr.sin_port = htons(atoi(argv[3]));
        if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
        {
                perror("Destination IP and Port configuration failed");
                exit(EXIT_FAILURE);
        }

        // Tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) // raw socket 에 보내는 data는 IP header를 포함하고 있다
        {
                perror("setsockopt(IP_HDRINCL, 1)");
                exit(EXIT_FAILURE);
        }

        // Step 1. Send SYN
        char* packet;
        int packet_len;
        int sent;
        create_syn_packet(&saddr, &daddr, &packet, &packet_len);
        if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
        {
                perror("sendto()");
                exit(EXIT_FAILURE);
        }
        else
        {
                printf("Successfully sent %d bytes SYN!\n", sent);
        }

        // Step 2. Receive SYN-ACK
        char recvbuf[DATAGRAM_LEN];
        int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
        if (received <= 0)
        {
                perror("receive_from()");
                exit(EXIT_FAILURE);
        }
        else
        {
                printf("Successfully received %d bytes SYN-ACK!\n", received);
        }

        // Read sequence number to acknowledge in next packet
        uint32_t seq_num, ack_num;
        read_seq_and_ack(recvbuf, &seq_num, &ack_num);
        int new_seq_num = seq_num + 1;

        // Step 3. Send ACK
        // previous seq number is used as ack number and vica vera
        create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
        if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
        {
                perror("sendto()");
                exit(EXIT_FAILURE);
        }
        else
        {
                printf("Successfully sent %d bytes ACK!\n", sent);
        }

        close(sock);
        return 0;
}

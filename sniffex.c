#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl; /* version << 4 | header length >> 2 */
  u_char ip_tos; /* type of service */
  u_short ip_len; /* total length */
  u_short ip_id; /* identification */
  u_short ip_off; /* fragment offset field */
  #define IP_RF 0x8000 /* reserved fragment flag */
  #define IP_DF 0x4000 /* don't fragment flag */
  #define IP_MF 0x2000 /* more fragments flag */
  #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
  u_char ip_ttl; /* time to live */
  u_char ip_p; /* protocol */
  u_short ip_sum; /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)(((ip) -> ip_vhl) & 0x0f)
#define IP_V(ip)(((ip) -> ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq; /* sequence number */
  tcp_seq th_ack; /* acknowledgement number */
  u_char th_offx2; /* data offset, rsvd */
  #define TH_OFF(th)(((th) -> th_offx2 & 0xf0) >> 4)
  u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

struct sniff_udp {
  u_short sport; //source port
  u_short dport; //destination port
  u_short len; //datagram length
  u_short crc; //checksum
};

void got_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet);

void print_payload(const u_char * payload, int len);

void print_hex_ascii_line(const u_char * payload, int len, int offset);

void print_app_usage(void);

/*
 * print help text
 */
void print_app_usage(void) {

  printf("Usage: %s [interface]\n", APP_NAME);
  printf("\n");
  printf("Options:\n");
  printf("    interface    Listen on <interface> for packets.\n");
  printf("\n");

  return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char * payload, int len, int offset) {

  int i;
  int gap;
  const u_char * ch;

  /* offset */
  printf("%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++) {
    printf("%02x ", * ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf(" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++) {
    if (isprint( * ch))
      printf("%c", * ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char * payload, int len) {

  int len_rem = len;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char * ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for (;;) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char * args,
  const struct pcap_pkthdr * header,
    const u_char * packet) {

  static int count = 1; /* packet counter */

  /* declare pointers to packet headers */
  const struct sniff_ethernet * ethernet; /* The ethernet header [1] */
  const struct sniff_ip * ip; /* The IP header */
  const struct sniff_tcp * tcp; /* The TCP header */
  const char * payload; /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nPacket number %d:\n", count);
  count++;

  /* define ethernet header */
  ethernet = (struct sniff_ethernet * )(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip * )(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  /* print source and destination IP addresses */
  printf("       From: %s\n", inet_ntoa(ip -> ip_src));
  printf("         To: %s\n", inet_ntoa(ip -> ip_dst));

  /* determine protocol */
  switch (ip -> ip_p) {
  case IPPROTO_TCP:
    printf("   Protocol: TCP\n");
    break;
  case IPPROTO_UDP:
    printf("   Protocol: UDP\n");
    break;
  case IPPROTO_ICMP:
    printf("   Protocol: ICMP\n");
    return;
  case IPPROTO_IP:
    printf("   Protocol: IP\n");
    return;
  default:
    printf("   Protocol: unknown\n");
    return;
  }

  /* define/compute tcp header offset */
  if (ip -> ip_p == IPPROTO_UDP) {
    struct sniff_udp * udp_header;
    udp_header = (struct udp_hdr * )(packet + SIZE_ETHERNET + size_ip);
    printf("**\t\tSource Port : %u\n**\t\tDestination Port : %u\n", udp_header -> sport, udp_header -> dport);
    printf("**\t\tUDP Datagram Length : %u\n", udp_header -> len / 256);
  } else {

    tcp = (struct sniff_tcp * )(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
      printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return;
    }

    printf("   Src port: %d\n", ntohs(tcp -> th_sport));
    printf("   Dst port: %d\n", ntohs(tcp -> th_dport));

    printf("Packet capture length: %d\n", header -> caplen);
    printf("Packet total length %d\n", header -> len);

    printf("Sequence number: %u\n", tcp -> th_seq);
    printf("Acknowledgement number: %u\n", tcp -> th_ack);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char * )(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip -> ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
      printf("   Payload (%d bytes):\n", size_payload);
      print_payload(payload, size_payload);
    }
  }

  return;
}

void Parse() {
  FILE * f;
  f = fopen("data.txt", "r");
  char c = fgetc(f);
  char buf[256];
  char File_Size[256];
  char Data_Speed[256];
  char Bit_Speed[256];
  char Packet_Rate[256];
  int count = 0;
  int i = 0, j = 0;
  float size, speed, Mbps, prate;
  char Temporary[256];
  while (fgets(buf, sizeof(buf), f) != NULL) {
    if (count == 11) {
      i = 0, j = 0;
      Temporary[0] = '\0';
      strcpy(Temporary, buf);
      while (Temporary[i++] != ':');
      while (Temporary[i] == ' ') i++;
      while (Temporary[i] != ' ') {
        Data_Speed[j] = Temporary[i];
        i++, j++;
      }
      speed = atof(Data_Speed);
      printf("**\t\tAVERAGE SPEED(MBps)   : %4.2fMBps\n", speed);
      count++;
    } else if (count == 12) {
      i = 0, j = 0;
      Temporary[0] = '\0';
      strcpy(Temporary, buf);
      while (Temporary[i++] != ':');
      while (Temporary[i] == ' ') i++;
      while (Temporary[i] != ' ') {
        Bit_Speed[j] = Temporary[i];
        i++, j++;
      }
      Mbps = atof(Bit_Speed);
      printf("**\t\tAVERAGE SPEED(Mbps)   : %4.2f Mbps\n", Mbps);
      count++;
    } else if (count == 13) {
      i = 0, j = 0;
      Temporary[0] = '\0';
      strcpy(Temporary, buf);
      while (Temporary[i++] != ':');
      while (Temporary[i] == ' ') i++;

      while (Temporary[i] != ' ') {
        File_Size[j] = Temporary[i];
        i++, j++;
      }
      size = atof(File_Size);
      printf("**\t\tAVERAGE PACKET SIZE   : %4.2f bytes\n", size);
      count++;
    } else if (count == 14) {
      i = 0, j = 0;
      Temporary[0] = '\0';
      strcpy(Temporary, buf);
      while (Temporary[i] != ':')
        i++;
      i++;
      while (Temporary[i] == ' ')
        i++;

      while (Temporary[i] != ' ') {
        Packet_Rate[j] = Temporary[i];
        j++;
        i++;
      }
      prate = atof(Packet_Rate);
      printf("**\t\tAVERAGE PACKET RATE/s : %4.2f kpackets/s\n", prate);
      count++;
    } else {
      count++;
    }
  }
  printf("**\t\tAVERAGE RTT           : %f seconds\n", (size * 2) / (speed * 1048576));
}

int main(int argc, char ** argv) {

  char * dev = NULL; /* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE]; /* error Temporary */
  pcap_t * handle; /* packet capture handle */

  char filter_exp[] = "ip"; /* filter expression [3] */
  struct bpf_program fp; /* compiled filter program (expression) */
  bpf_u_int32 mask = 0; /* subnet mask */
  bpf_u_int32 net = 0; /* ip */
  int num_packets = 0; /* number of packets to capture */

  char FileName[100];
  printf("Enter file name: ");
  scanf("%s", FileName);
  handle = pcap_open_offline(FileName, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device\n");
    exit(EXIT_FAILURE);
  }
  
  printf("Enter number of packets to be sniffed (Enter 0 for all): ");
  scanf("%d", &num_packets);
  if(num_packets == 0)
    printf("Number of packets: All\n");
  else
    printf("Number of packets: %d\n", num_packets);

  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Not an Ethernet\n");
    exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  if (pcap_compile(handle, & fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, & fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  pcap_loop(handle, num_packets, got_packet, NULL);

  /* cleanup */
  pcap_freecode( & fp);
  pcap_close(handle);

  char command[100];
  sprintf(command, "capinfos %s > ./data.txt", FileName);
  system(command);
  puts("-----------------------------------");
  Parse();
  puts("-----------------------------------");

  printf("\nCapture complete.\n");

  return 0;
}

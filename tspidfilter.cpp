/*************************************************************
    TS PID FILTER

    Quick and dirty tool to hide PIDs in a TS stream by changing
    the PID number to NULL (8191) without changing overall
    TS structure and any synchronization (such as SFN MIP)

    Principle of operation:
    - receive UDP datagram
    - check if raw UDP or RTP encapsulted
    - count number of TS packets in payload
    - for each TS packet in the payload
        - if PID is in the list of PIDs to hide
            - replace PID value by 8191 (NULL)
    - send patched (or not) datagram to another multicast socket
      (keep structure, RTP header if any,...)
*************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <time.h>

//=======================================
// Define multicast in and out

char* InputMCast = (char*)"239.1.2.3";
unsigned short InputPort = 5000;
char* InputInterface = NULL;

char* OutputMCast = (char*)"239.3.2.1";
unsigned short OutputPort = 5000;
char* OutputInterface = NULL;


// List of PID to detect and patch to NULL
unsigned short Pid2Patch[100] = { 0 };
int Pid2PatchCount = 0;

//=======================================
// Global variables and definitions

int fd_in = -1;
int fd_out = -1;
struct sockaddr_in addr_out;

#define MSGBUFSIZE 1400
unsigned char msgbuf[MSGBUFSIZE];

#define TS_LEN      188
#define TS_SYNC     0x47
#define PID_NULL    8191

typedef struct {
    unsigned char sync : 8;
    unsigned char pidH : 5;
    unsigned char tp : 1;
    unsigned char pusi : 1;
    unsigned char tei : 1;
    unsigned char pidL : 8;
    unsigned char cc : 4;
    unsigned char afc : 2;
    unsigned char tfc : 2;
} TSHDR_t;

//=======================================
// Transport stream tools and patcher

unsigned int get_pid(TSHDR_t* p)
{
    return p->pidL | (p->pidH << 8);
}

int check_sync(TSHDR_t* p)
{
    return TS_SYNC == p->sync;
}

void set_pid(TSHDR_t* p, unsigned int new_pid)
{
    new_pid &= 0x1FFF;
    p->pidL = new_pid & 0xFF;
    p->pidH = new_pid >> 8;
}

int patch_ts(unsigned char* ts_buf, int n_ts)
{
    int n_patched = 0;

    for (; n_ts > 0; n_ts--, ts_buf += TS_LEN)
    {
        if (!check_sync((TSHDR_t*)ts_buf))
        {
            printf("sync error !\n");
            continue;
        }

        for (int i = 0; i < Pid2PatchCount; i++)
        {
            if (get_pid((TSHDR_t*)ts_buf) == Pid2Patch[i])
            {
                set_pid((TSHDR_t*)ts_buf, PID_NULL);
                ++n_patched;
                //break;
            }
        }
    }

    return n_patched;
}

//=======================================
// create input and output sockets

int create_sockets(void)
{
    struct sockaddr_in addr_in;

    // create what looks like an ordinary UDP socket
    //
    fd_in = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_in < 0) {
        perror("socket");
        return 1;
    }

    // allow multiple sockets to use the same PORT number
    //
    unsigned int yes = 1;
    if (
        setsockopt(
            fd_in, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)
        ) < 0
        ) {
        perror("Reusing ADDR failed");
        return 1;
    }

    // set up receive address
    //
    memset(&addr_in, 0, sizeof(addr_in));
    addr_in.sin_family = AF_INET;
    if (InputInterface == NULL)
        addr_in.sin_addr.s_addr = htonl(INADDR_ANY); // differs from sender
    else
#ifdef _WIN32
        inet_pton(AF_INET, InputInterface, &addr_in.sin_addr.s_addr);
#else
        addr_in.sin_addr.s_addr = inet_addr(InputInterface);
#endif
    addr_in.sin_port = htons(InputPort);

    // bind to receive address
    //
    if (bind(fd_in, (struct sockaddr*) & addr_in, sizeof(addr_in)) < 0) {
        perror("bind");
        return 1;
    }

    // use setsockopt() to request that the kernel join a multicast group
    //
    struct ip_mreq mreq;
#ifdef _WIN32
    inet_pton(AF_INET, InputMCast, &mreq.imr_multiaddr.s_addr);
#else
    mreq.imr_multiaddr.s_addr = inet_addr(InputMCast);
#endif
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (
        setsockopt(
            fd_in, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)
        ) < 0
        ) {
        perror("setsockopt");
        return 1;
    }

    //---------------------------
    // Output socket

    // create what looks like an ordinary UDP socket
    //
    fd_out = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_out < 0) {
        perror("socket");
        return 1;
    }

    // set up interface address
    //
    if (OutputInterface != NULL)
    {
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
    #ifdef _WIN32
            inet_pton(AF_INET, InputInterface, &addr_in.sin_addr.s_addr);
    #else
            addr_in.sin_addr.s_addr = inet_addr(InputInterface);
    #endif
        addr_in.sin_port = htons(InputPort);

        // bind to receive address
        //
        if (bind(fd_out, (struct sockaddr*) & addr_in, sizeof(addr_in)) < 0) {
            perror("bind");
            return 1;
        }
    }

    // set up destination address
    //
    memset(&addr_out, 0, sizeof(addr_out));
    addr_out.sin_family = AF_INET;
    inet_pton(AF_INET, OutputMCast, &addr_out.sin_addr.s_addr);
    addr_out.sin_port = htons(OutputPort);

    return 0;
}

void parse_args(int argc, char** argv)
{
    if (argc < 5)
    {
        printf("usage  : %s mcast_in port_in mcast_out port_out pid1 [pid2 ...]\n", argv[0]);
        printf("example: %s 239.1.2.3 5000 239.3.2.1 6000 100 110 120\n", argv[0]);
        exit(1);
    }

    int arg = 1;
    InputMCast = argv[arg++]; 
    InputPort = atoi(argv[arg++]);
    OutputMCast = argv[arg++];
    OutputPort = atoi(argv[arg++]);
    for (; arg < argc; )
        Pid2Patch[Pid2PatchCount++] = atoi(argv[arg++]);
}


int main( int argc, char **argv)
{
    printf("tspidfilter\n");

    parse_args(argc, argv);

    printf("Input : %s : %u from %s\n", InputMCast, InputPort, InputInterface ? InputInterface : "any");
    printf("Output: %s : %u from %s\n", OutputMCast, OutputPort, OutputInterface ? OutputInterface : "any");
    printf("PIDs  : ");
    for (int i = 0; i < Pid2PatchCount; )
    {
        printf("%u", Pid2Patch[i++]);
        if (i < Pid2PatchCount)
            printf(", ");
    }
    printf("\n");

    if (sizeof(TSHDR_t) != 4)
    {
        printf("TSHDR_t size error : %ld\n", sizeof(TSHDR_t));
        exit(1);
    }

#ifdef _WIN32
    //
    // Initialize Windows Socket API with given VERSION.
    //
    WSADATA wsaData;
    if (WSAStartup(0x0101, &wsaData)) {
        perror("WSAStartup");
        return 1;
    }
#endif

    if (create_sockets())
    {
        printf("error create_sockets\n");
        return 1;
    }

    //------------------------
    // processing loop
    unsigned long long int count_udp = 0;
    unsigned long long int count_ts = 0;
    unsigned long long int count_patched = 0;
    struct sockaddr_in addr_in;
    time_t last_display = 0;

    while (1) {
        //------------------------
        // get UDP in

        int addrlen = sizeof(addr_in);
        int n_in = recvfrom(
            fd_in,
            (char*)msgbuf,
            MSGBUFSIZE,
            0,
            (struct sockaddr*) & addr_in,
            (socklen_t*)&addrlen
        );
        if (n_in < 0) {
            perror("recvfrom");
            continue;
        }

        //------------------------
        // compute length, number of TS packets, offset (UDP or RTP)

        int n_ts = n_in / TS_LEN;
        int ts_length = n_ts * TS_LEN;
        int ts_offset = n_in - ts_length;

        //------------------------
        // Patch PIDs

        count_patched += patch_ts(msgbuf + ts_offset, n_ts);
        ++count_udp;
        count_ts += n_ts;

        time_t now;
        if (time(&now) - last_display >= 5)
        {
            printf("%8I64u UDP (%d bytes), %8I64u TS, %8I64u patched\r", count_udp, n_in, count_ts, count_patched);
            last_display = now;
        }

        //------------------------
        // send patched UDP

        int n_out = sendto(
            fd_out,
            (char*)msgbuf,
            n_in,
            0,
            (struct sockaddr*) & addr_out,
            sizeof(addr_out)
        );
        if (n_out < 0 || n_out != n_in) {
            perror("sendto");
            continue;
        }
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

//struct icmp
#include <sys/types.h>

//struct timeval
#include <sys/time.h>

int pid = 0;
pthread_t recv_id = 0;
pthread_t send_id = 0;

struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;
int alive = 1;

#define BUFFER 1024 * 128
#define PACKET_SEND_MAX_NUM 64
#define SOCKET_ERROR -1

struct protoent* protocol = NULL;
int icmp_sock = 0;
int size = BUFFER;
struct sockaddr_in servaddr;

int send_count;
int recv_count;

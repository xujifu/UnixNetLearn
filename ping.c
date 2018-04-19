#include "base.h"

char rspace[3 + 4 * 9 + 1];

unsigned short checksum(unsigned short *header, int length)
{
    int len = length;
    unsigned int sum = 0;
    while(len > 1)
    {
        sum += *header ++;
        len -= 2;
    }
    if(len == 1)
    {
        sum += *(unsigned char *)header;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

void icmp_pack(struct icmp* icmphdr, int seq, int length)
{
    int i = 0;
    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = seq;
    icmphdr->icmp_id = pid & 0xffff;
    struct timeval *tval;
//    for(i = 0; i < length; i ++)
//    {
//        icmphdr->icmp_data[i] = i;
//    }
    tval = (struct timeval *)icmphdr->icmp_data;
    gettimeofday(tval, NULL);
    icmphdr->icmp_cksum = checksum((unsigned short*)icmphdr, length);
}

struct timeval cal_time_offset(struct timeval *begin, struct timeval end)
{
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin->tv_sec;
    ans.tv_usec = end.tv_usec - begin->tv_usec;
    if(ans.tv_usec < 0)
    {
        ans.tv_sec --;
        ans.tv_usec += 1000000;
    }
    return ans;
}

char * pr_addr(unsigned int addr)
{
    struct hostent *hp;
    static char buf[4096];
    if(!(hp = gethostbyaddr((char *)&addr, 4, AF_INET)))
    {
        snprintf(buf, sizeof(buf), "%s", inet_ntoa(*(struct in_addr *)&addr));
    }else{
        snprintf(buf, sizeof(buf), "%s (%s)", hp->h_name, inet_ntoa(*(struct in_addr *)&addr));
    }
    
    return buf;
}

void pr_options(unsigned char *opts, int hlen)
{
    unsigned char *optptr;
    optptr = opts;
    if(*opts == IPOPT_RR)
    {
        unsigned char len = *++opts;
        unsigned char pointer = *++opts;
        unsigned int address;
        for(;pointer > 0;pointer -= 4)
        {
            memcpy(&address, opts, 4);
            if(address == 0)
                printf("\t0.0.0.0\n");
            else
                printf("\t%s\n", pr_addr(address));
            opts += 4;
        }
    }
}

int icmp_unpack(char *buf, int len)
{
    int iphdr_len;
    struct timeval (*begin_time), recv_time, offset_time;
    int rtt;
    int optlen = 0;
    
    struct ip* ip_hdr = (struct ip *)buf;
    iphdr_len = ip_hdr->ip_hl * 4;
//    路由
//    optlen = iphdr_len - 20;//sizeof(struct iphdr);
//    printf("%d %d\n", iphdr_len, optlen);
//    unsigned char opts[40];
//    memset(opts, 0, 40);
//    memcpy(opts, buf + 20, optlen);
//    pr_options(opts, optlen);
    struct icmp *icmp = (struct icmp *)(buf + iphdr_len);
    len -= iphdr_len;
    if(len < 8)
    {
        printf("Invalid icmp packet. Its length is less than 8\n");
        return -1;
    }
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff)))
    {
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM))
        {
            printf("icmp packet seq is out of range!\n");
            return -1;
        }
        begin_time = (struct timeval *)icmp->icmp_data;
        gettimeofday(&recv_time, NULL);
        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec * 1000 + offset_time.tv_usec / 1000;
        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
               len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);
    }
    else
    {
        printf("Invalid ICMP packet! Its id is not matched!\n");
        return -1;
    }
    return 0;
}

void ping_send()
{
    char send_buf[128];
    memset(send_buf, 0, sizeof(send_buf));
    gettimeofday(&start_time, NULL);
    while(alive)
    {
        int size = 0;
        icmp_pack((struct icmp*)send_buf, send_count, 64);
        size = sendto(icmp_sock, send_buf, 64, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
        send_count ++;
        if(size < 0)
        {
            printf("send icmp package fail !\n");
            continue;
        }
        sleep(1);
    }
}

void ping_recv()
{
    struct timeval tv;
    tv.tv_usec = 200;
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[512];
    memset(recv_buf, 0, sizeof(recv_buf));
    while(alive)
    {
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(icmp_sock, &read_fd);
        ret = select(icmp_sock + 1, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                printf("fail to select!\n");
                break;
            case 0:
                break;
            default:
            {
                int size = recv(icmp_sock, recv_buf, sizeof(recv_buf), 0);
                if(size < 0)
                {
                    printf("recv data fail!\n");
                    continue;
                }
                ret = icmp_unpack(recv_buf, size);
                if(ret == -1)
                {
                    continue;
                }
                recv_count++;
            }
                break;
        }
    }
}

void ping_stats_show()
{
    long time = time_interval.tv_sec*1000+time_interval.tv_usec/1000;
    /*注意除数不能为零，这里send_count有可能为零，所以运行时提示错误*/
    printf("%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n",
           send_count, recv_count, (send_count-recv_count)*100/send_count, '%', time);
    
}

void icmp_sigint(int signo)
{
    alive = 0;
    gettimeofday(&end_time, NULL);
    time_interval = cal_time_offset(&start_time, end_time);
}

int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("Usage:ping <IPaddress>\n");
        return -1;
    }
    if((icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        printf("Fail to create raw socket!\n");
        return -1;
    }
    pid = getpid();
    
//    memset(rspace, 0, sizeof(rspace));
//    rspace[0] = IPOPT_NOP;
//    rspace[1 + IPOPT_OPTVAL] = IPOPT_RR;
//    rspace[1 + IPOPT_OLEN] = sizeof(rspace) - 1;
//    rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
//    setsockopt(icmp_sock, IPPROTO_IP, IP_OPTIONS, &rspace, sizeof(rspace));
    
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int));
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if((servaddr.sin_addr.s_addr=inet_addr(argv[1])) == INADDR_NONE)
    {
        struct hostent *host;
        host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            printf("Fail to getHostByName!\n");
            return -1;
        }
        servaddr.sin_addr = *((struct in_addr *)host->h_addr);
        //这里为什么缺省是56没有找到
        printf("PING %s(%s) : 56 bytes of data.\n", host->h_name, inet_ntoa(servaddr.sin_addr));
    }
    alive = 1;
    signal(SIGINT, icmp_sigint);
    int i = 0;
//    for(i = 0; i < 10; i ++)
//    {
//        ping_send();
//        ping_recv();
//    }
    if(pthread_create(&send_id, NULL, (void *)ping_send, NULL))
    {
        printf("Fail to create ping send thread!\n");
        return -1;
    }
    if(pthread_create(&recv_id, NULL, (void *)ping_recv, NULL))
    {
        printf("Fail to create ping recv thread!\n");
        return -1;
    }

    pthread_join(send_id, NULL);
    pthread_join(recv_id, NULL);
    
    ping_stats_show();

    close(icmp_sock);
    return 0;
}

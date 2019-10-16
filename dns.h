#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define DEFAULT_DNS_SERVER "202.96.128.86"

#define TIMER_CYCLE_DNS 0

#define BUF_SIZE 65536
#define DNS_TIMEOUT 3

#pragma pack(1)
struct dns_hdr
{
    uint16_t id;    /* Identifier */
    uint16_t flags; /* Query/Response Flag */

    uint16_t question_count;   /* Question Count */
    uint16_t answer_count;     /* Answer Record Count */
    uint16_t authority_count;  /* Authority Record Count */
    uint16_t additional_count; /* Additional Record Count */
};

struct question_hdr
{
    uint16_t question_type;
    uint16_t question_class;
};

struct answer_hdr
{
    uint16_t answer_name;
    uint16_t answer_type;
    uint16_t answer_class;
    uint32_t answer_ttl;
    uint16_t answer_data_len;
    uint8_t answer_txt_len;
    uint8_t answer_txt_data;
};

void timer_dns();
#include "dns.h"
#include "info.h"
#include "log.h"

int dns_server_valid = 0;

char *get_dns_server()
{
	static char buf[256];
	char cmd[] = "cat /tmp/resolv.conf.auto | sed -n '2p' | cut -d ' ' -f 2 | tr -d \\n";
	FILE *fp = popen(cmd, "r");
	if (fp == NULL || fgets(buf, sizeof(buf), fp) == NULL)
	{
		strcpy(buf, DEFAULT_DNS_SERVER);
		dns_server_valid = 0;

		return (char *)&buf;
	}

	pclose(fp);

	dns_server_valid = 1;

	logger(DEBUG, "get dns server : %s\n", buf);

	return (char *)&buf;
}

int dns_encode(char *buf, const char *domain)
{
	struct dns_hdr *dns_hdr = (struct dns_hdr *)buf;
	dns_hdr->id = htons(0x5d3f);
	dns_hdr->flags = htons(0x0100);
	dns_hdr->question_count = htons(1);
	dns_hdr->answer_count = htons(0);
	dns_hdr->authority_count = htons(0);
	dns_hdr->additional_count = htons(0);

	uint8_t *p = (uint8_t *)(buf + sizeof(struct dns_hdr));
	int i, j;
	for (i = 0, j = 0; i <= strlen(domain); i++)
	{ //encode domain to buf
		if (domain[i] == '.' || domain[i] == '\0')
		{
			p[j] = i - j;
			j = i + 1;
			if (domain[i] == '\0')
				p[j++] = '\0';
		}
		else
		{
			p[i + 1] = domain[i];
		}
	}

	struct question_hdr *question = (struct question_hdr *)(p + j);
	question->question_type = htons(16);
	question->question_class = htons(1);

	return sizeof(struct dns_hdr) + j + sizeof(struct question_hdr);
}

int dns_decode(char *buf, int offset)
{
	struct answer_hdr *answer = (struct answer_hdr *)(buf + offset);

	//check data len
	if (answer->answer_data_len == htons(answer->answer_txt_len + 1))
	{
		uint8_t len = answer->answer_txt_len;
		memmove(buf, &answer->answer_txt_data, len);
		buf[len] = '\0';
		return len;
	}
	else
	{
		return -1;
	}
}

int create_dns_socket()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		return -1;
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	addr.sin_addr.s_addr = inet_addr(get_dns_server());
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		close(fd);
		perror("connect");
		return -1;
	}

	return fd;
}

int dns_req(int fd, char *buf)
{
	int ret;
	char domain[256];

	process_req(domain);

	ret = dns_encode(buf, domain);
	ret = send(fd, buf, ret, 0);
	if (ret < 0)
	{
		perror("send");
		return -1;
	}

	return ret;
}

int dns_res(char *buf)
{
	process_res(buf);

	return 0;
}

int dns_req_timeout(int fd)
{
	static struct timeval timer, now;
	//timer
	gettimeofday(&now, NULL); // refresh timer
	if (now.tv_sec - timer.tv_sec > DNS_TIMEOUT)
	{
		gettimeofday(&timer, NULL); // refresh timmer
		return 1;
	}
	return 0;
}

void trigger_dns()
{
	int ret;
	char buf[BUF_SIZE];
	static int fd = 0, offset = 0;

	if (fd <= 0)
	{ //init socket
		fd = create_dns_socket();
	}
	if (fd <= 0)
		return;

	//async
	ret = recv(fd, buf, BUF_SIZE, MSG_DONTWAIT);
	if (ret < 0 && errno != EAGAIN)
	{					   //socket error
		perror("recv");	//print error msg
		close(fd), fd = 0; //reset socket
		return;
	}
	else if (ret < 0 && errno == EAGAIN)
	{ //recv packet timeout
		if (dns_req_timeout(fd) > 0)
		{
			if (dns_server_valid == 0)
			{
				close(fd), fd = 0; //reset socket
			}
			else
			{
				offset = dns_req(fd, buf);
			}
		}
		return;
	}
	else if (ret > 0)
	{
		ret = dns_decode(buf, offset);
		if (ret > 0)
			dns_res(buf); //handle dns responsed
		return;
	}
}

void timer_dns()
{
	static struct timeval timer, now;

	gettimeofday(&now, NULL); // refresh timer
	if (now.tv_sec - timer.tv_sec > TIMER_CYCLE_DNS)
	{
		trigger_dns();
		gettimeofday(&timer, NULL); // refresh timmer
	}
}
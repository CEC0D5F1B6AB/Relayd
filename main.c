#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "log.h"
#include "relay.h"
#include "dns.h"

void stop(int signo)
{
    stop_flag = 1;
    logger(DEBUG, "\nStop\n");
}

int start(char *lan, char *wan)
{
    while (!stop_flag)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            return -1;
        }
        else if (pid == 0)
        { //This is the child process
            return start_relay(lan, wan);
        }
        else
        { //This is the main process
            int status;
            wait(&status);
            if (WEXITSTATUS(status) == 0)
                break;
            sleep(3); //3 sec
            logger(DEBUG, "Restart\n");
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

    // while (1)
    // {
    //     timer_dns();
    //     //system("sleep 1");
    // }
    // return 0;

    int ch, background = 0;
    char *lan = NULL, *wan = NULL;

    while ((ch = getopt(argc, argv, "l:w:bd")) != -1)
    {
        switch (ch)
        {
        case 'l':
            lan = optarg;
            break;
        case 'w':
            wan = optarg;
            break;
        case 'b':
            background = 1;
            break;
        case 'd':
            log_level = 1;
            break;
        default:
            //show_usage(argv[0]);
            return -1;
        }
    }

    if (!lan || !wan)
    {
        printf("Args error\n");
        return -1;
    }

    signal(SIGINT, stop);
    signal(SIGQUIT, stop);
    signal(SIGTERM, stop);
    signal(SIGSTOP, stop);

    pid_t fpid = 0;
    if (background)
    {
        fpid = fork();
    }

    //check no error
    if (fpid < 0)
    {
        perror("fork");
        return -1;
    }
    else if (fpid == 0)
    {
        return start(lan, wan); // start relay
    }
}

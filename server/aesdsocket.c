#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include "queue.h"
#include "../aesd-char-driver/aesd_ioctl.h"

#define USE_AESD_CHAR_DEVICE (1)

#define PORT "9000"
#define MAXBUFLEN (256 * 1024U)
#define BACKLOG 10 // Number of pending connections queue will hold.

// Path and pointer to the log file.
#if USE_AESD_CHAR_DEVICE
#define LOG_PATH "/dev/aesdchar"
#else
#define LOG_PATH "/var/tmp/aesdsocketdata"
#endif

// Global boolean for SIGINT and SIGTERM
bool caughtsig = false;

// Global mutex to be used for writing to the log file
pthread_mutex_t log_lock;

// Structs for the single linked lists
typedef struct thread_args_s thread_args_t;
typedef struct slist_data_s slist_data_t;

struct thread_args_s
{
	int complete;
	int rv;
	int listenfd;
	struct sockaddr laddr;
};

struct slist_data_s
{
	pthread_t thread;
	thread_args_t threadargs;
	SLIST_ENTRY(slist_data_s)
	entries;
};


// Function to handle SIGTERM and SIGINT
static void signal_handler(int signum)
{
	caughtsig = true;
}


// This function will be used for the timestamp creation thread
#if !USE_AESD_CHAR_DEVICE
static void time_thread(union sigval sv)
{
	char outstr[256];
	time_t t;
	struct tm *time_info;
	FILE *fp;
	t = time(NULL);

	// Get the local time
	if ((time_info = localtime(&t)) == NULL)
	{
		printf("ERROR: Get Local Time\n");
		syslog(LOG_ERR, "ERROR: Get Local Time");
	}

	// Format the timestamp using RFC 2822 compliant strftime
	if (strftime(outstr, sizeof(outstr), "%a, %d %b %Y %T %z", time_info) == 0)
	{
		printf("ERROR: Format TimeStamp to RFC 2822\n");
		syslog(LOG_ERR, "ERROR: Format TimeStamp to RFC 2822");
	}

	// Get the mutex to lock the LOG FILE for writing.
	if (pthread_mutex_lock(&log_lock) != 0)
	{
		printf("ERROR: Mutex Lock to Write Timestamp\n");
		syslog(LOG_ERR, "ERROR: Mutex Lock to Write Timestamp");
	}

	// Write timestampt to LOG FILE using global pointer.
	if ((fp = fopen(LOG_PATH, "a")) == NULL)
	{
		perror("ERROR: Unable to Open Log Path");
	}
	else
	{
		fprintf(fp, "timestamp:%s\n", outstr);
		if (fclose(fp) == EOF)
		{
			perror("ERROR: Unable to Close Log File");
		}
	}
	// Release the mutex lock.
	if (pthread_mutex_unlock(&log_lock) != 0)
	{
		printf("ERROR: Mutex Unlock After Timestamp Write to Log File\n");
		syslog(LOG_ERR, "ERROR: Mutex Unlock After Timestamp Write to Log File");
	}
}
#endif


int parse_cmd(char *buf, size_t buflen, struct aesd_seekto *seekto)
{
	char *cmd, *arg1, *arg2;

	cmd = malloc(buflen);
	if (!cmd)
	{
		return -1;
	}
	memcpy(cmd, buf, buflen);

	cmd[strcspn(cmd, "\n")] = '\0';
	cmd = strtok(cmd, ":");
	if (!cmd)
	{
		free(cmd);
		return -1;
	}

	// Compare the strings. A false match will return a non-zero value
	if (strcmp(cmd, "AESDCHAR_IOCSEEKTO"))
	{
		free(cmd);
		return -1;
	}

	arg1 = strtok(NULL, ",");
	arg2 = strtok(NULL, "");
	if (arg1 == NULL || arg2 == NULL)
	{
		free(cmd);
		return -1;
	}

	seekto->write_cmd = strtoul(arg1, NULL, 10);
	if (seekto->write_cmd == 0 && errno == EINVAL)
	{
		free(cmd);
		return -1;
	}
	seekto->write_cmd_offset = strtoul(arg2, NULL, 10);
	if (seekto->write_cmd_offset == 0 && errno == EINVAL)
	{
		free(cmd);
		return -1;
	}

	free(cmd);
	return 0;
}

// This function will be used for the data receive and send thread
static void *serve_thread(void *arg)
{
	char ipstr[INET_ADDRSTRLEN];
	char *recvbuf, *sendbuf;
	int rv;
	size_t sendbuflen;
	thread_args_t *targs = arg;
	FILE *fp;
	int fd;
	struct aesd_seekto seekto;

	targs->rv = 0;
	// Convert binary format address of client to characters and store in the address buffer
	if (inet_ntop(targs->laddr.sa_family, targs->laddr.sa_data, ipstr, sizeof(ipstr)) == NULL)
	{
		printf("ERROR: INET NTOP\n");
        syslog(LOG_ERR, "ERROR: INET NTOP");
		targs->rv = -1;
		return &targs->rv;
	}
	syslog(LOG_INFO, "Accepted connection from %s\n", ipstr);

	while (1)
	{
		// Allocate memory for the send and receive buffers
		if ((recvbuf = malloc(MAXBUFLEN)) == NULL)
		{
			printf("ERROR: Malloc for Receive Buffer\n");
	        syslog(LOG_ERR, "ERROR: Malloc for Receive Buffer");
			targs->rv = -1;
			break;
		}
		if ((sendbuf = malloc(MAXBUFLEN)) == NULL)
		{
			printf("ERROR: Malloc for Send Buffer\n");
	        syslog(LOG_ERR, "ERROR: Malloc for Send Buffer");
			targs->rv = -1;
			break;
		}

		// Receive data on listen port
		rv = recv(targs->listenfd, recvbuf, MAXBUFLEN, MSG_DONTWAIT);
		if (rv > 0)
		{
			recvbuf[rv] = '\0';

			// Obtain mutex lock to write data to log file
			if (pthread_mutex_lock(&log_lock) != 0)
			{
				printf("ERROR: Mutex Lock to Write Data From Receive Buffer to Log File\n");
				syslog(LOG_ERR, "ERROR: Mutex Lock to Write Data From Receive Buffer to Log File");
			}

			if (parse_cmd(recvbuf, rv, &seekto) == 0)
			{

				// Open the log path to read
				if ((fp = fopen(LOG_PATH, "r")) == NULL)
				{
					printf("ERROR: Unable to Open Log Path\n");
					syslog(LOG_ERR, "ERROR: Unable to Open Log Path");
				}
				else
				{
					// The IOCTL function requires that the file pointer be converted to an int
					fd = fileno(fp);
					if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) == 0)
					{
						while((sendbuflen = fread(sendbuf, sizeof(char), MAXBUFLEN, fp)) > 0) 
						{
							if (send(targs->listenfd, sendbuf, sendbuflen, 0) == -1)
							{
								printf("ERROR: Data Send\n");
								syslog(LOG_ERR, "ERROR: Data Send");
							}
						}
						if (fclose(fp) == EOF)
						{
							printf("ERROR: Unable to Close Log File\n");
							syslog(LOG_ERR, "ERROR: Unable to Close Log File");
						}
					}
					else
					{
						printf("ERROR: IOCTL\n");
						syslog(LOG_ERR, "ERROR: IOCTL");
					}
				}
			}

			else
			{
				// Append to log
				if ((fp = fopen(LOG_PATH, "a")) == NULL)
				{
					printf("ERROR: Unable to Open Log Path\n");
					syslog(LOG_ERR, "ERROR: Unable to Open Log Path");
				}
				else
				{
					if (fprintf(fp, "%s", recvbuf) < 0)
					{
						printf("ERROR: fprintf\n");
						syslog(LOG_ERR, "ERROR: fprintf");
					}
					if (fclose(fp) == EOF)
					{
						printf("ERROR: fclose\n");
						syslog(LOG_ERR, "ERROR: fclose");
					}
				}

				// Read log
				if ((fp = fopen(LOG_PATH, "r")) == NULL)
				{
					printf("ERROR: Unable to Open Log Path\n");
					syslog(LOG_ERR, "ERROR: Unable to Open Log Path");
				}
				else
				{
					while ((sendbuflen = fread(sendbuf, sizeof(char), MAXBUFLEN, fp)) > 0)
					{
						if (send(targs->listenfd, sendbuf, sendbuflen, 0) == -1)
						{
							printf("ERROR: Data Send\n");
							syslog(LOG_ERR, "ERROR: Data Send");
						}
					}
					if (fclose(fp) == EOF)
					{
						printf("ERROR: fclose\n");
						syslog(LOG_ERR, "ERROR: fclose");
					}
				}
			}

			// Release the mutex lock of the log file
			if (pthread_mutex_unlock(&log_lock) != 0)
			{
				printf("ERROR: Mutex Unlock\n");
				syslog(LOG_ERR, "ERROR: Mutex Unlock");
			}
		}

		// Failed to receive
		else if (rv == -1)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				targs->rv = -1;
				printf("ERROR: Data Receive\n");
				syslog(LOG_ERR, "ERROR: Data Receive");
			}
		}
		else
		{
			targs->rv = -1;
		}

		// Free both send and receive buffers.
		free(sendbuf);
		free(recvbuf);

		if (targs->rv < 0)
		{
			break;
		}
	}

	// Close the listen port
	if (close(targs->listenfd) == -1)
	{
		printf("ERROR: Listen Socket Close\n");
		syslog(LOG_ERR, "ERROR: Listen Socket Close");
		targs->rv = -1;
	}

	syslog(LOG_INFO, "SUCCESS: Closed Connection From %s\n", ipstr);

	return &targs->rv;
}


int main(int argc, char *argv[])
{
	int sockfd, listenfd, rv, status, res_bind;
	struct addrinfo hints, *servinfo;
	struct sigaction sigact;
	struct sockaddr laddr;
	socklen_t addr_size;
	pthread_t thread;
	pid_t pid;
	slist_data_t *datap = NULL;
	slist_data_t *tdatap = NULL;

#if !USE_AESD_CHAR_DEVICE
	timer_t timer;
	struct sigevent sev;
	struct itimerspec its;
#endif

	// Make a socket:
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        printf("ERROR: Open Socket\n");
        syslog(LOG_ERR, "ERROR: Open Socket");
        return -1;
    }
    printf("SUCCESS: Socket Opened\n");

	// Make sure the struct is empty
	memset(&hints, 0, sizeof(struct addrinfo));

	// Fill in the IP automatically
	hints.ai_flags = AI_PASSIVE;

	// Set for IPv4
	hints.ai_family = AF_INET;

	// TCP stream sockets
	hints.ai_socktype = SOCK_STREAM;


	if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        printf("ERROR: Get Address Info\n");
		syslog(LOG_ERR, "ERROR: Get Address Info");
        return -1;
    }
    printf("SUCCESS: Get Address\n");

	// Bind to socket
	res_bind = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
    if(res_bind != 0){
        printf("ERROR: Bind to Socket\n");
        syslog(LOG_ERR, "ERROR: Bind to Socket: %d", errno);
        freeaddrinfo(servinfo); // free the linked list
        return -1;
    }
	printf("SUCCESS: Bind to Socket\n"); 

	// Free the linked list.
	freeaddrinfo(servinfo);


	// Refer to LSP p174
    // Fork to a daemon if -d command line argument present
    if (argc > 1) { // Note this line is necessary or test will fail
        if (strcmp(argv[1], "-d") == 0) {
			pid = fork ();
        	if (pid == -1){
            	return -1;
        	}
        	else if (pid > 0){
            	return 0;
        	}
		}
	}

	// Start listen
	//if (listen(sockfd, 16) == -1)
	if (listen(sockfd, BACKLOG) == -1)
	{
		printf("ERROR: Listen on Socket\n");
        syslog(LOG_ERR, "ERROR: Listen on Socket");
		return -1;
	}

	// Register signal_handler as our signal handler
	memset(&sigact, 0, sizeof(struct sigaction));
	sigact.sa_handler = signal_handler;
	
	// Configure for SIGINT
	if (sigaction(SIGINT, &sigact, NULL) == -1)
	{
		printf ("ERROR: Cannot Handle SIGINT\n");
		syslog(LOG_ERR, "ERROR: Cannot Handle SIGINT");
		return -1;
	}
	
	// Configure for SIGTERM
	if (sigaction(SIGTERM, &sigact, NULL) == -1)
	{
		printf ("ERROR: Cannot Handle SIGTERM\n");
		syslog(LOG_ERR, "ERROR: Cannot Handle SIGTERM");
		return -1;
	}

	// Initialize pthread mutex
	if (pthread_mutex_init(&log_lock, NULL) != 0)
	{
		printf ("ERROR: Initialize Mutex\n");
		syslog(LOG_ERR, "ERROR: Initialize Mutex");
		return -1;
	}

	// Configure timer thread
#if !USE_AESD_CHAR_DEVICE
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = &time_thread;

	// Enable monotonic clock
	if (timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0)
	{
		printf ("ERROR: Create Monotonic Clock\n");
		syslog(LOG_ERR, "ERROR: Create Monotonic Clock");
		return -1;
	}

	// Configure timer settings
	its.it_value.tv_sec = 10;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 10;
	its.it_interval.tv_nsec = 0;
	if (timer_settime(timer, 0, &its, NULL) != 0)
	{
		printf ("ERROR: Set Timer\n");
		syslog(LOG_ERR, "ERROR: Set Timer");
		return -1;
	}
#endif

	// Struct for singular linked list and initialize
	SLIST_HEAD(slisthead, slist_data_s) head;
	SLIST_INIT(&head);

	while (!caughtsig)
	{
		// Now accept an incoming connection:
        addr_size = sizeof(struct sockaddr);
		if ((listenfd = accept(sockfd, &laddr, &addr_size)) == -1)
		{
			printf ("ERROR: Accept Incoming Connection\n");
			syslog(LOG_ERR, "ERROR: Accept Incoming Connection");
			continue;
		}

		// Remove any previous threads
		SLIST_FOREACH_SAFE(datap, &head, entries, tdatap)
		{
			if (datap->threadargs.complete)
			{
				if ((pthread_join(datap->thread, NULL)) != 0)
				{
					printf ("ERROR: Thread Join\n");
					syslog(LOG_ERR, "ERROR: Thread Join\n");
				}
				SLIST_REMOVE(&head, datap, slist_data_s, entries);
				free(datap);
			}
		}

		// Begin to create the threads
		datap = malloc(sizeof(slist_data_t));
		datap->threadargs.complete = false;
		datap->threadargs.listenfd = listenfd;
		datap->threadargs.laddr = laddr;
		if ((pthread_create(&thread, NULL, serve_thread, &datap->threadargs)) != 0)
		{
			
			printf ("ERROR: Create Thread\n");
			syslog(LOG_ERR, "ERROR: Create Thread\n");
			free(datap);
			continue;
		}
		datap->thread = thread;
		SLIST_INSERT_HEAD(&head, datap, entries);
	}

	// Cleanup before exiting application
	syslog(LOG_INFO, "Exiting application gracefully.");
	printf("SUCCESS: Begin Cleanup\n");
	rv = 0;

	// Use linked list to join threads
	while (!SLIST_EMPTY(&head))
	{
		datap = SLIST_FIRST(&head);
		if (pthread_join(datap->thread, NULL) != 0)
		{
			printf ("ERROR: Cleanup Thread Join\n");
			syslog(LOG_ERR, "ERROR: Cleanup Thread Join\n");
			rv = -1;
		}
		SLIST_REMOVE_HEAD(&head, entries);
		free(datap);
	}

	// Delete timer
#if !USE_AESD_CHAR_DEVICE
	if (timer_delete(timer) != 0)
	{
		printf ("ERROR: Cleanup Timer Delete\n");
		syslog(LOG_ERR, "ERROR: Cleanup Timer Delete\n");
		rv = -1;
	}
#endif

	// Destroy the mutex
	if (pthread_mutex_destroy(&log_lock) != 0)
	{
		printf ("ERROR: Cleanup Mutex Destroy\n");
		syslog(LOG_ERR, "ERROR: Cleanup Mutex Destroy\n");
		rv = -1;
	}

	// Shutdown down read/write to the socket
	if (shutdown(sockfd, SHUT_RDWR) == -1)
	{
		printf ("ERROR: Cleanup Socket Read/Write Shutdown\n");
		syslog(LOG_ERR, "ERROR: Cleanup Socket Read/Write Shutdown\n");
		rv = -1;
	}

	// Close the socket
	if (close(sockfd) == -1)
	{
		printf ("ERROR: Cleanup Socket Close\n");
		syslog(LOG_ERR, "ERROR: Cleanup Socket Close\n");
		rv = -1;
	}
	
	// Cleanup the log file
#if !USE_AESD_CHAR_DEVICE
	if (access(LOG_PATH, F_OK) == 0)
	{
		if (remove(LOG_PATH) == -1)
		{
			printf ("ERROR: Cleanup Close Log File\n");
			syslog(LOG_ERR, "ERROR: Cleanup Log File\n");
			rv = -1;
		}
	}
#endif

	return rv;
}

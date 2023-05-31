/*
 ** server.c -- a stream socket server demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/queue.h>
#include <assert.h>




#define PORT "9000"  // the port users will be connecting to

#define BACKLOG 10   // how many pending connections queue will hold
#define BUFF_SIZE (1024) 
#define OUTPUTFILE "/var/tmp/aesdsocketdata"
ssize_t read_size = 0;
ssize_t write_size = 0;
FILE *fp;
bool line_flag = false;


int daemon_flag;
static bool sigint = false;
static bool sigterm = false;
static bool sigchld = false;
//static int running = 1;
static int thread_count = 0;
static int thread_remove = 0;
int output_file_descriptor = 0;
int connection_socket_descriptor = 0;
int server_socket_descriptor = 0;


typedef struct 
{
	pthread_t           thread_id;
	pthread_mutex_t     *mutex_lock;
	int                 incoming_fd;
	bool                thread_complete_success;
} thread_data;


struct elm
{
	thread_data t_data;
	TAILQ_ENTRY(elm) elm_index; 
};



void close_socket(int sd) {
	if (sd && close(sd) < 0) {
		syslog(LOG_WARNING, "Failed to close incoming socket, error %d", errno);
	}
}



void sync_and_close_output_file(int file_descriptor) {
	if (file_descriptor && fsync(file_descriptor) < 0) {
		syslog(LOG_WARNING, "Failed to flush output file, error %d", errno);
	}
	if (file_descriptor && close(file_descriptor) < 0) {
		syslog(LOG_WARNING, "Failed to close output file, error %d", errno);
	}
}


void terminate(int termination_reason) {
	sync_and_close_output_file(output_file_descriptor);
	close_socket(connection_socket_descriptor);
	close_socket(server_socket_descriptor);
	if (remove(OUTPUTFILE) < 0) {
		syslog(LOG_ERR, "Failed to remove the file at %s upon termination, error: %s",OUTPUTFILE, strerror(errno));
		exit(EXIT_FAILURE);
	}
	exit(termination_reason);
}







#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */

#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */






void sigchld_handler(int s)
{
	int ret = -1;

	switch (s)
	{




		case SIGCHLD:
			sigchld = true;
			break;

		case SIGINT:
			sigint = true;



			ret = remove(OUTPUTFILE);
			if (ret != 0) {
				handle_error_en(ret, "Failed: To remove aesdsocketdata file");
			}
			fprintf(stderr, "Removed file successfully\n");



			exit(1);	




			break;

		case SIGTERM:
			sigterm = true;






			ret = remove(OUTPUTFILE);
			if (ret != 0) {
				handle_error_en(ret, "Failed: To remove aesdsocketdata file");
			}
			fprintf(stderr, "Removed file successfully\n");



			exit(1);	

			break;

		default:
			break;
	}





}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}



int write_to_file(char *string) 
{
	FILE       *fd;
	size_t      bytes_wrote = 0;
	int         str_len = 0;

	printf("String recived: %s -> writing to file %s\n", string, OUTPUTFILE);


	fd = fopen(OUTPUTFILE, "a+");
	if (fd == NULL) {
		fprintf(stderr, "Failed: to open file (%s)\n", strerror(errno));
		return 1;
	}

	str_len = strlen(string);
	bytes_wrote = fwrite(string, sizeof(char), str_len, fd);

	if ((int)bytes_wrote < str_len) {
		fprintf(stderr, "Failed: to write to file (%s)\n", strerror(errno));
		return 1;
	}
	fclose(fd);

	return 0;
}

char *read_from_file(void) 
{
	FILE       *fd;
	char       *buffer              = NULL;
	size_t      bytes_read          = 0;
	long        file_size           = 0;
	int         ret                 = 0;

	fd = fopen(OUTPUTFILE, "r");
	if (fd == NULL) {
		fprintf(stderr, "Failed: to open file (%s)\n", strerror(errno));
		exit(0);
	}

	ret = fseek(fd, 0, SEEK_END);
	if (ret == -1) {
		fprintf(stderr, "Failed: to seek file (%s)\n", strerror(errno));
		exit(0);
	}

	file_size = ftell(fd);
	if (file_size == -1) {
		fprintf(stderr, "Failed: to get file size (%s)\n", strerror(errno));
		exit(0);
	}

	ret = fseek(fd, 0, SEEK_SET);
	if (ret == -1) {
		fprintf(stderr, "Failed: to seek file (%s)\n", strerror(errno));
		exit(0);
	}

	buffer = malloc(file_size + sizeof(char)); // why +1 -> (https://stackoverflow.com/a/12230807)
	if (buffer == NULL) {
		fprintf(stderr, "Failed: to malloc buffer (%s)\n", strerror(errno));
		exit(0);
	}

	bytes_read = fread(buffer, sizeof(char), file_size, fd);
	if ((long)bytes_read < file_size) {
		fprintf(stderr, "Failed: to read from file (%s)\n", strerror(errno));
		exit(0);
	}
	fclose(fd);

	buffer[bytes_read - 1] = '\n';
	buffer[bytes_read] = '\0';

	return buffer;
}



void *data_process(void *data)
{
	struct elm *e = (struct elm *)data;
	char buf[BUFF_SIZE] = {0};
	ssize_t num_bytes = 0;
	void *str_read = NULL;
	int ret = -1;

	num_bytes = recv(e->t_data.incoming_fd, buf, BUFF_SIZE-1, 0);
	if (num_bytes <= 0) {
		syslog(LOG_ERR, "Failed: To recive stream from socket (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (buf[num_bytes - 1] == '\n') {
		pthread_mutex_lock(e->t_data.mutex_lock);
		ret = write_to_file(buf);
		pthread_mutex_unlock(e->t_data.mutex_lock);
		if (ret == 0)
			memset(buf, 0, num_bytes);
	}

	else if (((num_bytes % (BUFF_SIZE-1)) == 0) && (buf[num_bytes-1] != '\n')) {
		fprintf(stderr, "writing stream in blocks of [%d]\n", BUFF_SIZE);
		while (buf[num_bytes-1] != '\n')
		{    
			pthread_mutex_lock(e->t_data.mutex_lock);
			ret = write_to_file(buf);
			pthread_mutex_unlock(e->t_data.mutex_lock);
			if (ret == 0) {
				memset(buf, 0, num_bytes);
				num_bytes = recv(e->t_data.incoming_fd, buf, BUFF_SIZE-1, 0);
				if (num_bytes <= 0) {
					syslog(LOG_ERR, "Failed: To recive stream from socket (%s)\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
		pthread_mutex_lock(e->t_data.mutex_lock);
		ret = write_to_file(buf);
		pthread_mutex_unlock(e->t_data.mutex_lock);
		if (ret == 0)
			memset(buf, 0, BUFF_SIZE);
	}

	else {
		fprintf(stderr, "Size dosent match..!\n");
		exit(EXIT_FAILURE);
	}

	str_read = read_from_file();
	if (str_read != NULL) {
		// printf(YELLOW "%s -> String read from file..\n" RESET, (char *)str_read);
		num_bytes = send(e->t_data.incoming_fd, str_read, strlen((char *)str_read), 0);
		if (num_bytes == -1) {
			syslog(LOG_ERR, "Failed: To recive stream from socket (%s)\n", strerror(errno));
			fprintf(stderr, "Failed: To send stream to socket (%s)\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		// fprintf(stderr, "Closed connection from [%s:%s]\n", ipver, ipstr);
		// syslog(LOG_INFO, "Closed connection from [%s:%s]\n", ipver, ipstr);
	}
	free(str_read);
	close(e->t_data.incoming_fd);
	e->t_data.thread_complete_success = true;
	printf("Finished process\n");

	return NULL;
}
















int main(int argc, char **argv)
{





	/* Setting up syslog facility */
	openlog("Logs", LOG_PID, LOG_USER);
	syslog(LOG_INFO, "Start logging for assignment 5 (aesdsocket-server)");

	/* Opens a stream socket bound to port 9000, 
	 * failing and returning -1 if any of the socket connection steps fail. 
	 */
	int                            opt                      = 0;
	//int                            getaddr_fd               = 0;
	//int                            listen_socket            = 0;
	bool                           start_daemeon            = false;
	int                            ret                      = 0;
	pthread_mutex_t                mutex;


	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd

	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	//	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	/* Options handler for starting dameon */
	while ((opt = getopt(argc, argv, "d")) != -1) {
		switch (opt) {
			case 'd':
				start_daemeon = true;
				break;
			default: /* '?' */
				start_daemeon = false;
				fprintf(stderr, "Usage: %s -d [To run as daemon]\n", argv[0]);
				return -1;
		}
	}







	setlogmask (LOG_UPTO (LOG_NOTICE));

	openlog ("exampleprog", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_DEBUG, LOG_LOCAL1 | LOG_ERR );



	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
					sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}




	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}





	/* Signal handler */
	struct sigaction sa = { 
		.sa_handler = sigchld_handler, 
		.sa_flags = SA_NODEFER | SA_RESETHAND 
	};
	sigemptyset(&sa.sa_mask);





	//	sa.sa_handler = sigchld_handler; // reap all dead processes
	//	sigemptyset(&sa.sa_mask);
	//	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
	else if (sigaction(SIGINT, &sa, NULL) == -1) {
		syslog(LOG_ERR, "Error (%s)\n", strerror(errno));
		exit(1);
	}
	else if (sigaction(SIGTERM, &sa, NULL) == -1) {
		syslog(LOG_ERR, "Error (%s)\n", strerror(errno));
		exit(1);
	}	





	if (sigchld) {

		// waitpid() might overwrite errno, so we save and restore it:
		int saved_errno = errno;

		while(waitpid(-1, NULL, WNOHANG) > 0);

		errno = saved_errno;


	}



	if (start_daemeon) {




		/* Here is where we need to check if we should be running as a daemon */
		pid_t sid = 0;
		pid_t process_id = fork();


		if (process_id < 0) {
			syslog(LOG_ERR, "Program was requested to run as daemon, but fork() call failed, error: %s", strerror(errno));
			terminate(EXIT_FAILURE);
		}
		else if (process_id > 0) {
			/* this code branch is for the parent process, where we need to exit */
			syslog(LOG_NOTICE, "Spun daemon process with PID %d", process_id);
			exit(EXIT_SUCCESS);
		}
		else {
			/*mask(0);*/
			/* close stdin, stdout & stderr */
			if (close(0) < 0) {
				syslog(LOG_ERR, "Failed to close stdin on daemon process, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}
			if (close(1) < 0) {
				syslog(LOG_ERR, "Failed to close stdout on daemon process, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}
			if (close(2) < 0) {
				syslog(LOG_ERR, "Failed to close stderr on daemon process, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}

			int null_fd = open("/dev/null", O_APPEND|O_RDWR);
			if (null_fd < 0) {
				syslog(LOG_ERR, "Could not open /dev/null to redirect std streams, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}
			if (dup2(null_fd, 0) < 0) {
				syslog(LOG_ERR, "Failed while trying to redirect stdin, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}
			if (dup2(null_fd, 1) < 0) {
				syslog(LOG_ERR, "Failed while trying to redirect stdout, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}
			if (dup2(null_fd, 2) < 0) {
				syslog(LOG_ERR, "Failed while trying to redirect stderr, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}

			/* set new session ID, no terminal, daemon will be the only process in this session */
			sid = setsid();
			if (sid < 0) {
				syslog(LOG_ERR, "Failed to set new session ID for the daemon, error: %s", strerror(errno));
				terminate(EXIT_FAILURE);
			}

int re;

re =			chdir("/");
printf("chdir %d",re);
		}







	}


	ret = pthread_mutex_init(&mutex, NULL);
	if(ret != 0) {
		handle_error_en(ret, "Mutex init failed..\n");
	}

	/* This macro creates the data type for the head of the queue
	*/
	TAILQ_HEAD(head_s, elm) head;

	/* Initialize the head before use */
	TAILQ_INIT(&head);

	struct elm *e;


	printf("server: waiting for connections...\n");





	do {  // main accept() loop









		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s, sizeof s);
		printf("server: got connection from %s\n", s);
		syslog (LOG_INFO, "Too few arguments");











		e = malloc(sizeof(struct elm));
		if (e == NULL) {
			fprintf(stderr, "Failed TAILQ malloc..\n");
			assert(true);
		}
		e->t_data.mutex_lock = &mutex;
		e->t_data.thread_complete_success = false;
		e->t_data.incoming_fd = new_fd;

		// Actually insert the node e into the queue at the end
		TAILQ_INSERT_TAIL(&head, e, elm_index);
		thread_count++;

		ret = pthread_create(&e->t_data.thread_id, NULL, data_process, (void *)e);
		if (ret != 0) {
			handle_error_en(ret, "Pthread create\n");
		}
		e = NULL;
		printf("### Started data process thread: [%d]\n", thread_count);



	}while (!(sigint) || !(sigterm));




	syslog(LOG_DEBUG, "Caught signal. Exiting\n");
	printf(RED "Caught signal. Exiting\n" RESET);

	// Join the queue
	TAILQ_FOREACH(e, &head, elm_index) {
		ret = pthread_join(e->t_data.thread_id, NULL);
		if (ret != 0) {
			handle_error_en(ret, "Failed: To join thread\n");
		}
	}

	// free the elements from the queue
	while (!TAILQ_EMPTY(&head))
	{
		e = TAILQ_FIRST(&head);
		TAILQ_REMOVE(&head, e, elm_index);
		thread_remove++;
		free(e);
		e = NULL;
		printf("Removed thread from list: [%d]\n", thread_remove);
	}

	if (thread_count != thread_remove) {
		printf("ALL ELMS IN THE LIST NOT REMOVED (pending:%d)\n", thread_count);
		assert(true);    
	}


	ret = remove(OUTPUTFILE);
	if (ret != 0) {
		handle_error_en(ret, "Failed: To remove aesdsocketdata file");
	}
	fprintf(stderr, "Removed file successfully\n");

	ret = pthread_mutex_destroy(&mutex);
	if (ret != 0) {
		handle_error_en(ret, "Mutex destroyed failed..\n");
	}
	// free(thread_sync);

	ret = close(sockfd);
	if (ret != 0) {
		handle_error_en(ret, "Failed to close socket FD..\n");
	}

	syslog(LOG_INFO, "Closing socket\n");
	closelog();

	printf(BOLDGREEN "aesdsocket program exited gracefully\n" RESET);

	return 0;














}


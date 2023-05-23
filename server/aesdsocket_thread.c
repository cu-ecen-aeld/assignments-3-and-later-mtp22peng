#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/queue.h>
#include <assert.h>

#define PORT "9000"
#define LOCALHOST "localhost"
#define BACKLOG 10
#define MAXDATASIZE 1024
#define OUTFILE "/tmp/var/aesdsocketdata"
#define TIMESTAMP_INTERVAL 10

#define handle_error_en(en, msg) \
               do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */

#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */

typedef struct 
{
    pthread_t           thread_id;
    pthread_mutex_t     *mutex_lock;
    int                 client_fd;
        
    bool                thread_complete_success;
} thread_data;


// The data type for the node
struct node
{
    thread_data t_data;
    TAILQ_ENTRY(node) nodes; 
};


static bool sigint = false;
static bool sigterm = false;
static int running = 1;
static int thread_count = 0;
static int thread_remove = 0;


void signal_handler(int signal_number)
{
    switch (signal_number)
    {
    case SIGINT:
        sigint = true;
        break;

    case SIGTERM:
        sigterm = true;
        break;
    
    default:
        break;
    }
}


void make_daemon()
{
    pid_t pid = fork();

    /* Fork to create child */
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If fork then let parent terminate */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* If parent terminate success then the child 
     * owns the session
     */
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Open the log file */
    openlog ("aesdsocket_daemon", LOG_PID, LOG_DAEMON);
}


char *read_from_file(void) 
{
    FILE       *File_fd;
    char       *buffer              = NULL;
    size_t      bytes_read          = 0;
    long        file_size           = 0;
    int         ret                 = 0;

    File_fd = fopen(OUTFILE, "r");
    if (File_fd == NULL) {
        fprintf(stderr, "Failed: to open file (%s)\n", strerror(errno));
        exit(0);
    }

    ret = fseek(File_fd, 0, SEEK_END);
    if (ret == -1) {
        fprintf(stderr, "Failed: to seek file (%s)\n", strerror(errno));
        exit(0);
    }

    file_size = ftell(File_fd);
    if (file_size == -1) {
        fprintf(stderr, "Failed: to get file size (%s)\n", strerror(errno));
        exit(0);
    }

    ret = fseek(File_fd, 0, SEEK_SET);
    if (ret == -1) {
        fprintf(stderr, "Failed: to seek file (%s)\n", strerror(errno));
        exit(0);
    }

    buffer = malloc(file_size + sizeof(char)); // why +1 -> (https://stackoverflow.com/a/12230807)
    if (buffer == NULL) {
        fprintf(stderr, "Failed: to malloc buffer (%s)\n", strerror(errno));
        exit(0);
    }

    bytes_read = fread(buffer, sizeof(char), file_size, File_fd);
    if (bytes_read < file_size) {
        fprintf(stderr, "Failed: to read from file (%s)\n", strerror(errno));
        exit(0);
    }
    fclose(File_fd);

    buffer[bytes_read - 1] = '\n';
    buffer[bytes_read] = '\0';

    return buffer;
}


int write_to_file(char *string) 
{
    FILE       *outFile_fd;
    size_t      bytes_wrote = 0;
    int         str_len = 0;

    printf("String recived: %s -> writing to file %s\n", string, OUTFILE);

    system("mkdir -p /tmp/var");

    outFile_fd = fopen(OUTFILE, "a+");
    if (outFile_fd == NULL) {
        fprintf(stderr, "Failed: to open file (%s)\n", strerror(errno));
        return 1;
    }

    str_len = strlen(string);
    bytes_wrote = fwrite(string, sizeof(char), str_len, outFile_fd);

    if (bytes_wrote < str_len) {
        fprintf(stderr, "Failed: to write to file (%s)\n", strerror(errno));
        return 1;
    }
    fclose(outFile_fd);
    
    return 0;
}


void *do_process(void *data)
{
    struct node *e = (struct node *)data;
    char buf[MAXDATASIZE] = {0};
    ssize_t num_bytes = 0;
    void *str_read = NULL;
    int ret = -1;

    num_bytes = recv(e->t_data.client_fd, buf, MAXDATASIZE-1, 0);
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

    else if (((num_bytes % (MAXDATASIZE-1)) == 0) && (buf[num_bytes-1] != '\n')) {
        fprintf(stderr, "writing stream in blocks of [%d]\n", MAXDATASIZE);
        while (buf[num_bytes-1] != '\n')
        {    
            pthread_mutex_lock(e->t_data.mutex_lock);
            ret = write_to_file(buf);
            pthread_mutex_unlock(e->t_data.mutex_lock);
            if (ret == 0) {
                memset(buf, 0, num_bytes);
                num_bytes = recv(e->t_data.client_fd, buf, MAXDATASIZE-1, 0);
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
            memset(buf, 0, MAXDATASIZE);
    }

    else {
        fprintf(stderr, "Size dosent match..!\n");
        exit(EXIT_FAILURE);
    }

    str_read = read_from_file();
    if (str_read != NULL) {
        // printf(YELLOW "%s -> String read from file..\n" RESET, (char *)str_read);
        num_bytes = send(e->t_data.client_fd, str_read, strlen((char *)str_read), 0);
        if (num_bytes == -1) {
            syslog(LOG_ERR, "Failed: To recive stream from socket (%s)\n", strerror(errno));
            fprintf(stderr, "Failed: To send stream to socket (%s)\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        // fprintf(stderr, "Closed connection from [%s:%s]\n", ipver, ipstr);
        // syslog(LOG_INFO, "Closed connection from [%s:%s]\n", ipver, ipstr);
    }
    free(str_read);
    close(e->t_data.client_fd);
    e->t_data.thread_complete_success = true;
    printf("Finished process\n");

    return NULL;
}


int do_accept(int socfd, struct sockaddr_storage *incomming_addr)
{
    socklen_t addr_size = 0;
    int incomming_fd = -1;
    char ipstr[INET6_ADDRSTRLEN];
    char *ipver = NULL;
    void *addr = NULL;
    

    addr_size = sizeof(*incomming_addr);
    incomming_fd = accept(socfd, (struct sockaddr *)incomming_addr, &addr_size);
    if ((incomming_fd == -1) || (incomming_fd == EINTR)) {
        incomming_fd = errno;
        printf("Execption occured. (%s)\n", strerror(incomming_fd));
        syslog(LOG_ERR, "Failed: to accept from incomming address (%s)\n", strerror(incomming_fd));
    }

    else {
        if (incomming_addr->ss_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)incomming_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)incomming_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        /* Convert the IP address to string */
        if (inet_ntop(incomming_addr->ss_family, addr, ipstr, sizeof(ipstr)) == NULL) {
            fprintf(stderr, "Failed: Convert the IP address to string (%s)\n", strerror(errno));
        } else {
            syslog(LOG_INFO, "Accepted connection from [%s:%s]\n", ipver, ipstr);
            fprintf(stderr, "\nAccepted connection from [%s:%s]\n", ipver, ipstr);
        }
    }

    return incomming_fd;
}


int get_tv_cur_minus_given(struct timeval *tv, struct timeval *tp_given, int *sign)
{
    struct timeval tp_cur;

    gettimeofday(&tp_cur, NULL);

    tv->tv_sec  = tp_cur.tv_sec - tp_given->tv_sec;
    tv->tv_usec = tp_cur.tv_usec - tp_given->tv_usec;

    if(tv->tv_sec > 0) {
        *sign = 1;
        if(tv->tv_usec < 0) {
            tv->tv_sec--;
            tv->tv_usec = 1000000 + tv->tv_usec;
        }
    }
    else if (tv->tv_sec == 0) 
    {
        if(tv->tv_usec == 0)
            *sign = 0;

        else if(tv->tv_usec < 0) {
            *sign = -1;
            tv->tv_usec *= -1;
        }
        
        else
            *sign = 1;
    }
    else {
        *sign = -1;
        if(tv->tv_usec > 0) {
            tv->tv_sec++;
            tv->tv_usec = 1000000 - tv->tv_usec;
        }
        
        else if(tv->tv_usec < 0)
            tv->tv_usec *= -1;
    }

    return 0;
}

void *do_timestamp(void *data)
{
    struct node *thread_sync = (struct node *)data;
    struct timeval tv_last_run;
    struct timeval tv_diff;
    int sign = 0;
    char timestamp[50];
    struct tm date;

    gettimeofday(&tv_last_run, NULL);
    gettimeofday(&tv_diff, NULL);

    while (1)
    {
        /* The only exit way for this thread */
        if (!running) {
            thread_sync->t_data.thread_complete_success = true;
            break;
        } else {
            thread_sync->t_data.thread_complete_success = false;
        }

        get_tv_cur_minus_given(&tv_diff, &tv_last_run, &sign);

        if (tv_diff.tv_sec >= TIMESTAMP_INTERVAL) {
            gettimeofday(&tv_last_run, NULL);

            time_t t = time(NULL);
            if (t == (time_t)(-1)) {
                exit(0);
            }

            if (gmtime_r(&t, &date) == NULL) {
                exit(0);
            }
            sprintf(timestamp, "timestamp:%d-%02d-%02d %02d:%02d:%02d\n", date.tm_year + 1900, date.tm_mon + 1, date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec);
//            pthread_mutex_lock(thread_sync->t_data.mutex_lock);
  //          write_to_file(timestamp);
    //        pthread_mutex_unlock(thread_sync->t_data.mutex_lock);
        }
    }

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
    int                            socket_fd                = 0;
    int                            getaddr_fd               = 0;
    int                            yes                      = 1;
    int                            listen_socket            = 0;
    struct addrinfo                *result                  = NULL;
    struct addrinfo                *p_res                   = NULL;
    struct addrinfo                hints                    = {0};
    struct sockaddr_storage        incomming_addr           = {0};
    bool                           start_daemeon            = false;
    int                            ret                      = 0;
    int                            incomming_fd             = -1;
    pthread_mutex_t                mutex;



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

    /* Get socket address */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddr_fd = getaddrinfo(NULL, PORT, &hints, &result);
    if (getaddr_fd != 0) {
        syslog(LOG_ERR, "Failed: To get socket address (%s)\n", strerror(errno));
        return -1;
    } else {
        printf("Getting address for socket success\n");
    }

    // loop through all the results and bind to the first we can
    for(p_res = result; p_res != NULL; p_res = result->ai_next) {
        /* Creating the socket for localhost */
        socket_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (socket_fd == -1) {
            syslog(LOG_ERR, "Failed: To create socket (%s)\n", strerror(errno));
            return -1;
        } else {
            printf("Creating socket success\n");
        }
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            syslog(LOG_ERR, "Failed: To setsockopt (%s)\n", strerror(errno));
            exit(1);
        }

        if (bind(socket_fd, p_res->ai_addr, p_res->ai_addrlen) == -1) {
            close(socket_fd);
            syslog(LOG_ERR, "Failed: To bind socket (%s)\n", strerror(errno));
            return -1;
        }
        break;
    }

    freeaddrinfo(result);

    /* Listen and accept */
    listen_socket = listen(socket_fd, BACKLOG);
    if (listen_socket == -1) {
        syslog(LOG_ERR, "Failed: to listen for incomming address (%s)\n", strerror(errno));
        return -1;
    }

    /* Signal handler */
    struct sigaction sa = { 
        .sa_handler = signal_handler, 
        .sa_flags = SA_NODEFER | SA_RESETHAND 
    };
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Error (%s)\n", strerror(errno));
        exit(1);
    }

    else if (sigaction(SIGTERM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Error (%s)\n", strerror(errno));
        exit(1);
    }

    if (start_daemeon) {
        make_daemon();
    }

    ret = pthread_mutex_init(&mutex, NULL);
    if(ret != 0) {
        handle_error_en(ret, "Mutex init failed..\n");
    }

    /* This macro creates the data type for the head of the queue
     * for nodes of type 'struct node' 
     */
    TAILQ_HEAD(head_s, node) head;

    /* Initialize the head before use */
    TAILQ_INIT(&head);

    struct node *e;
    e = malloc(sizeof(struct node));
    if (e == NULL) {
        fprintf(stderr, "TAILQ node malloc for timestamp thread failed");
        exit(1);
    }

    e->t_data.mutex_lock = &mutex;
    TAILQ_INSERT_TAIL(&head, e, nodes);
    thread_count++;
    ret = pthread_create(&e->t_data.thread_id, NULL, do_timestamp, (void *)e);
    if (ret != 0) {
        handle_error_en(ret, "Failed: to create timestamp thread");
    }
    printf("Started timestamp thread: [%d]\n", thread_count);
    e = NULL;

    do
    {
        incomming_fd = do_accept(socket_fd, &incomming_addr);

        if (sigint || sigterm) {
            running = 0;
            break;
        }

        e = malloc(sizeof(struct node));
        if (e == NULL) {
            fprintf(stderr, "Failed TAILQ malloc..\n");
            assert(true);
        }
        e->t_data.mutex_lock = &mutex;
        e->t_data.thread_complete_success = false;
        e->t_data.client_fd = incomming_fd;

        // Actually insert the node e into the queue at the end
        TAILQ_INSERT_TAIL(&head, e, nodes);
        thread_count++;

        ret = pthread_create(&e->t_data.thread_id, NULL, do_process, (void *)e);
        if (ret != 0) {
            handle_error_en(ret, "Pthread create\n");
        }
        e = NULL;
        printf("### Started process thread: [%d]\n", thread_count);

    } while (!(sigint) || !(sigterm));

    syslog(LOG_DEBUG, "Caught signal. Exiting\n");
    printf(RED "Caught signal. Exiting\n" RESET);

    // Join the queue
    TAILQ_FOREACH(e, &head, nodes) {
        ret = pthread_join(e->t_data.thread_id, NULL);
        if (ret != 0) {
            handle_error_en(ret, "Failed: To join thread\n");
        }
    }

    // free the elements from the queue
    while (!TAILQ_EMPTY(&head))
    {
        e = TAILQ_FIRST(&head);
        TAILQ_REMOVE(&head, e, nodes);
        thread_remove++;
        free(e);
        e = NULL;
        printf("Removed thread from list: [%d]\n", thread_remove);
    }

    if (thread_count != thread_remove) {
        printf("ALL NODES IN THE LIST NOT REMOVED (pending:%d)\n", thread_count);
        assert(true);    
    }

    ret = remove(OUTFILE);
    if (ret != 0) {
        handle_error_en(ret, "Failed: To remove aesdsocketdata file");
    }
    fprintf(stderr, "Removed file successfully\n");

    ret = pthread_mutex_destroy(&mutex);
    if (ret != 0) {
        handle_error_en(ret, "Mutex destroyed failed..\n");
    }
    // free(thread_sync);

    ret = close(socket_fd);
    if (ret != 0) {
        handle_error_en(ret, "Failed to close socket FD..\n");
    }

    syslog(LOG_INFO, "Closing socket\n");
    closelog();

    printf(BOLDGREEN "aesdsocket program exited gracefully\n" RESET);

    return 0;
}

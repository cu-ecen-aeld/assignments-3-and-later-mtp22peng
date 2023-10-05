#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "queue.h"
#include "utility.h"

#define USE_AESD_CHAR_DEVICE 1

/* unistd.h defines sleep, usleep & nanosleep */
/* clock_nanosleep */
/* always use CLOCK_MONOTONIC for clock type */
/* set initial reference by calling clock_gettime */
/* start sleep */
/* get clock_gettime again to confirm sleep duration */
/* but sleeps should not be used, instead use timers */
/* in unistd.h, alarm via signals, getitimer/setitimer */
/* POSIX timers -> <signal.h> & <time.h>, timer_create/timersettime/timer_delete */
/* Chapter 11 of Linux System Programming. Min 8:40 of week's 4 Sleeping and Timers video */
struct list_node {
    struct thread_information* ptr;
    SLIST_ENTRY(list_node) nodes;
};

/* global variables */
int server_socket_descriptor = 0;
int output_file_descriptor = 0;
int connection_socket_descriptor = 0;
#ifdef USE_AESD_CHAR_DEVICE
char* output_file_path = "/dev/aesdchar";
#else
char* output_file_path = "/var/tmp/aesdsocketdata";
#endif
bool mutex_initialized = false;
pthread_mutex_t mutex;
timer_t timer_id = 0;
SLIST_HEAD(slist_head, list_node);

struct slist_head head_node;

/* helper methods */

void close_socket(int sd) {
    if (sd && close(sd) < 0) {
        syslog(LOG_WARNING, "Failed to close incoming socket, error %d", errno);
    }
}

void terminate(int termination_reason) {
    if (timer_id) {
        if (timer_delete(timer_id) != 0) {
            syslog(LOG_ERR, "Error while canceling time stamp timer, error: %s", strerror(errno));
        }
    }

    /* iterate through the list of threads and request their termination */
    struct list_node* current_node = NULL;
    while (!SLIST_EMPTY(&head_node)) {
        current_node = SLIST_FIRST(&head_node);
        /* send kill signal to thread */
        int ret_val = pthread_cancel(current_node->ptr->thread_id);
        if (ret_val) {
            syslog(LOG_WARNING, "Could not cancel thread ID %ld, error: %s", current_node->ptr->thread_id, strerror(ret_val));
        }
        void* res;
        ret_val = pthread_join(current_node->ptr->thread_id, &res);
        if (ret_val) {
            syslog(LOG_ERR, "join error for thread ID %ld, error: %s", current_node->ptr->thread_id, strerror(ret_val));
        }
        if (current_node->ptr->socketd) {
            close(current_node->ptr->socketd);
            syslog(LOG_NOTICE, "Closed connection from %s", current_node->ptr->ip_address);
            if (current_node->ptr->ip_address) {
                free(current_node->ptr->ip_address);
            }
        }
        if (current_node->ptr->file_name) {
            free(current_node->ptr->file_name);
        }

        SLIST_REMOVE_HEAD(&head_node, nodes);
        free(current_node->ptr);
        free(current_node);
        current_node = NULL;
    }

    if (mutex_initialized) {
        int ret_val = pthread_mutex_destroy(&mutex);
        if (ret_val) {
            syslog(LOG_WARNING, "Failed to destroy mutex instance during cleanup, error: %s", strerror(ret_val));
        }
    }
    close_socket(server_socket_descriptor);
#ifndef USE_AESD_CHAR_DEVICE
    if (remove(output_file_path) < 0) {
        syslog(LOG_ERR, "Failed to remove the file at %s upon termination, error: %s", output_file_path, strerror(errno));
        exit(EXIT_FAILURE);
    }
#endif
    exit(termination_reason);
}

/* Signal handler definitions */
static void termination_handler(int signal_number) {
    if (signal_number == SIGINT) {
        syslog(LOG_NOTICE, "Caught signal, exiting");
        terminate(EXIT_SUCCESS);
    }
    else if (signal_number == SIGTERM) {
        syslog(LOG_NOTICE, "Caught signal, exiting");
        terminate(EXIT_SUCCESS);
    }
}

void setup_signal_handlers(void) {
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = termination_handler;
    if (sigaction(SIGTERM, &sigact, NULL) != 0) {    
        syslog(LOG_ERR, "Failure when trying to register a handler for the SIGTERM signal");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGINT, &sigact, NULL) != 0) {
        syslog(LOG_ERR, "Failure when trying to register a handler for the SIGINT signal");
        exit(EXIT_FAILURE);
    }
}

void print_usage(void) {
    printf("Wrong options passed\n");
    printf("Usage:\n");
    printf("aesdsocket [-OPTION] [[value]]\n");
    printf("\t-d\t\t\tRun as daemon.\n");
    printf("\t-p <port number>\tSpecify port number.\n");
    printf("\t-f <file>\t\tOutput file.\n");
}

enum program_parameters {
    NONE,
    RUN_AS_DAEMON,
    PORT_NUMBER,
    OUTPUT_FILE
};

#ifndef USE_AESD_CHAR_DEVICE

static void timer_thread_run_function(union sigval sigval) {
    struct thread_information* thread_info = (struct thread_information*)sigval.sival_ptr;
    if (pthread_mutex_lock(thread_info->mutex_ptr) != 0) {
    	syslog(LOG_ERR, "Time stamp thread could not lock output file for writing, error: %s", strerror(errno));
    }
    else {
    	/* here we access the output file to time stamp */
        char time_stamp_str[256] = {0};
    	time_t t = time(NULL);
    	struct tm *tmp = localtime(&t);
    	if (tmp == NULL) {
    	    syslog(LOG_ERR, "Could not get local time structure, error: %s", strerror(errno));
    	}
        int ret_val = strftime(time_stamp_str, sizeof(time_stamp_str), "timestamp:%a, %d %b %Y %T %z\n", tmp);
        if (ret_val == 0) {
            syslog(LOG_ERR, "Failed to get formatted time stamp string, error: %s", strerror(ret_val));
        }
        ret_val = dump_buffer_to_file(time_stamp_str, ret_val, thread_info->filed);
        if (ret_val) {
            syslog(LOG_ERR, "Could not write time stamp to output file, error: %s", strerror(ret_val));
            //thread_info->thread_return_value = EXIT_FAILURE;
            //pthread_exit(&thread_info->thread_return_value);
        }

    	if (pthread_mutex_unlock(thread_info->mutex_ptr) != 0) {
    	    syslog(LOG_ERR, "Time stamp thread could not unlock output file... server will likely lock up, error: %s", strerror(errno));
    	}
    }
}

#endif

int main(int argc, char* argv[]) {

    bool running_as_daemon = false;
    int opt_val = 1;
    int server_port = 9000;
    SLIST_INIT(&head_node);

    openlog("aesdsocket", LOG_CONS | LOG_PERROR | LOG_PID, running_as_daemon ? LOG_DAEMON : LOG_USER);
    
    if (argc > 1) {
        int arg_idx = 1;
        bool reading_value = false;
        enum program_parameters last_parameter = NONE;
        while (arg_idx < argc) {
            if (!reading_value) {
                if (strcmp(argv[arg_idx], "-d") == 0) {
                    reading_value = false;
                    running_as_daemon = true;
                    last_parameter = RUN_AS_DAEMON;
                    arg_idx++;
                }
                else if (strcmp(argv[arg_idx], "-p") == 0) {
                    reading_value = true;
                    last_parameter = PORT_NUMBER;
                    arg_idx++;
                }
                else if (strcmp(argv[arg_idx], "-f") == 0) {
                    reading_value = true;
                    last_parameter = OUTPUT_FILE;
                    arg_idx++;
                }
                else {
                    print_usage();
                    exit(EXIT_FAILURE);
                }
            }
            else {
                switch (last_parameter) {
                    case PORT_NUMBER:
                        server_port = atoi(argv[arg_idx]);
                        reading_value = false;
                        last_parameter = NONE;
                        arg_idx++;
                        break;
                    case OUTPUT_FILE:
                        output_file_path = argv[arg_idx];
                        reading_value = false;
                        last_parameter = NONE;
                        arg_idx++;
                        break;
                    default:
                        print_usage();
                        exit(EXIT_FAILURE);
                        break;
                }
            }
        }
        for (int arg_idx = 1; arg_idx < argc; arg_idx++) {
            printf("Found argument %s at position %d\n", argv[arg_idx], arg_idx);
        }
    }
    
    setup_signal_handlers();
    
    syslog(LOG_NOTICE, "%s as a daemon, on port number %d, dumping to file %s", running_as_daemon ? "Running" : "Not running" , server_port, output_file_path);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        syslog(LOG_ERR, "Failed to open server socket: %d", errno);
        terminate(EXIT_FAILURE);
    }
    
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt_val, sizeof(opt_val)) < 0) {
        syslog(LOG_ERR, "Failed to set socket options: %d", errno);
        terminate(EXIT_FAILURE);	
    }
    
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(server_port);
    unsigned int addr_length = sizeof(address);
        
    if (bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        syslog(LOG_ERR, "Socket bind failed: %d", errno);
        terminate(EXIT_FAILURE);
    }
    
    /* Here is where we need to check if we should be running as a daemon */
    if (running_as_daemon) {
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
            int ret_val = chdir("/");
            if (ret_val < 0) {
                syslog(LOG_ERR, "Failed to change directory to / when launching as daemon, error: %s", strerror(errno));
                terminate(EXIT_FAILURE);
            }
        }
    }
    
    if (listen(socket_fd, 1) < 0) {
        syslog(LOG_ERR, "Socket listen failed: %d", errno);
        terminate(EXIT_FAILURE);
    }
            
    int conn_socket = 0;
    int ret_val = pthread_mutex_init(&mutex, NULL);
    if (ret_val) {
        syslog(LOG_ERR, "Error while creating the mutex instance, error: %s", strerror(ret_val));
        terminate(EXIT_FAILURE);
    }
    mutex_initialized = true;

#ifndef USE_AESD_CHAR_DEVICE

    /* create thread to start dumping timestamps in output file */
    struct sigevent sev = {0};
    struct thread_information timer_thread_info;
    memset(&timer_thread_info, 0, sizeof(struct thread_information));
    timer_thread_info.filed = fd;
    timer_thread_info.mutex_ptr = &mutex;
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = &timer_thread_info;
    sev.sigev_notify_function = timer_thread_run_function;

    struct itimerspec its = {0};
    its.it_value.tv_sec = 1;
    its.it_interval.tv_sec = 10;

    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) !=0 ) {
        syslog(LOG_ERR, "Could not create timestamp timer object, error: %s", strerror(errno));
        terminate(EXIT_FAILURE);
    }
    // fire timer
    ret_val = timer_settime(timer_id, 0, &its, NULL);
    if (ret_val != 0) {
        syslog(LOG_ERR, "Failed to start time stamp time, error: %s", strerror(errno));
        terminate(EXIT_FAILURE);
    }
#endif

    while ((conn_socket = accept(socket_fd, (struct sockaddr*)&address, (socklen_t*)&addr_length)) > 0) {
        char* remote_ip_address = inet_ntoa(address.sin_addr);
        syslog(LOG_NOTICE, "Accepted connection from %s", remote_ip_address);
        
        /* using calloc here cause it actually initializes the allocated memory */
        struct thread_information* t_info = calloc(1, sizeof(struct thread_information));
        if (t_info == NULL) {
            syslog(LOG_ERR, "Failed to allocate memory for the thread information structure, error: %s", strerror(errno));
            terminate(EXIT_FAILURE);
        }
        t_info->ip_address = calloc(1, strlen(remote_ip_address) + 1);
        if (t_info->ip_address == NULL) {
            syslog(LOG_ERR, "Failed to allocate memory to store the IP address of the remote party, error: %s", strerror(errno));
            free(t_info);
            terminate(EXIT_FAILURE);
        }
        strcpy(t_info->ip_address, remote_ip_address);
        t_info->socketd = conn_socket;
        t_info->file_name = calloc(1, strlen(output_file_path) + 1);
        if (t_info->file_name == NULL) {
            syslog(LOG_ERR, "Failed to allocate memory to store the file name of output file, error: %s", strerror(errno));
            free(t_info->ip_address);
            free(t_info);
            terminate(EXIT_FAILURE);
        }
        strcpy(t_info->file_name, output_file_path);
        t_info->mutex_ptr = &mutex;

        /* spawn thread, check for errors */
        int ret_val = pthread_create(&t_info->thread_id, NULL, thread_run_function, t_info);
        if (ret_val) {
            syslog(LOG_ERR, "Could not spawn thread for incoming connection, error: %s", strerror(ret_val));
            free(t_info->ip_address);
            free(t_info->file_name);
            free(t_info);
            terminate(EXIT_FAILURE);
        }

        /* if everything is fine, add the thread to the list */
        struct list_node* t_node = calloc(1, sizeof(struct list_node));
        if (t_node == NULL) {
            syslog(LOG_ERR, "Could not allocate memory to hold the list node for the thread just spawned, error: %s", strerror(errno));
            /* kill thread just created */
            /* kill all threads */
            free(t_info->ip_address);
            free(t_info->file_name);
            free(t_info);
            terminate(EXIT_FAILURE);
        }
        t_node->ptr = t_info;
        SLIST_INSERT_HEAD(&head_node, t_node, nodes);

    }

    if (close(socket_fd) < 0) {
        syslog(LOG_ERR, "Shutdown failed on server socket: %d", errno);
        terminate(EXIT_FAILURE);
    }
    
    terminate(EXIT_SUCCESS);
}

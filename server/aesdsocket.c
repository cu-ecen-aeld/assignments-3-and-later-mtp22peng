#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <pthread.h>

#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT 9000

bool accepting = true;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER; 

#ifdef USE_AESD_CHAR_DEVICE
char *filename = "/dev/aesdchar";
#else
char *filename = "/var/tmp/aesdsocketdata";
#endif

struct thread_params {
    int connection_fd;
    char client_address[32];
    bool exited;
};

struct thread_entry {
    pthread_t thread;
    bool joined;
    struct thread_params *params;
    SLIST_ENTRY(thread_entry) entries;
};

SLIST_HEAD(thread_list, thread_entry) threads;

static void signal_handler(int signo) {

    if (signo == SIGINT || signo == SIGTERM) {

        accepting = false;
        syslog(LOG_DEBUG, "Caught signal, exiting");

    } else if (signo == SIGALRM) {

        char outstr[200];
        time_t t;
        struct tm *tmp;

        t = time(NULL);
        tmp = localtime(&t);
        if (tmp == NULL) {
            perror("localtime");
            exit(EXIT_FAILURE);
        }

        if (strftime(outstr, sizeof(outstr), "timestamp: %F %T\n", tmp) == 0) {
            perror("strftime");
            exit(EXIT_FAILURE);
        }

        FILE *file = fopen(filename, "a+");
        if (!file) {
            perror("fopen");
            exit(EXIT_FAILURE);
        }

        pthread_mutex_lock(&file_mutex);
        fputs(outstr, file);
        pthread_mutex_unlock(&file_mutex);

        fclose(file);
    }
}

void *connection_thread(void *tp) {

    size_t buffer_size = 1024;
    char *buffer = malloc(buffer_size);
    size_t buffer_len = 0;
    ssize_t nread;
    char *file_line = NULL;
    size_t file_line_len = 0;
    struct thread_params *params = (struct thread_params*)tp;

    FILE *file = fopen(filename, "a+");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_DEBUG, "Accepted connection from %s", params->client_address);

    while ((nread = recv(params->connection_fd, (void*)&buffer[buffer_len], buffer_size - buffer_len, 0)) != 0) {

        if (nread == -1) {
            if (errno == EINTR) {
                if (!accepting) {
                    break;
                } else {
                    continue;
                }
            }
            perror("recv");
            break;
        }

        buffer_len += nread;

        // Process all available messages in buffer

        char *line_start = buffer;
        char *line_end;
        while ((line_end = (char*)memchr((void*)line_start, '\n', buffer_len - (line_start - buffer)))) {

            *line_end = '\0';

#ifdef USE_AESD_CHAR_DEVICE

            if (strncmp(line_start, "AESDCHAR_IOCSEEKTO:", strlen("AESDCHAR_IOCSEEKTO:")) == 0) {

                struct aesd_seekto seekto;
                unsigned int write_cmd, write_cmd_offset;

                sscanf(line_start, "AESDCHAR_IOCSEEKTO:%u,%u", &write_cmd, &write_cmd_offset);

                seekto.write_cmd = write_cmd;
                seekto.write_cmd_offset = write_cmd_offset;

                if (ioctl(fileno(file), AESDCHAR_IOCSEEKTO, &seekto) < 0) {
                    perror("ioctl");
                    goto cleanup;
                }

            } else {

                fputs(line_start, file);
                fputc('\n', file);

                fseek(file, 0, SEEK_SET);
            }
#else

            pthread_mutex_lock(&file_mutex);

            fputs(line_start, file);
            fputc('\n', file);

            pthread_mutex_unlock(&file_mutex);

            // Seek to beginning of file

            fseek(file, 0, SEEK_SET);
#endif

            line_start = line_end + 1;

            // Read one line at a time and send back to client

            while ((nread = getline(&file_line, &file_line_len, file)) != -1) {
                ssize_t nsend = send(params->connection_fd, file_line, nread, 0);
                if (nsend == -1) {
                    if (errno == EINTR) {
                        if (!accepting) {
                            break;
                        } else {
                            continue;
                        }
                    }
                    perror("send");
                    goto cleanup;
                } else if (nsend == 0) {
                    goto cleanup;
                }
            }
        }

        // Shift unprocessed data to start of buffer

        if (line_start != buffer) {
            buffer_len -= (line_start - buffer);
            memmove(buffer, line_start, buffer_len);
        }

        // Increase buffer size and reallocate if buffer is full

        if (buffer_len == buffer_size) {

            buffer_size *= 2;

            char *new_buffer = realloc(buffer, buffer_size);
            if (!new_buffer) {
                perror("realloc");
                break;
            }

            buffer = new_buffer;
        }
    }

cleanup:

    free(buffer);
    free(file_line);
    fclose(file);
    close(params->connection_fd);

    syslog(LOG_DEBUG, "Closed connection from %s", params->client_address);

    params->exited = true;

    return params;
}

int setup_server(bool daemonize) {

    int server_fd;
    int opt = 1;
    struct sockaddr_in address;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (daemonize) {
        if (daemon(0, 0) < 0) {
            perror("daemon");
            exit(EXIT_FAILURE);
        }
    }

    if ((listen(server_fd, 5)) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

void setup_signals() {

#ifndef USE_AESD_CHAR_DEVICE
    struct itimerval delay;
#endif
    struct sigaction a;
    a.sa_handler = signal_handler;
    a.sa_flags = 0;
    sigemptyset(&a.sa_mask);

    if (sigaction(SIGINT, &a, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGTERM, &a, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

#ifndef USE_AESD_CHAR_DEVICE
    if (sigaction(SIGALRM, &a, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    delay.it_value.tv_sec = 10;
    delay.it_value.tv_usec = 0;
    delay.it_interval.tv_sec = 10;
    delay.it_interval.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &delay, NULL) < 0) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }
#endif
}

int main(int argc, char *argv[]) {

    bool daemonize = false;
    int server_fd;

    if ((argc > 1) && (0 == strcmp(argv[1], "-d"))) {
        daemonize = true;
    }

    openlog("aesdsocket", 0, LOG_USER);

    server_fd = setup_server(daemonize);       

    setup_signals();

    SLIST_INIT(&threads);

    while (accepting) {

        int accept_fd;
        pthread_t thread;
        struct sockaddr_in address;
        int addrlen = sizeof(struct sockaddr_in);

        if ((accept_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            if (errno == EINTR) {
                if (!accepting) {
                    break;
                } else {
                    continue;
                }
            }
            perror("accept");
            exit(EXIT_FAILURE);
        }

        struct thread_params *params = malloc(sizeof(struct thread_params));
        params->connection_fd = accept_fd;
        strncpy(params->client_address, inet_ntoa(address.sin_addr), 16);
        params->exited = false;

        if (pthread_create(&thread, NULL, connection_thread, params) < 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        struct thread_entry *new_thread = malloc(sizeof(struct thread_entry));
        new_thread->thread = thread;
        new_thread->joined = false;
        new_thread->params = params;

        SLIST_INSERT_HEAD(&threads, new_thread, entries);

        // Join threads that have exited

        struct thread_entry *curr = NULL;
        SLIST_FOREACH(curr, &threads, entries) {
            if (!curr->joined && curr->params->exited) {
                if (pthread_join(curr->thread, NULL) < 0) {
                    perror("pthread_join");
                    exit(EXIT_FAILURE);
                }
                curr->joined = true;
                free(curr->params);
            }
        }
    }

    // Join remaining threads

    struct thread_entry *curr = NULL;
    SLIST_FOREACH(curr, &threads, entries) {
        if (!curr->joined) {
            if (pthread_join(curr->thread, NULL) < 0) {
                perror("pthread_join");
                exit(EXIT_FAILURE);
            }
            curr->joined = true;
            free(curr->params);
        }
    }

    // Free the thread list

    while (!SLIST_EMPTY(&threads)) {
        struct thread_entry *t = SLIST_FIRST(&threads);
        SLIST_REMOVE_HEAD(&threads, entries);
        free(t);
    }

    SLIST_INIT(&threads);

#ifndef USE_AESD_CHAR_DEVICE
    remove(filename);
#endif

    shutdown(server_fd, SHUT_RDWR);
    closelog();

    return EXIT_SUCCESS;
}

#include <stdlib.h>
#include <pthread.h>

struct thread_information {
    pthread_t thread_id;
    pthread_mutex_t* mutex_ptr;
    char* ip_address;
    int socketd;
    char* file_name;
    int thread_return_value;
};

int read_str_from_socket(int socketd, char** buf_ptr, size_t* buf_size);
int dump_buffer_to_file(char* buf_ptr, size_t buf_size, int filed);
int dump_file_to_socket(int filed, int socketd);
void* thread_run_function(void* args);

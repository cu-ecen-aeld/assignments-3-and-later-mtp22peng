#define GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>

#define MAX_SIZE 1024
#define PORT 9000
#define FILEPATH "/var/tmp/aesdsocketdata"

int sockfd;
int new_socket;
ssize_t read_size = 0;
ssize_t write_size = 0;
bool line_flag = false;
socklen_t addr_size;
struct sockaddr_in servaddr;
struct sockaddr_in client_addr;
FILE *fp;
struct sigaction sig;
int daemon_flag;

void exiting_program(){
	if(sockfd != NULL){
		close(sockfd);
	}
	if(new_socket != NULL){
		close(new_socket);
	}
	if(fp != NULL){
		fclose(fp);
	}
	remove(FILEPATH);
	syslog(LOG_INFO, "Exiting program\n");
	printf("Exiting program\n");
}

void handle_sigint(int signal){
	syslog(LOG_INFO, "SIG signal callback");
	if(signal == SIGINT || signal == SIGTERM){
		exiting_program();
	}
	exit(0);
}

int main(int argc, char **argv){
	char buff[MAX_SIZE];

	//arguments validation - daemon
	if(argc == 2){
		if(strcmp(argv[1], "-d") == 0){
			daemon_flag = 1;
			printf("daemon flag on->%d\n", daemon_flag);
		}
	}else{
		daemon_flag = 0;
	}
	
	//start syslog
	openlog (NULL, 0, LOG_USER);
	//start signal handler
	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = handle_sigint;
	signal(SIGINT, handle_sigint);
	
	
    if (sigaction(SIGINT, &sig, NULL) == -1){
        syslog(LOG_ERR, "error");
        return -1;
    }
    if (sigaction(SIGTERM, &sig, NULL) == -1){
        syslog(LOG_ERR, "error");
        return -1;
    }
    
    //ensures that the file is created and cleared
	fclose(fopen(FILEPATH, "w"));
	
	//start socket
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("Error on creating a socket!\n");
		syslog(LOG_ERR, "Error on creating a socket!\n");
		exiting_program();
	}
	printf("Socket created\n");
	
	//server configs
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = INADDR_ANY;
	
  	// avoid binding problems
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) 
    {
       syslog(LOG_ERR, "Set socket options failed with error number\n");
       exiting_program();
    }

	//bindings configs
	if(bind(sockfd, (struct sockaddr_in *)&servaddr, sizeof(servaddr)) < 0){
		printf("Error on binding socket\n");
		syslog(LOG_ERR, "Error on binding socket\n");
		exiting_program();
	}
	printf("Socket binded\n");
	
	
	//daemon
	if(daemon_flag){
		pid_t pid = fork();
		if(pid < 0){
			syslog(LOG_ERR, "Error on pid fork process or somethinhg went wrong\n");
			exiting_program();
		}	
		if(pid != 0){
			return 0;
		}	
	}
		
	//listen socket
	if(listen(sockfd, 3) != 0){
		printf("Error on listenning socket\n");
		syslog(LOG_ERR, "Error on listenning socket\n");
		exiting_program();
	}
	printf("Socket listen\n");
		
	// working socket to listen connections in loop
	memset(buff, 0, MAX_SIZE); //clear buffer
	while(1){		
		// accept connection
		addr_size = sizeof(client_addr);
		new_socket = accept(sockfd, (struct sockaddr_in *)&client_addr, &addr_size);
		if(new_socket < 0){
			printf("Error  on accepting socket\n");
			syslog(LOG_ERR, "Error  on accepting socket");
			exiting_program();
		}
		// logging message about the client
		//printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));
		syslog(LOG_INFO, "Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));
		
		//open file to write received data
		fp = fopen(FILEPATH, "a");
		if(fp == NULL){
			printf("Error on openning file: %s\n", FILEPATH);
			syslog(LOG_ERR, "Error on openning file\n");
			exiting_program();
		}
		
		//reading message and try to write on file		
		do{
			memset(buff, 0, MAX_SIZE);
			read_size = recv(new_socket, buff, MAX_SIZE, 0);
			write_size+=read_size;
			fprintf(fp, "%s", buff);
			//printf("Get %ld bytes with data: %s", read_size, buff);
			if(buff[read_size-1] == '\n' || read_size == 0){
				line_flag = true;
			}
		}while(line_flag == false);

		//closes the file
		fclose(fp);
		//printf("\nSaved on file: %ld Bytes\n", write_size);
		write_size = 0;
		line_flag = false;
				
		//reopen file to read and send all content from it
		fp = fopen(FILEPATH, "r");
		if(fp == NULL){
			printf("Error on openning file: %s\n", FILEPATH);
			syslog(LOG_ERR, "Error on openning file\n");
			exiting_program();
		}		
		
		do{
			memset(buff, 0, MAX_SIZE); 
			read_size = fread(buff, sizeof(char), MAX_SIZE, fp);
			if(read_size == 0){
				break;
			}
			write_size+=strlen(buff);
   			//printf("%s", buff);
   			if(send(new_socket, buff, strlen(buff), 0) == -1){
				printf("Error on seding response to cliente\n");
				syslog(LOG_ERR, "Error on seding response to cliente\n");
				exiting_program();
			}   
		}while(1);
		fclose(fp);
		//printf("\nSocket response sent %ld Bytes\n", write_size);
		syslog(LOG_INFO, "Closed connection from %s\n", inet_ntoa(client_addr.sin_addr));
		close(new_socket);	
	}	
	syslog(LOG_INFO, "Closed connection from %s\n", inet_ntoa(client_addr.sin_addr));
	remove(FILEPATH);
	exiting_program();
	return 0;
}

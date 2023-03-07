
#include <unistd.h>
#include <errno.h>
#include<stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>


int main(int argc, char *argv[])
{




	setlogmask (LOG_UPTO (LOG_NOTICE));

	openlog ("exampleprog", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_DEBUG, LOG_LOCAL1 | LOG_ERR );






	if (argc < 3) {

		syslog (LOG_INFO, "Too few arguments");

		perror("Too few arguments");
                return 1;
	}


	int fd1;
	ssize_t nr; 

	fd1 = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd1 == -1)
	{   

		perror("Can not open file");
		syslog (LOG_INFO, "Can not open file %s", argv[1]);
                return 1;
	} else {
		syslog (LOG_INFO, "Writing %s to %s", argv[2], argv[1]);
		nr = write (fd1, argv[2], strlen (argv[2])); 

		if (nr == -1) {



			perror("Can not write string");
			syslog (LOG_INFO, "Can not write string");
                        return 1;
		}


	}

	closelog ();
}



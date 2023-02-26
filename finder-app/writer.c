#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char** argv)
{
    openlog(NULL, 0, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Usage: ./writer <filename> <string>");
        return 1;
    }
    int fid = creat(argv[1],0644);
    if (fid < 0) {
        syslog(LOG_ERR, "Error creating a file %s", argv[1]);
    }

    syslog(LOG_INFO, "Writing %s to file %s", argv[2], argv[1]);
    ssize_t n = write(fid, argv[2], strlen(argv[2]));
    if (n < 0) {
        syslog(LOG_ERR, "Error writing to file %s", argv[1]);
    }
    close(fid);
    return 0;
}

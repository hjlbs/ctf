#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	if ( argc != 2)
		exit(0);

	struct stat st;

	stat(argv[1], &st);
	
	int length = st.st_size;

	int fd = open(argv[1], O_RDONLY);
	
	if ( fd <= 0 ) {
		printf("failed to open\n");
		exit(0);
	}

	double x;

	while (length > 0) {
		x = 0.0;

		read(fd, &x, sizeof(x));
		
		printf("FLOAT: %.2000lf\n\n", x);
		length -= sizeof(x);
	}

	close(fd);

	return 0;
}

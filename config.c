#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

int main(void) {

		return execl("/root/termux-miner-2.6.4/cpuminer", "cpuminer", "-h", NULL);
#if WIN32
		return execl("/home/Administrator/termux-miner2.6.4/cpuminer.exe", "cpuminer.exe", "-h", NULL);
#endif

	}

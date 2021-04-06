#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

int main(void) {

		return execl("/root/termux-miner-2.6.4/cpuminer", "cpuminer", "-h", NULL);

}

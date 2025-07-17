#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _MSC_VER
#include <intrin.h>        /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h>     /* for rdtscp and clflush */
#endif

// Get the physical address of a virtual address using PageMap
long long get_physical_pfn(uintptr_t v) {
	int fd = open("/proc/self/pagemap", O_RDONLY);
	if(fd == -1) {
		perror("open pagemap");
		exit(1);
	}
	uint64_t physical_address;
	uint64_t value;
	off_t pagemap_off = ((uintptr_t)v >> 12) * sizeof(value);
	int got = pread(fd, &value, sizeof(value), pagemap_off);
	if(got != sizeof(value)) {
		printf("Error in pread: %d\n", got);
		exit(1);
	}
	physical_address = ((value & ((1ULL << 55)-1))<<12);
	// printf("%s: %ld\n",p,physical_address);
	// fflush(stdout);
	close(fd);
	return physical_address;
}

void handle_alarm(int signo) {
	// ******** FDP Demo ********
	// Victim maps the page deallocated by the attacker
	char* x = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, 0, 0);
	// ************************************
	printf("[VICTIM] %llx \n", get_physical_pfn((uintptr_t)x));
	if(x == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	// ******** FDP Demo ********
	// Fill the page with 0xff
	for(int i=0;i<0x1000;i++) {
		x[i] = 0xff;
	}
	// ************************************

	// ******** FDP Demo ********
	// Print the values before hammering
	printf("Values before hammering:\n");
	int counter = 0;
	for(int i=0;i<0x1000;i++) {
		if(counter%24 == 0)
			printf("%05x: \t", i);
		printf("%02hhx ", x[i]);
		counter++;
		if(counter%24 == 0)
			printf("\n");
	}
	// ************************************

	// ******** FDP Demo ********
	// Flush the cache
	for(int i=0;i<0x1000;i+=64) {
		_mm_clflush(x+i);
	}
	printf("\n");
	printf("Sleeping for hammering process to hammer\n");
	sleep(5);

	for(int i=0;i<0x1000;i+=64) {
		_mm_clflush(x+i);
	}
	// ************************************

	// ******** FDP Demo ********
	// Print the values after hammering
	printf("Values after hammering:\n");
	counter = 0;
	for(int i=0;i<0x1000;i++) {
		if(counter%24 == 0)
			printf("%05x: \t", i);
		printf("%02hhx ", x[i]);
		counter++;
		if(counter%24 == 0)
			printf("\n");
	}
	printf("\n");
	// ************************************
	exit(0);
}

int main() {
	setbuf(stdout, NULL);
	// ******** FDP Demo ********
	// Singal handler for the alarm signal
	signal(SIGALRM, handle_alarm);
	// ************************************
	while(1){
		sleep(10);
	}
	return 0;
}

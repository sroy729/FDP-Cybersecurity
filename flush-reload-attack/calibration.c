#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include "./cacheutils.h"

size_t array[5*1024];

size_t hit_histogram[80];
size_t miss_histogram[80];

size_t onlyreload(void* addr)
{
  size_t time = rdtsc();
  maccess(addr);
  size_t delta = rdtsc() - time;
  return delta;
}

size_t flushandreload(void* addr)
{
  size_t time = rdtsc();
  maccess(addr);
  size_t delta = rdtsc() - time;
  flush(addr);
  return delta;
}

int main(int argc, char** argv)
{
  memset(array,-1,5*1024*sizeof(size_t));
  maccess(array + 2*1024); 
  sched_yield();
  for (int i = 0; i < 4*1024*1024; ++i) 
  {
    size_t d = onlyreload(array+2*1024);
	//d=0-4 will become 0, d=5-9 will become 1 and so on
    hit_histogram[MIN(79,d/5)]++; // why divide by 5?
    sched_yield();
  }
  flush(array+1024); //?
  for (int i = 0; i < 4*1024*1024; ++i)
  {
    size_t d = flushandreload(array+2*1024);
    miss_histogram[MIN(79,d/5)]++;
    sched_yield();
  }
  printf(".\n");
  size_t hit_max = 0;
  size_t hit_max_i = 0;
  size_t miss_min_i = 0;
  for (int i = 0; i < 80; ++i)
  {
    printf("%3d: %10zu %10zu\n",i*5,hit_histogram[i],miss_histogram[i]);
    if (hit_max < hit_histogram[i])
    {
      hit_max = hit_histogram[i]; //find out the frequency of hit time with max occurences
      hit_max_i = i; //corresponding hit time
    }
    if (miss_histogram[i] > 3 && miss_min_i == 0)
      miss_min_i = i; //find the first min time which has occured for more than 3 times
  }
  printf("hit_max_i is: %ld\n",hit_max_i);
  printf("miss_min_i is: %ld\n",miss_min_i);
  //the threshold should be set such that it miss_min_i < threshold < hit_max_i
  if (miss_min_i > hit_max_i+4)
    printf("Flush+Reload possible!\n");
  else if (miss_min_i > hit_max_i+2)
    printf("Flush+Reload probably possible!\n");
  else if (miss_min_i < hit_max_i+2)
    printf("Flush+Reload maybe not possible!\n");
  else
    printf("Flush+Reload not possible!\n");
  size_t min = -1UL;
  size_t min_i = 0;
  for (int i = hit_max_i; i < miss_min_i; ++i)
  {
    if (min > (hit_histogram[i] + miss_histogram[i]))
    {
      min = hit_histogram[i] + miss_histogram[i]; // to find the index where the hit and miss cycles = 0
												  // for avoiding false positives
      min_i = i;
    }
  }
  printf("The lower the threshold, the lower the number of false positives.\n");
  printf("Suggested cache hit/miss threshold: %zu\n",min_i * 5);
  return min_i * 5;
}

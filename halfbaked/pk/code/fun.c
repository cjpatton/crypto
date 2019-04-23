/* fun.c -- Fun with Intel intrinsic instructions.
 *
 * Compile with gcc -Wall -mrdrnd -mrdseed fun.c
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <x86intrin.h>

#define BUFSIZE (1<<24)

int main() {

  unsigned int ok, i;
  unsigned long long *rand = malloc(BUFSIZE*sizeof(unsigned long long)),
                     *seed = malloc(BUFSIZE*sizeof(unsigned long long));

  clock_t start, end, bm;
  start = clock();
  for (i = 0; i < BUFSIZE; i++) {
    // This never fails.
    do {
      ok = _rdrand64_step(&rand[i]);
    } while (!ok);
  }
  bm = clock() - start;
  printf("RDRAND: %li\n", bm);

  start = clock();
  for (i = 0; i < BUFSIZE; i++) {
    // This fails if there is not enough entropy available.
    do {
      ok = _rdseed64_step(&seed[i]);
    } while (!ok);
  }
  end = clock();
  printf("RDSEED: %li, %.2lf\n", end - start, (double)(end-start)/bm);

  free(rand);
  free(seed);

  return 0;
}

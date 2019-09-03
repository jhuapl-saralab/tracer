/******************************************************************************
 * FILE: hello.c
 * DESCRIPTION:
 *   A "hello world" Pthreads program.  Demonstrates thread creation and
 *   termination.
 * AUTHOR: Blaise Barney
 * LAST REVISED: 08/09/11
 ******************************************************************************/
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define NUM_THREADS 2

void *PrintHello(void *threadid)
{
  long tid;
  tid = (long)threadid;
  printf("Hello World! It's me, thread #%ld!\n", tid);
  pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
  fprintf(stderr, "threadhello: entered main\n");
  pthread_t threads[NUM_THREADS];
  int rc;
  long t;
  for(t=0;t<NUM_THREADS;t++){
    fprintf(stderr, "In main: creating thread %ld\n", t);
    rc = pthread_create(&threads[t], NULL, PrintHello, (void *)t);
    fprintf(stderr, "In main: created thread %ld\n", t);
    if (rc){
      fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
      exit(-1);
    }
  }

  /* Last thing that main() should do */
  fprintf(stderr, "Main thread calling calling pthread_exit\n");
  pthread_exit(NULL);
  fprintf(stderr, "Main thread returning 0\n");
  return 0;
}

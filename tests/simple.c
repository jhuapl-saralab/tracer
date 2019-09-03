/*
 * Copyright (c) 2019, Johns Hopkins University Applied Physics Laboratory
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]){
    int max = atoi(argv[1]);
    int x   = atoi(argv[2]);
    pid_t p0,p1;

    if(x >= max/2){
	printf("%d: exiting\n", getpid());
	return x;
    }
    printf("*** %d test: %d ***\n", getpid(), x);
    if((p0 = fork()) < 0){
	printf("%d: failed to fork process 0: %s\n", getpid(), strerror(errno));
    }else if(p0 == 0){
	char buf_max[10], buf_x[10];
	char *args[4];
	sprintf(buf_max, "%d", max);
	sprintf(buf_x, "%d", 2*x);
	args[0] = argv[0];
	args[1] = buf_max;
	args[2] = buf_x;
	args[3] = NULL;
	printf("%d: exec()\n", getpid());
	execvp(args[0], args);
    }else if((p1 = fork()) < 0){
	printf("%d: failed to fork process 1: %s\n", getpid(), strerror(errno));
    }else if(p1 == 0){
	char buf_max[10], buf_x[10];
	char *args[4];
	sprintf(buf_max, "%d", max);
	sprintf(buf_x, "%d", 2*x+1);
	args[0] = argv[0];
	args[1] = buf_max;
	args[2] = buf_x;
	args[3] = NULL;
	printf("%d: exec()\n", getpid());
	execvp(args[0], args);
    }else{
	while(1){
	    int status;
	    waitpid(p0, &status, 0);
	    if(WIFEXITED(status)){
		printf("%d: reaped child %d (0) exited\n", getpid(), p0);
		    break;
	    }
	}
	while(1){
	    int status;
	    waitpid(p1, &status, 0);
	    if(WIFEXITED(status)){
		printf("%d: reaped child %d (1) exited\n", getpid(), p1);
		break;
	    }
	}
    }
    printf("%d: exiting\n", getpid());
    return 0;
}

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

/* needed for asprintf() function */
#define _GNU_SOURCE

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <syscall.h>
#include <sys/user.h>
#include <sys/signalfd.h>
#include <limits.h>
#include <libgen.h>
#include <sys/uio.h>
#include <regex.h>
#include <ctype.h>
#include "syscalls.h"

static struct option long_options[] = {
    {
	.name		= "verbose",
	.has_arg	= 0,
	.flag		= NULL,
	.val		= 'v'
    },
    {
	.name		= "log",
	.has_arg	= 1,
	.flag		= NULL,
	.val		= 'l'
    },
    {
	.name		= "child-out",
	.has_arg	= 1,
	.flag		= NULL,
	.val		= 'o'
    },
    {
	.name		= "child-error",
	.has_arg	= 1,
	.flag		= NULL,
	.val		= 'e'
    },
    {
	.name           = "no-record-env",
	.has_arg        = 0,
	.flag           = NULL,
	.val            = 'E'
    },
    {
	.name           = "dont-descend",
	.has_arg        = 1,
	.flag           = NULL,
	.val            = 'd'
    },
    {
	.name           = "dont-descend-re",
	.has_arg        = 1,
	.flag           = NULL,
	.val            = 'D'
    },
    {
	.name           = "stream-execs-mode",
	.has_arg        = 0,
	.flag           = NULL,
	.val            = 's'
    },
    {
	.name           = "tracee-error-code",
	.has_arg        = 1,
	.flag           = NULL,
	.val            = 'c'
    },
    {
	.name           = "trace-mmap",
	.has_arg        = 0,
	.flag           = NULL,
	.val            = 'm'
    },
    {0}
};

static char *short_options = "mvl:o:e:d:D:Esc:";
void print_usage(char *progname){
    fprintf(stderr, "Usage: %s [--no-record-env|-E] [--verbose|-v] [--log|-l <file>]\n"
	    "\t[--dont-descend|-d cmd] [--dont-descend-re|-D regex] [--tracee-error-code|-c NUM]\n"
	    "\t[--child-out|-o <file>] [--child-error|-e <file>] [--stream-execs-mode|-s]\n"
	    "\t[--trace-mmap|-m] <tracefile> -- <prog> [args...]\n",
	    progname);
    exit(1);
}


static int verbose = 0;
static int record_process_environments = 1;

static FILE *logfile = NULL;
static FILE *outfile = NULL;
static char **dont_descend_cmds = NULL;
static size_t nr_dont_descends = 0;
static regex_t dont_descend_regex;
static int dont_descend_regex_set = 0;

static int stream_execs_mode = 0;
static int tracee_error_code = 0;
static int trace_mmap = 0;

struct buffer {
    size_t size;
    unsigned char bytes[];
};

struct mmap_rec{
    char *path;
    struct mmap_rec *next;
};

struct rec{
    pid_t pid;
    char *cmd;
    size_t argc;
    char **argv;
    char *cwd;
    char **env;
    size_t nenv;
    int in_syscall;
    int exit_status;
    int exited;

    size_t nr_arg_files;
    struct buffer **arg_files;

    struct mmap_rec *mmaps;

    struct rec *children;
    struct rec *prev_sibling;
    struct rec *next_sibling;
    struct rec *next;
};

int should_descend(struct rec *prec){
    size_t i;
    for(i=0;i<nr_dont_descends;i++){
	if(dont_descend_cmds[i][0] == '/'){
	    if(strcmp(dont_descend_cmds[i], prec->cmd) == 0){
		return 0;
	    }
	}else{
	    char cmdcopy[strlen(prec->cmd)+1];
	    memcpy(cmdcopy, prec->cmd, strlen(prec->cmd)+1);
	    if(strcmp(dont_descend_cmds[i], basename(cmdcopy)) == 0){
		return 0;
	    }
	}
    }
    if(dont_descend_regex_set){
	size_t len = 0;
	for(i=0;i<prec->argc;i++){
	    len += strlen(prec->argv[i])+1;
	}
	char *cmdline = NULL;
        assert(len != 0);
        cmdline = malloc(sizeof(char)*len);
        if (!cmdline) {
            fprintf(logfile, "ERROR: malloc failure, exiting\n");
            exit(1);
        }
	len = 0;
	for(i=0;i<prec->argc;i++){
	    if(i > 0){
		cmdline[len] = ' ';
		len++;
	    }
	    memcpy(&cmdline[len], prec->argv[i], strlen(prec->argv[i])+1);
	    len += strlen(prec->argv[i]);
	}
        int matches = regexec(&dont_descend_regex, cmdline, 0, NULL, 0);
        free(cmdline);
	if(matches == 0){
	    return 0;
	}
    }
    return 1;
}

struct rec **cmd_table = NULL;
size_t nr_cmd_table_ents = 0;
size_t total_cmds = 0;

#define MAX_TABLE_ENTS 65535

void rehash_cmd_table(void){
    if(verbose){
	fprintf(logfile, "Rehashing cmd_table!\n");
    }
    if(nr_cmd_table_ents >= MAX_TABLE_ENTS){
	if(verbose){
	    fprintf(logfile, "\tNever mind...it's already quite large\n");
	}
	return;
    }

    size_t new_nr_ents = 1+(nr_cmd_table_ents * 2);
    struct rec **new_cmd_table = calloc(sizeof(struct rec *), new_nr_ents);
    if(new_cmd_table == NULL){
	fprintf(logfile, "Failed to alloc new_cmd_table of size %zu\n",
		new_nr_ents);
	exit(1);
    }
    size_t i;
    for(i=0;i<nr_cmd_table_ents;i++){
	struct rec *prec = cmd_table[i];
	struct rec *tmp;
	while(prec){
	  size_t new_bucket = ((size_t)prec->pid) % new_nr_ents;
	    tmp = prec->next;
	    prec->next = new_cmd_table[new_bucket];
	    new_cmd_table[new_bucket] = prec;
	    prec = tmp;
	}
    }
    free(cmd_table);
    cmd_table = new_cmd_table;
    nr_cmd_table_ents = new_nr_ents;
}


void free_mmap_recs(struct mmap_rec *mrec){
    while(mrec){
	struct mmap_rec *next = mrec->next;
	free(mrec->path);
	free(mrec);
	mrec = next;
    }
}

void free_rec_internal_fields(struct rec *prec){
    /* Note: this function gets called to free the internal fields of
     * a record for a process doing an `exec()` call, the record
     * itself may get reused so we must leave it in a valid state. We
     * specifically preserve the `mmaps` field since we want to keep
     * track of all executable mappings this process has ever had.
     */

    /*
       Elements of argv reference into the buffer pointed to by
       cmd. We still have to free the array, but not the individual
       elements.
    */
    free(prec->argv);
    free(prec->cmd);

    free(prec->cwd);
    if(prec->env){
	free(prec->env[0]); /* like argv, env[0] points to the buffer
			     * containing all the env variables, and
			     * env[1...] points to offsets in that
			     * buffer */
	free(prec->env);
    }
    if(prec->arg_files){
	for(size_t i = 0;i<prec->nr_arg_files;i++){
	    free(prec->arg_files[i]);
	}
	free(prec->arg_files);
    }
}

void append_child(struct rec *parent, struct rec *new_child){
    if(parent->children){
	struct rec *last_child		= parent->children->prev_sibling;
	struct rec *first_child		= parent->children;
	new_child->prev_sibling		= last_child;
	new_child->next_sibling		= first_child;
	last_child->next_sibling	= new_child;
	first_child->prev_sibling	= new_child;
    }else{
	parent->children = new_child;
	new_child->prev_sibling = new_child;
	new_child->next_sibling = new_child;
    }
}


char low_nibble_hexchar(unsigned char byte){
    byte = (byte & 0x0f);
    return (char) (byte > 9 ? 'A' + (byte - 10) : '0' + byte);
}

char high_nibble_hexchar(unsigned char byte){
    return low_nibble_hexchar(byte >> 4);
}

int escape_bytes(unsigned char *bytes, size_t in_sz, char **out){
    size_t out_sz = in_sz;
    size_t i;
    char *ptr;
    for(i=0;i<in_sz;i++){
	switch(bytes[i]){
	case '"':
	case '\\':
	case '\n':
	case '\t':
	case '\r':
	    out_sz += 1;
	    break;
	default:
	    if(!isprint(bytes[i])){
		out_sz += 3; /* make room for \xAB */
	    }
	}
    }
    *out = malloc((out_sz+1)*sizeof(char));
    if(*out == NULL){
      fprintf(logfile, "Failed to allocate output string!\n");
      exit(-1);
    }
    ptr  = *out;
    for(i=0;i<in_sz;i++){
	switch(bytes[i]){
	case '"':
	case '\\':
	    *ptr	  = '\\';
	    ptr++;
	    *ptr	  = (char)bytes[i];
	    ptr++;
	    break;
	case '\n':
	    *ptr          = '\\';
	    ptr++;
	    *ptr          = 'n';
	    ptr++;
	    break;
	case '\t':
	    *ptr          = '\\';
	    ptr++;
	    *ptr          = 't';
	    ptr++;
	    break;
	case '\r':
	    *ptr          = '\\';
	    ptr++;
	    *ptr          = 'r';
	    ptr++;
	    break;
	default:
	    if(isprint(bytes[i])){
		*ptr        = (char)bytes[i];
		ptr++;
	    }else{
		*ptr = '\\';
		ptr++;
		*ptr = 'x';
		ptr++;
		*ptr = high_nibble_hexchar(bytes[i]);
		ptr++;
		*ptr = low_nibble_hexchar(bytes[i]);
		ptr++;
	    }
	    break;
	}
    }
    (*out)[out_sz] = '\0';

    return 0;
}

int escape_string(char *str, char **out){
    return escape_bytes((unsigned char *)str, strlen(str), out);
}

struct rec *create_rec(struct rec *parent, pid_t pid){
    if(pid < 0){
      fprintf(logfile, "Error: refusing to create record for negative pid value %d\n", pid);
      exit(-1);
    }

    struct rec *res = malloc(sizeof(struct rec));
    if(res == NULL){
	fprintf(logfile, "Failed to allocate record!\n");
	exit(-1);
    }

    res->pid  = pid;
    res->cmd  = NULL;
    res->argc = 0;
    res->argv = NULL;
    res->cwd = NULL;
    res->env = NULL;
    res->nenv = 0;
    res->in_syscall = 0;
    res->exit_status = -1;
    res->exited = 0;
    res->nr_arg_files = 0;
    res->arg_files = NULL;
    res->mmaps = NULL;
    res->children = NULL;

    if((!stream_execs_mode) && (parent != NULL)){
	append_child(parent, res);
    }else{
	res->next_sibling = res;
	res->prev_sibling = res;
    }

    struct rec **cmd_list = &cmd_table[((size_t)pid) % nr_cmd_table_ents];
    res->next = *cmd_list;
    *cmd_list  = res;

    if(total_cmds > SIZE_MAX -1){
	fprintf(logfile, "Error: too many forks to count!\n");
	exit(1);
    }else{
	total_cmds++;
	if(total_cmds > nr_cmd_table_ents * 16){
	    rehash_cmd_table();
	}
    }
    return res;
}

struct rec *find_rec(pid_t p){
    if(p < 0){
	return NULL;
    }
    struct rec *res;
    struct rec *cmd_list = cmd_table[((size_t)p) % nr_cmd_table_ents];

    for(res = cmd_list;res != NULL;res = res->next){
	if(res->pid == p){
	    return res;
	}
    }
    return NULL;
}

void dispose_rec(struct rec *prec){
  struct rec *cmd_list = cmd_table[((size_t)prec->pid) % nr_cmd_table_ents];
    struct rec *ent;
    struct rec *prev = NULL;

    if(verbose){
	fprintf(logfile, "disposing record for pid %d\n", prec->pid);
    }

    for(ent = cmd_list;ent != prec && ent != NULL;ent = ent->next){
	prev = ent;
    }
    if(ent == NULL){
	/* prec wasn't in the chain...nothing to unlink. */
    }else if(prev == NULL){
	cmd_table[((size_t)prec->pid) % nr_cmd_table_ents] = prec->next;
    }else{
	prev->next = prec->next;
    }
    --total_cmds;
    free_mmap_recs(prec->mmaps);
    free_rec_internal_fields(prec);
    free(prec);
}

void print_exit_rec(pid_t p, int exit_status){
    fprintf(outfile, "{\"pid\": %d, \"exit_status\": %d}\n",
	    p, exit_status);
}

void print_recs(struct rec *r, int depth){
    struct rec *c;
    char *escaped = NULL;
    fprintf(outfile, "{\"pid\": %d", r->pid);
    if(r->cmd){
	escape_string(r->cmd, &escaped);
	fprintf(outfile, ", \"cmd\": \"%s\"", escaped);
	free(escaped);
    }

    fprintf(outfile, ", \"args\": [");
    for(size_t i=1;i<r->argc;i++){
	escape_string(r->argv[i], &escaped);
    	fprintf(outfile, "\"%s\"", escaped);
	if(i+1 < r->argc){
	    fprintf(outfile, ", ");
	}
	free(escaped);
	escaped = NULL;
    }
    fputc(']', outfile);

    if(r->cwd) {
	escape_string(r->cwd, &escaped);
	fprintf(outfile, ", \"cwd\": \"%s\"", r->cwd);
	free(escaped);
    }

    if(r->exited){
	fprintf(outfile, ", \"exit_status\": %d", r->exit_status);
    }

    if (r->env) {
	fprintf(outfile, ", \"env\": [ ");
	for (size_t i = 0; i < r->nenv; i++) {
	    escape_string(r->env[i], &escaped);
	    if (i > 0) {
		fprintf(outfile, ", ");
	    }
	    fprintf(outfile, "\"%s\"", escaped);
	    free(escaped);
	}
	fputc(']', outfile);
    }

    if(r->arg_files){
	fprintf(outfile, ", \"arg_files\": [");
	for(size_t i = 0; i < r->nr_arg_files; i++){
	    if(i > 0) {
		fprintf(outfile, ", ");
	    }
	    if(r->arg_files[i] != NULL){
		escape_bytes(r->arg_files[i]->bytes, r->arg_files[i]->size, &escaped);
		fprintf(outfile, "\"%s\"", escaped);
		free(escaped);
	    }else{
		fprintf(outfile, "null");
	    }
	    fputc(']', outfile);
	}
    }
    if(r->mmaps != NULL){
	fprintf(outfile, ", \"mmaps\": [");
	struct mmap_rec *m;
	for(m = r->mmaps;m != NULL;m = m->next){
	    escape_bytes(m->path, strlen(m->path), &escaped);
	    fprintf(outfile, "\"%s\"%s", escaped, m->next ? "," :"");
	    free(escaped);
	}
	fprintf(outfile, "]");
    }

    if((c = r->children) != NULL){
	fprintf(outfile, ", \"children\": [");
	do{
	    fprintf(outfile, "\n");
	    for(int i=0;i<depth+1;i++){fprintf(outfile, "\t");}
	    print_recs(c, depth+1);
	    c = c->next_sibling;
	    if(c != r->children){fputc(',', outfile);}
	}while(c != r->children);
	fputc(']', outfile);
    }
    fputc('}', outfile);
}

int do_child(int argc, char *argv[]) {
    char *args[argc+1];
    memcpy(args, argv, ((unsigned long) argc)*sizeof(char*));
    args[argc] = NULL;
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

void set_ptrace_options(pid_t child){
    if(ptrace(PTRACE_SETOPTIONS, child, 0,
	      PTRACE_O_TRACEFORK |
	      PTRACE_O_TRACEVFORK |
	      PTRACE_O_TRACECLONE |
	      PTRACE_O_TRACESYSGOOD |
	      0) < 0){
    }
}

void detach_from_process(pid_t p){
    /*
       From the ptrace(2) manpage:

       If the tracee is running when the tracer wants to detach it,
       the usual solution is to send SIGSTOP (using tgkill(2), to make
       sure it goes to the correct thread), wait for the tracee to
       stop in signal-delivery-stop for SIGSTOP and then detach it
       (suppressing SIGSTOP injection).  A design bug is that this can
       race with concurrent SIGSTOPs.  Another complication is that
       the tracee may enter other ptrace-stops and needs to be
       restarted and waited for again, until SIGSTOP is seen.  Yet
       another complication is to be sure that the tracee is not
       already ptrace-stopped, because no signal delivery happens
       while it is—not even SIGSTOP.

       We aren't using tgkill (which is a bit sloppy), but it seems to
       work *ok*...
    */
    ptrace(PTRACE_SETOPTIONS, p, 0, 0);
    kill(p, SIGSTOP);
    int stopped = 0;
    int status = 0;
    ptrace(PTRACE_CONT, p, 0, 0);
    while(!stopped){
	waitpid(p, &status, 0);
	if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)){
	    ptrace(PTRACE_DETACH, p, 0, 0);
	    kill(p, SIGCONT);
	    stopped = 1;
	}else if(WIFSTOPPED(p)){
	    ptrace(PTRACE_CONT, p, WSTOPSIG(status), 0);
	}else{
	    ptrace(PTRACE_CONT, p, 0, 0);
	}
    }
}

int read_file(char *cwd, char *infile, struct buffer **outbuf){
    char *infile_abs = infile;
    if(infile[0] != '/'){
	if(asprintf(&infile_abs, "%s/%s", cwd, infile) < 0){
	    fprintf(logfile, "Error: failed to construct absolute filename '%s/%s'\n", cwd, infile);
	    return -1;
	}
    }

    int fd = open(infile_abs, O_RDONLY);

    if(infile_abs != infile){
	free(infile_abs);
    }

    if(fd < 0){
	/* this routine is used to read the contents of files named by
	 * arguments prefixed with an "@", this is a fairly common
	 * idiom and is heavily used by commands that take a lot of
	 * arguments (looking at you `javac`) so we need to do it,
	 * **but** some arguments may be prefixed with an "@" because
	 * that's what the argument is (notably autoconf generated
	 * configure scripts generate makefiles with commands like
	 * `echo "@@@$MAKE@@@@" because they think that sort of thing
	 * is fun).  So, the absence of a file here might not actually
	 * be an error. If the open fails we just return -1 and the
	 * caller sticks a NULL value into the arg_files list, it's up
	 * to the consumer to figure out what went on but at least
	 * they know that for every arg prefixed with "@" there will
	 * be an entry in arg_files.
	 */
	return -1;
    }

    struct stat st;
    /* Using stat to calculate file size isn't safe for virtual files
     * (e.g., in /proc) but since our intended use case is argument
     * files passed to things like `javac` we're going to call this ok
     * enough. Note that unlike in the `open()` case above, if the
     * `stat()` call fails we really do want to print an error since
     * this is no longer expected behavior.
     */
    if(fstat(fd, &st) < 0){
	fprintf(logfile, "Error: Unable to stat file \"%s\": %s\n", infile, strerror(errno));
	close(fd);
	return -1;
    }

    if(st.st_size < 0){
	fprintf(logfile, "Error: reported file size is negative\n");
	close(fd);
	return -1;
    }

    if((*outbuf = malloc(sizeof(struct buffer) + (size_t)st.st_size)) == NULL){
	fprintf(logfile, "Error: Unable to allocate %zd bytes for buffer: %s\n",
		st.st_size, strerror(errno));
	close(fd);
	return -1;
    }

    (*outbuf)->size = st.st_size;
    if((read(fd, &(*outbuf)->bytes, (size_t)st.st_size)) != (size_t)st.st_size){
	fprintf(logfile, "Error: Failed to read file \"%s\": %s\n", infile, strerror(errno));
	free(*outbuf);
	*outbuf = NULL;
	close(fd);
	return -1;
    }
    close(fd);
    return 0;
}

#define MAX_FILENAME_LEN 10000
void set_rec_cwd(struct rec *prec, pid_t p) {
    // /proc/<pid>/cwd is a symlink to the working directory of process <pid>
    char cwd_sl[MAX_FILENAME_LEN];
    char cwd[MAX_FILENAME_LEN];
    // snprintf usage here is fine, %d can't be more than 21 bytes.
    snprintf(cwd_sl, MAX_FILENAME_LEN, "/proc/%d/cwd", p);
    ssize_t bytes_read = readlink(cwd_sl, cwd, MAX_FILENAME_LEN);
    if (bytes_read <= 0) {
      fprintf(logfile, "ERROR: can't read symlink %s\n", cwd_sl);
    }
    if (bytes_read >= MAX_FILENAME_LEN) {
      fprintf(logfile, "Implausible error: filename >= %d characters long. Exiting.\n",
	      MAX_FILENAME_LEN);
      exit(1);
    }
    cwd[bytes_read] = '\0';
    prec->cwd = strdup(cwd);
    if(prec->cwd == NULL){
	fprintf(logfile, "Error: failed to allocate record cwd\n");
	exit(-1);
    }
}

void set_rec_env(struct rec *prec, pid_t p) {
    char filename[MAX_FILENAME_LEN];
    // snprintf usage here is fine, %d can't be more than 21 bytes.
    snprintf(filename, MAX_FILENAME_LEN, "/proc/%d/environ", p);
    FILE* envf = fopen(filename, "r");
    if (!envf) {
	fprintf(logfile, "ERROR: Failed to open file: %s. Errno: %d\n", filename, errno);
	fprintf(logfile, "Process cmd was: %s\n", prec->cmd);
	exit(1);
    }
    size_t bufsize = 1000;
    char* buf = malloc(bufsize*sizeof(char));
    size_t read = 0;
    int c;
    size_t nentries = 0;
    if(buf == NULL){
	fprintf(logfile, "ERROR: Failed to alloc %zd bytes for env file buffer\n", bufsize);
	exit(1);
    }

    while ((c = fgetc(envf)) != EOF) {
	if (read == bufsize) {
	    bufsize = bufsize*2;
	    buf = realloc(buf, bufsize);
	    if(buf == NULL){
		fprintf(logfile, "ERROR: Failed to alloc %zd bytes for env file buffer\n",
			bufsize);
		exit(1);
	    }
	}
	buf[read] = (char)c;
	read++;
	if (c == '\0'){
	    nentries++;
	}
    }

    if (nentries > 0) {
        prec->env = malloc(sizeof(char*)*nentries);
        if(prec->env == NULL){
            fprintf(logfile, "Failed to allocate %zd entries for env array\n", nentries);
            exit(1);
        }
        size_t curEntry = 0;
        size_t curStart = 0;
        while (curEntry < nentries) {
            prec->env[curEntry] = &buf[curStart];


            while(buf[curStart] != '\0'){
                curStart++;
            }
            curStart++;
            curEntry++;
        }
    }else{
	free(buf);
	prec->env = NULL;
    }
    prec->nenv = nentries;

    assert(0 == fclose(envf));
}

void set_rec_cmdline(struct rec *prec, pid_t p){
    char filename[MAX_FILENAME_LEN];
    // snprintf usage here is fine, %d can't be more than 21 bytes.
    snprintf(filename, MAX_FILENAME_LEN, "/proc/%d/cmdline", p);
    FILE *cmdlinef = fopen(filename, "r");
    if(cmdlinef == NULL){
	fprintf(logfile, "Failed to open cmdline file \"%s\": %s", filename, strerror(errno));
	exit(-1);
    }
    size_t bufsize = 128;
    char* buf = malloc(bufsize*sizeof(char));
    size_t read = 0;
    int c;
    size_t nentries = 0;
    if(buf == NULL){
	fprintf(logfile, "ERROR: Failed to alloc %zd bytes for cmdline buffer\n", bufsize);
	exit(1);
    }

    while ((c = fgetc(cmdlinef)) != EOF) {
	if (read == bufsize) {
	    bufsize = bufsize*2;
	    buf = realloc(buf, bufsize);
	    if(buf == NULL){
		fprintf(logfile, "ERROR: Failed to alloc %zd bytes for cmdline buffer\n",
			bufsize);
		exit(1);
	    }
	}
	buf[read] = (char)c;
	read++;
	if (c == '\0'){
	    nentries++;
	}
    }
    if (nentries == 0) {
        fprintf(logfile, "ERROR: saw process %d with empty command-line?! Exiting.\n", p);
        exit(1);
    }
    prec->argv = malloc(sizeof(char*)*nentries);
    if(prec->argv == NULL){
	fprintf(logfile, "Failed to allocate %zd entries for argv array\n", nentries);
	exit(1);
    }

    prec->cmd = buf;
    size_t curEntry = 0;
    size_t curStart = 0;
    while (curEntry < nentries) {
	prec->argv[curEntry] = &buf[curStart];

	while(buf[curStart] != '\0'){
	    curStart++;
	}


	if(prec->argv[curEntry][0] == '@'){
	    prec->nr_arg_files++;
	}

	curStart++;
	curEntry++;
    }
    prec->argc = nentries;
    assert(0 == fclose(cmdlinef));

    if(prec->nr_arg_files > 0){
	prec->arg_files = malloc(sizeof(struct buffer*)*prec->nr_arg_files);
	if(prec->arg_files == NULL){
	    fprintf(logfile, "Failed to allocate %zd entries for arg_files array\n",
		    prec->nr_arg_files);
	    exit(1);
	}
	for(int arg_idx = 0, findex = 0;
	    arg_idx < prec->argc && findex < prec->nr_arg_files;
	    arg_idx++){
	    if(prec->argv[arg_idx][0] == '@'){
		if(read_file(prec->cwd, &prec->argv[arg_idx][1],
			     &prec->arg_files[findex]) < 0){
		    prec->arg_files[findex] = NULL;
		}
		findex++;
	    }
	}
    }
}

int file_in_mmap_list(struct rec *prec, char *filename){
    struct mmap_rec *map = prec->mmaps;
    while(map){
	if(!strcmp(map->path, filename)){
	    return 1;
	}
	map = map->next;
    }
    return 0;
}

void handle_mmap(struct rec *prec){
    if(!trace_mmap){
	return;
    }
    char filename[MAX_FILENAME_LEN];
    // snprintf usage here is fine, %d can't be more than 21 bytes.
    snprintf(filename, MAX_FILENAME_LEN, "/proc/%d/maps", prec->pid);
    FILE *f = fopen(filename, "r");
    if(f == NULL){
	fprintf(logfile, "Error: unable to open maps file '%s'\n", filename);
	return;
    }
    char *path;
    char exe_flag;
    /* This is arguably woefully inefficient. On every call to mmap,
     * we scan through the list of mmap()ed regions in
     * /proc/[pid]/maps and for each entry marked executable we
     * perform a linear search through our list of known mappings to
     * see if we've already recorded it (O(n^2)). But, the number of
     * executable mappings *should* never be too long (on my ubuntu
     * system the largest I see is 203 executable file mappings from
     * gnome-shell, the average is about 30). So I'm calling this ok.
     */
    while(fscanf(f, "%*x-%*x %*c%*c%c%*c %*x %*x:%*x %*d", &exe_flag) == 1){
	char c;
	// skip anonymous maps (no filename) and [heap] [stack]
	while(((c = fgetc(f)) == ' ') || (c == '\t')){
	}
	if(c == '\n'){
	    continue;
	}
	if(c == '['){
	    fscanf(f, "%*s\n");
	    continue;
	}
	ungetc(c, f);
	fscanf(f, "%m[^\n]\n", &path);

	if(!file_in_mmap_list(prec, path)){
	    struct mmap_rec *new_rec = malloc(sizeof(struct mmap_rec));
	    if(new_rec == NULL){
		fprintf(logfile, "Error: failed to allocate new mmap record");
		free(path);
		continue;
	    }
	    if(verbose){
		fprintf(logfile, "\tcreating mmap record for file '%s'\n", path);
	    }
	    new_rec->path = path;
	    new_rec->next = prec->mmaps;
	    prec->mmaps   = new_rec;
	}else{
	    free(path);
	}
    }
    fclose(f);
}

void handle_exec(struct rec *prec){
    pid_t p = prec->pid;


    if(verbose){
	fprintf(logfile, "\tHandling exec for pid %d\n", prec->pid);
    }

    if(prec->cmd != NULL){
	if(verbose){
	    fprintf(logfile, "WARNING: process %d exec()ing more than once.\n", prec->pid);
	}
	free_rec_internal_fields(prec);
    }

    set_rec_cwd(prec, p);
    set_rec_cmdline(prec, p);
    if(record_process_environments){
	set_rec_env(prec, p);
    }

    if(stream_execs_mode){
	print_recs(prec, 1);
	putc('\n', outfile);
	fflush(outfile);
    }
}

void handle_fork_like_event(int status, struct rec *prec){
    unsigned long grandchild;

    if(verbose){
	fprintf(logfile, "\tStopped at a fork-like event (status = %x)\n", status);
    }
    ptrace(PTRACE_GETEVENTMSG, prec->pid, 0, &grandchild);

    if(grandchild > INT_MAX){
	fprintf(logfile, "\tChild pid is greater than max pid!\n");
    }

    struct rec *gc_rec = find_rec((pid_t)grandchild);
    if(gc_rec != NULL){
	if(verbose){
	    fprintf(logfile, "\tFound the child process %ld, associating parent\n", grandchild);
	}
	if(!stream_execs_mode){
	    append_child(prec, gc_rec);
	}
    }else{
	if(verbose){
	    fprintf(logfile, "\tHaven't seen child %ld yet, creating record in anticipation\n", grandchild);
	}

	create_rec(prec, (pid_t)grandchild);
	waitpid((pid_t)grandchild, NULL, 0);
	set_ptrace_options((pid_t)grandchild);
    }
    if(verbose){
	fprintf(logfile, "\tSending PTRACE_SYSCALL to grandchild %ld\n", grandchild);
    }
    ptrace(PTRACE_SYSCALL, grandchild, 0, 0);
}

int do_trace(pid_t child){
    int status;
    pid_t p = child;
    waitpid(p, &status, 0);
    set_ptrace_options(p);
    ptrace(PTRACE_SYSCALL, p, 0, 0);


    while(1){
	p = waitpid(-1, &status, __WALL);
	if(p <= 0) continue;

	if(verbose){
	    fprintf(logfile, "Awoke for pid %d {\n", (int) p);
	}
	struct rec *prec = find_rec(p);

	int send_sig = 0;

	if(prec == NULL){
	    if(verbose){
		fprintf(logfile, "\tPID %d is a new process, creating a record\n", (int)p);
	    }
     	    // we haven't seen this process before. create a record.
	    prec = create_rec(NULL, p);
	    set_ptrace_options(p);
	}

	if(WIFSTOPPED(status)){
	    if(((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) ||
	       ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) ||
	       ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)))){
		handle_fork_like_event(status, prec);
	    } else if((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))){
		if(verbose){
		    fprintf(logfile, "\tReceived PTRACE_EVENT_EXEC...ignoring\n");
		}
	    } else if(WSTOPSIG(status) == (SIGTRAP | 0x80)){
		/* syscall entry */
		struct user_regs_struct regs;
		/* we're not going to worry about 32 vs 64 bit here.
		   All we are doing is looking at rax/eax which should
		   be the same regardless of word size.
		*/
		ptrace(PTRACE_GETREGS, p, NULL, &regs);

	    	if(!prec->in_syscall){
		    if(verbose){
	    		fprintf(logfile, "\tEntering syscall %s. orig_rax: %lld rax: %lld\n",
				syscall_name_from_id((int)regs.orig_rax), regs.orig_rax, regs.rax);
	    	    }
	    	    prec->in_syscall = 1;
	    	}else{
	    	    prec->in_syscall = 0;

	    	    if(verbose){
	    		fprintf(logfile, "\tFinished call to %s. orig_rax: %lld rax: %lld\n",
	    			syscall_name_from_id((int)regs.orig_rax), regs.orig_rax, regs.rax);
	    	    }

	    	    if(regs.orig_rax == SYS_clone){
	    	    }else if(regs.rax == 0 && regs.orig_rax == SYS_execve){
			handle_exec(prec);
			if(!should_descend(prec)){
			    if(verbose){
				fprintf(logfile, "\tNot descending into command %s\n", prec->cmd);
			    }
			    if(stream_execs_mode){
				dispose_rec(prec);
			    }
			    detach_from_process(p);
			    continue;
			}
	    	    }else if(regs.rax > 0 && regs.orig_rax == SYS_mmap){
			handle_mmap(prec);
		    }
	    	}
	    } else if (WSTOPSIG(status) != SIGTRAP){
		if(verbose){
		    fprintf(logfile, "\tProcess got signal %d, sending signal back\n", WSTOPSIG(status));
		}
		send_sig = WSTOPSIG(status);
	    }
	}else if(WIFEXITED(status)){
	    if(verbose){
		fprintf(logfile, "\tProcess terminated with WIFEXITED\n}\n");
	    }
	    struct rec *prec = find_rec(p);
	    if(prec){
		prec->exited = 1;
		prec->exit_status = WEXITSTATUS(status);
	    }
	    if(stream_execs_mode){
		print_exit_rec(p, WEXITSTATUS(status));
		if(prec){
		    dispose_rec(prec);
		}
	    }
	    if(p == child){
		return WEXITSTATUS(status) == 0 ? 0 : tracee_error_code;
	    }
	    continue;
	} else if (WIFSIGNALED(status)) {
	    if(verbose) {
		fprintf(logfile, "\tProcess terminated by signal\n}\n");
	    }
	    struct rec *prec = find_rec(p);
	    if(prec){
		prec->exited = 1;
		prec->exit_status = WTERMSIG(status);
	    }
	    if(stream_execs_mode){
		print_exit_rec(p, WTERMSIG(status));
		if(prec){
		    dispose_rec(prec);
		}
	    }
	    if(p == child){
		return tracee_error_code;
	    }
	    continue;
	} else {
	    if(verbose) {
		fprintf(logfile, "\tUnknown reason for waking? %x\n", status);
	    }
	}

	if(verbose){
	    fprintf(logfile, "}\n");
	}
	ptrace(PTRACE_SYSCALL, p, 0, send_sig);
    }
}

int main(int argc, char *argv[]){
    pid_t p;
    char *child_err = NULL;
    char *child_out = NULL;
    int opt;
    logfile = stderr;

    dont_descend_cmds = calloc(sizeof(char *), (size_t)argc);
    if(dont_descend_cmds == NULL){
	fprintf(stderr, "Failed to alloc \"don't descend list\"\n");
	return -1;
    }

    while((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1){
	switch(opt){
	case 'v': verbose = 1;
	    break;
	case 'l':
	    if(logfile != stderr){
		fclose(logfile);
	    }
	    logfile = fopen(optarg, "w+");
	    if(logfile == NULL){
		fprintf(stderr, "Failed to open log file %s\n", optarg);
		print_usage(argv[0]);
	    }
	    break;
	case 'o': child_out = optarg;
	    break;
	case 'e': child_err = optarg;
	    break;
	case 'E':
	    record_process_environments = 0;
	    break;
	case 'd':
	    dont_descend_cmds[nr_dont_descends] = optarg;
	    nr_dont_descends++;
	    break;
	case 'D':
	    if(dont_descend_regex_set){
		fprintf(stderr, "Warning: dont-descend-re only works once, replacing your old choice...\n");
		regfree(&dont_descend_regex);
		dont_descend_regex_set = 0;
	    }
	    if(regcomp(&dont_descend_regex, optarg, REG_EXTENDED | REG_NOSUB) != 0){
		fprintf(stderr, "Error: failed to compile dont_descend_regex\n");
		print_usage(argv[0]);
	    }
	    dont_descend_regex_set = 1;
	    break;
	case 's':
	    stream_execs_mode = 1;
	    break;
	case 'c':
	    tracee_error_code = atoi(optarg);
	    break;
	case 'm':
	    trace_mmap = 1;
	    break;
	default: print_usage(argv[0]);
	    break;
	}
    }

    nr_cmd_table_ents = 1;
    cmd_table = calloc(sizeof(struct rec *), nr_cmd_table_ents);

    if(argc < optind + 2){
	print_usage(argv[0]);
    }

    if(verbose){
	fprintf(logfile, "trace file: %s\n", argv[optind]);
	fprintf(logfile, "child out: %s\n", child_out ? child_out : "stdout");
	fprintf(logfile, "child err: %s\n", child_err ? child_err : "stderr");
	fprintf(logfile, "cmd: %s", argv[optind+1]);
	int i;
	for(i=optind+2;i<argc;i++){
	    fprintf(logfile, " %s", argv[i]);
	}
	fprintf(logfile, "\n");
    }

    outfile = fopen(argv[optind],"w+");
    if (outfile == NULL) {
        fprintf(stderr, "Failed to open output file: %s; errno %d\n",
		argv[optind], errno);
	print_usage(argv[0]);
    }

    if((p = fork()) == 0){
	if(child_out){
	    int fd = open(child_out, O_WRONLY | O_CREAT, 0644);
	    if((fd < 0) ||
	       (dup2(fd, STDOUT_FILENO) < 0)){
		fprintf(stderr, "Failed to open file \"%s\" for standard output\n", child_out);
		print_usage(argv[0]);
	    }
	    close(fd);
	}
	if(child_err){
	    int fd;
	    if(strcmp(child_err, "&1") == 0){
		fd = STDOUT_FILENO;
	    }else{
		fd = open(child_err, O_WRONLY | O_CREAT, 0644);
	    }
	    if((fd < 0) ||
	       (dup2(fd, STDERR_FILENO) < 0)){
		fprintf(stderr, "Failed to open file \"%s\" for std error\n", child_err);
		print_usage(argv[0]);
	    }
	    if(fd != STDOUT_FILENO){
		close(fd);
	    }
	}
	return do_child(argc-(optind+1), argv+(optind+1));
    }

    struct rec *root = create_rec(NULL, (pid_t)p);
    if(root == NULL){
	fprintf(logfile, "Error creating root record\n");
	exit(-1);
    }

    int rc = do_trace(p);
    if(!stream_execs_mode){
	print_recs(root, 0);
	fputc('\n', outfile);
    }
    fclose(outfile);
    if(logfile != stderr){
	fclose(logfile);
    }
    return rc;
}


/* Local-Variables:	*/
/* mode: c		*/
/* c-basic-offset: 4	*/
/* End:			*/

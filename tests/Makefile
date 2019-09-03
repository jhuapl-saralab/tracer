# Copyright (c) 2019, Johns Hopkins University Applied Physics Laboratory
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

TRACER=../tracer
CWD=`pwd`

all: test-relative-argfile test-absolute-argfile test-nonascii-argfile \
	test-threadhello test-simple

test-relative-argfile:
	$(TRACER) -E -s trace.json -- bash -c "/bin/echo @./arg_file > /dev/null"
	grep -q '"arg_files": \["hello world\\n"\]' trace.json

test-absolute-argfile:
	$(TRACER) -E -s trace.json -- bash -c "/bin/echo @${CWD}/arg_file > /dev/null"
	grep -q '"arg_files": \["hello world\\n"\]' trace.json

test-nonascii-argfile:
	$(TRACER) -E -s trace.json -- bash -c "/bin/echo @../tracer > /dev/null"

test-threadhello:
	$(TRACER) trace.json -- ./threadhello > /dev/null 2>&1

test-simple:
	$(TRACER) trace.json -- ./simple 100 3 >/dev/null 2>&1

threadhello: threadhello.o
	${CC} ${CPPFLAGS} ${CFLAGS} -o threadhello threadhello.o -lpthread

simple: simple.o

%.o : %.c
	${CC} ${CPPFLAGS} ${CFLAGS} -c -o $@ $<

clean:
	rm -f *.o *~ ${OBJS}

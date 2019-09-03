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

#include <syscall.h>

const char* syscall_name_from_id(int syscall) {
      switch(syscall) {

#ifdef SYS_uselib
        case __NR_uselib: return "SYS_uselib"; break;
#endif

#ifdef SYS_clone
        case __NR_clone: return "SYS_clone"; break;
#endif

#ifdef SYS_recvmsg
        case __NR_recvmsg: return "SYS_recvmsg"; break;
#endif

#ifdef SYS_seccomp
        case __NR_seccomp: return "SYS_seccomp"; break;
#endif

#ifdef SYS_nfsservctl
        case __NR_nfsservctl: return "SYS_nfsservctl"; break;
#endif

#ifdef SYS_clock_settime
        case __NR_clock_settime: return "SYS_clock_settime"; break;
#endif

#ifdef SYS_mq_open
        case __NR_mq_open: return "SYS_mq_open"; break;
#endif

#ifdef SYS_lsetxattr
        case __NR_lsetxattr: return "SYS_lsetxattr"; break;
#endif

#ifdef SYS_afs_syscall
        case __NR_afs_syscall: return "SYS_afs_syscall"; break;
#endif

#ifdef SYS_set_thread_area
        case __NR_set_thread_area: return "SYS_set_thread_area"; break;
#endif

#ifdef SYS_prctl
        case __NR_prctl: return "SYS_prctl"; break;
#endif

#ifdef SYS_query_module
        case __NR_query_module: return "SYS_query_module"; break;
#endif

#ifdef SYS_mprotect
        case __NR_mprotect: return "SYS_mprotect"; break;
#endif

#ifdef SYS_rt_sigreturn
        case __NR_rt_sigreturn: return "SYS_rt_sigreturn"; break;
#endif

#ifdef SYS_reboot
        case __NR_reboot: return "SYS_reboot"; break;
#endif

#ifdef SYS_munlockall
        case __NR_munlockall: return "SYS_munlockall"; break;
#endif

#ifdef SYS_add_key
        case __NR_add_key: return "SYS_add_key"; break;
#endif

#ifdef SYS_llistxattr
        case __NR_llistxattr: return "SYS_llistxattr"; break;
#endif

#ifdef SYS_clock_nanosleep
        case __NR_clock_nanosleep: return "SYS_clock_nanosleep"; break;
#endif

#ifdef SYS_mq_unlink
        case __NR_mq_unlink: return "SYS_mq_unlink"; break;
#endif

#ifdef SYS_shmctl
        case __NR_shmctl: return "SYS_shmctl"; break;
#endif

#ifdef SYS_readlink
        case __NR_readlink: return "SYS_readlink"; break;
#endif

#ifdef SYS_open_by_handle_at
        case __NR_open_by_handle_at: return "SYS_open_by_handle_at"; break;
#endif

#ifdef SYS_sched_getaffinity
        case __NR_sched_getaffinity: return "SYS_sched_getaffinity"; break;
#endif

#ifdef SYS_sched_getattr
        case __NR_sched_getattr: return "SYS_sched_getattr"; break;
#endif

#ifdef SYS_epoll_ctl_old
        case __NR_epoll_ctl_old: return "SYS_epoll_ctl_old"; break;
#endif

#ifdef SYS_vhangup
        case __NR_vhangup: return "SYS_vhangup"; break;
#endif

#ifdef SYS_pivot_root
        case __NR_pivot_root: return "SYS_pivot_root"; break;
#endif

#ifdef SYS_execve
        case __NR_execve: return "SYS_execve"; break;
#endif

#ifdef SYS_setxattr
        case __NR_setxattr: return "SYS_setxattr"; break;
#endif

#ifdef SYS_get_robust_list
        case __NR_get_robust_list: return "SYS_get_robust_list"; break;
#endif

#ifdef SYS_signalfd
        case __NR_signalfd: return "SYS_signalfd"; break;
#endif

#ifdef SYS_setns
        case __NR_setns: return "SYS_setns"; break;
#endif

#ifdef SYS_openat
        case __NR_openat: return "SYS_openat"; break;
#endif

#ifdef SYS_creat
        case __NR_creat: return "SYS_creat"; break;
#endif

#ifdef SYS_sched_getparam
        case __NR_sched_getparam: return "SYS_sched_getparam"; break;
#endif

#ifdef SYS_kill
        case __NR_kill: return "SYS_kill"; break;
#endif

#ifdef SYS_timerfd_gettime
        case __NR_timerfd_gettime: return "SYS_timerfd_gettime"; break;
#endif

#ifdef SYS_security
        case __NR_security: return "SYS_security"; break;
#endif

#ifdef SYS_sync_file_range
        case __NR_sync_file_range: return "SYS_sync_file_range"; break;
#endif

#ifdef SYS_mlock
        case __NR_mlock: return "SYS_mlock"; break;
#endif

#ifdef SYS_getdents64
        case __NR_getdents64: return "SYS_getdents64"; break;
#endif

#ifdef SYS_rt_sigpending
        case __NR_rt_sigpending: return "SYS_rt_sigpending"; break;
#endif

#ifdef SYS_mlockall
        case __NR_mlockall: return "SYS_mlockall"; break;
#endif

#ifdef SYS_pause
        case __NR_pause: return "SYS_pause"; break;
#endif

#ifdef SYS_accept
        case __NR_accept: return "SYS_accept"; break;
#endif

#ifdef SYS_set_tid_address
        case __NR_set_tid_address: return "SYS_set_tid_address"; break;
#endif

#ifdef SYS_mkdir
        case __NR_mkdir: return "SYS_mkdir"; break;
#endif

#ifdef SYS_process_vm_readv
        case __NR_process_vm_readv: return "SYS_process_vm_readv"; break;
#endif

#ifdef SYS_munmap
        case __NR_munmap: return "SYS_munmap"; break;
#endif

#ifdef SYS_sched_get_priority_min
        case __NR_sched_get_priority_min: return "SYS_sched_get_priority_min"; break;
#endif

#ifdef SYS_setsockopt
        case __NR_setsockopt: return "SYS_setsockopt"; break;
#endif

#ifdef SYS_getcpu
        case __NR_getcpu: return "SYS_getcpu"; break;
#endif

#ifdef SYS_setsid
        case __NR_setsid: return "SYS_setsid"; break;
#endif

#ifdef SYS_setresgid
        case __NR_setresgid: return "SYS_setresgid"; break;
#endif

#ifdef SYS_sync
        case __NR_sync: return "SYS_sync"; break;
#endif

#ifdef SYS_vfork
        case __NR_vfork: return "SYS_vfork"; break;
#endif

#ifdef SYS_getpmsg
        case __NR_getpmsg: return "SYS_getpmsg"; break;
#endif

#ifdef SYS_tuxcall
        case __NR_tuxcall: return "SYS_tuxcall"; break;
#endif

#ifdef SYS_munlock
        case __NR_munlock: return "SYS_munlock"; break;
#endif

#ifdef SYS_lstat
        case __NR_lstat: return "SYS_lstat"; break;
#endif

#ifdef SYS_lchown
        case __NR_lchown: return "SYS_lchown"; break;
#endif

#ifdef SYS_ustat
        case __NR_ustat: return "SYS_ustat"; break;
#endif

#ifdef SYS_readv
        case __NR_readv: return "SYS_readv"; break;
#endif

#ifdef SYS_stat
        case __NR_stat: return "SYS_stat"; break;
#endif

#ifdef SYS_create_module
        case __NR_create_module: return "SYS_create_module"; break;
#endif

#ifdef SYS_migrate_pages
        case __NR_migrate_pages: return "SYS_migrate_pages"; break;
#endif

#ifdef SYS_rt_sigprocmask
        case __NR_rt_sigprocmask: return "SYS_rt_sigprocmask"; break;
#endif

#ifdef SYS_getresgid
        case __NR_getresgid: return "SYS_getresgid"; break;
#endif

#ifdef SYS_umask
        case __NR_umask: return "SYS_umask"; break;
#endif

#ifdef SYS_io_submit
        case __NR_io_submit: return "SYS_io_submit"; break;
#endif

#ifdef SYS_inotify_init1
        case __NR_inotify_init1: return "SYS_inotify_init1"; break;
#endif

#ifdef SYS_modify_ldt
        case __NR_modify_ldt: return "SYS_modify_ldt"; break;
#endif

#ifdef SYS_dup
        case __NR_dup: return "SYS_dup"; break;
#endif

#ifdef SYS_epoll_create
        case __NR_epoll_create: return "SYS_epoll_create"; break;
#endif

#ifdef SYS_sched_yield
        case __NR_sched_yield: return "SYS_sched_yield"; break;
#endif

#ifdef SYS_eventfd
        case __NR_eventfd: return "SYS_eventfd"; break;
#endif

#ifdef SYS_shmdt
        case __NR_shmdt: return "SYS_shmdt"; break;
#endif

#ifdef SYS_umount2
        case __NR_umount2: return "SYS_umount2"; break;
#endif

#ifdef SYS_symlinkat
        case __NR_symlinkat: return "SYS_symlinkat"; break;
#endif

#ifdef SYS_clock_gettime
        case __NR_clock_gettime: return "SYS_clock_gettime"; break;
#endif

#ifdef SYS_mremap
        case __NR_mremap: return "SYS_mremap"; break;
#endif

#ifdef SYS_renameat
        case __NR_renameat: return "SYS_renameat"; break;
#endif

#ifdef SYS_syncfs
        case __NR_syncfs: return "SYS_syncfs"; break;
#endif

#ifdef SYS_readahead
        case __NR_readahead: return "SYS_readahead"; break;
#endif

#ifdef SYS_finit_module
        case __NR_finit_module: return "SYS_finit_module"; break;
#endif

#ifdef SYS_pipe
        case __NR_pipe: return "SYS_pipe"; break;
#endif

#ifdef SYS_timerfd_create
        case __NR_timerfd_create: return "SYS_timerfd_create"; break;
#endif

#ifdef SYS_rt_sigtimedwait
        case __NR_rt_sigtimedwait: return "SYS_rt_sigtimedwait"; break;
#endif

#ifdef SYS_get_kernel_syms
        case __NR_get_kernel_syms: return "SYS_get_kernel_syms"; break;
#endif

#ifdef SYS_exit
        case __NR_exit: return "SYS_exit"; break;
#endif

#ifdef SYS_set_robust_list
        case __NR_set_robust_list: return "SYS_set_robust_list"; break;
#endif

#ifdef SYS_semtimedop
        case __NR_semtimedop: return "SYS_semtimedop"; break;
#endif

#ifdef SYS_putpmsg
        case __NR_putpmsg: return "SYS_putpmsg"; break;
#endif

#ifdef SYS_getcwd
        case __NR_getcwd: return "SYS_getcwd"; break;
#endif

#ifdef SYS_rt_sigsuspend
        case __NR_rt_sigsuspend: return "SYS_rt_sigsuspend"; break;
#endif

#ifdef SYS_mq_timedreceive
        case __NR_mq_timedreceive: return "SYS_mq_timedreceive"; break;
#endif

#ifdef SYS_getpriority
        case __NR_getpriority: return "SYS_getpriority"; break;
#endif

#ifdef SYS_getppid
        case __NR_getppid: return "SYS_getppid"; break;
#endif

#ifdef SYS_pselect6
        case __NR_pselect6: return "SYS_pselect6"; break;
#endif

#ifdef SYS_clock_adjtime
        case __NR_clock_adjtime: return "SYS_clock_adjtime"; break;
#endif

#ifdef SYS_setuid
        case __NR_setuid: return "SYS_setuid"; break;
#endif

#ifdef SYS_fchmodat
        case __NR_fchmodat: return "SYS_fchmodat"; break;
#endif

#ifdef SYS_inotify_init
        case __NR_inotify_init: return "SYS_inotify_init"; break;
#endif

#ifdef SYS_removexattr
        case __NR_removexattr: return "SYS_removexattr"; break;
#endif

#ifdef SYS_setresuid
        case __NR_setresuid: return "SYS_setresuid"; break;
#endif

#ifdef SYS_getsockopt
        case __NR_getsockopt: return "SYS_getsockopt"; break;
#endif

#ifdef SYS_getgid
        case __NR_getgid: return "SYS_getgid"; break;
#endif

#ifdef SYS_fremovexattr
        case __NR_fremovexattr: return "SYS_fremovexattr"; break;
#endif

#ifdef SYS_getuid
        case __NR_getuid: return "SYS_getuid"; break;
#endif

#ifdef SYS_ppoll
        case __NR_ppoll: return "SYS_ppoll"; break;
#endif

#ifdef SYS_chdir
        case __NR_chdir: return "SYS_chdir"; break;
#endif

#ifdef SYS_ioprio_get
        case __NR_ioprio_get: return "SYS_ioprio_get"; break;
#endif

#ifdef SYS_shmat
        case __NR_shmat: return "SYS_shmat"; break;
#endif

#ifdef SYS_msgrcv
        case __NR_msgrcv: return "SYS_msgrcv"; break;
#endif

#ifdef SYS_setrlimit
        case __NR_setrlimit: return "SYS_setrlimit"; break;
#endif

#ifdef SYS_tkill
        case __NR_tkill: return "SYS_tkill"; break;
#endif

#ifdef SYS_accept4
        case __NR_accept4: return "SYS_accept4"; break;
#endif

#ifdef SYS_inotify_rm_watch
        case __NR_inotify_rm_watch: return "SYS_inotify_rm_watch"; break;
#endif

#ifdef SYS_syslog
        case __NR_syslog: return "SYS_syslog"; break;
#endif

#ifdef SYS_connect
        case __NR_connect: return "SYS_connect"; break;
#endif

#ifdef SYS_swapon
        case __NR_swapon: return "SYS_swapon"; break;
#endif

#ifdef SYS_getresuid
        case __NR_getresuid: return "SYS_getresuid"; break;
#endif

#ifdef SYS_io_setup
        case __NR_io_setup: return "SYS_io_setup"; break;
#endif

#ifdef SYS_personality
        case __NR_personality: return "SYS_personality"; break;
#endif

#ifdef SYS_open
        case __NR_open: return "SYS_open"; break;
#endif

#ifdef SYS_setfsgid
        case __NR_setfsgid: return "SYS_setfsgid"; break;
#endif

#ifdef SYS_fanotify_init
        case __NR_fanotify_init: return "SYS_fanotify_init"; break;
#endif

#ifdef SYS_kcmp
        case __NR_kcmp: return "SYS_kcmp"; break;
#endif

#ifdef SYS_poll
        case __NR_poll: return "SYS_poll"; break;
#endif

#ifdef SYS_adjtimex
        case __NR_adjtimex: return "SYS_adjtimex"; break;
#endif

#ifdef SYS_lremovexattr
        case __NR_lremovexattr: return "SYS_lremovexattr"; break;
#endif

#ifdef SYS_fsync
        case __NR_fsync: return "SYS_fsync"; break;
#endif

#ifdef SYS_clock_getres
        case __NR_clock_getres: return "SYS_clock_getres"; break;
#endif

#ifdef SYS_chown
        case __NR_chown: return "SYS_chown"; break;
#endif

#ifdef SYS_sigaltstack
        case __NR_sigaltstack: return "SYS_sigaltstack"; break;
#endif

#ifdef SYS_truncate
        case __NR_truncate: return "SYS_truncate"; break;
#endif

#ifdef SYS_io_destroy
        case __NR_io_destroy: return "SYS_io_destroy"; break;
#endif

#ifdef SYS_perf_event_open
        case __NR_perf_event_open: return "SYS_perf_event_open"; break;
#endif

#ifdef SYS_mkdirat
        case __NR_mkdirat: return "SYS_mkdirat"; break;
#endif

#ifdef SYS_getxattr
        case __NR_getxattr: return "SYS_getxattr"; break;
#endif

#ifdef SYS_rt_sigqueueinfo
        case __NR_rt_sigqueueinfo: return "SYS_rt_sigqueueinfo"; break;
#endif

#ifdef SYS_semop
        case __NR_semop: return "SYS_semop"; break;
#endif

#ifdef SYS_semctl
        case __NR_semctl: return "SYS_semctl"; break;
#endif

#ifdef SYS_ioctl
        case __NR_ioctl: return "SYS_ioctl"; break;
#endif

#ifdef SYS_io_cancel
        case __NR_io_cancel: return "SYS_io_cancel"; break;
#endif

#ifdef SYS_arch_prctl
        case __NR_arch_prctl: return "SYS_arch_prctl"; break;
#endif

#ifdef SYS_ioprio_set
        case __NR_ioprio_set: return "SYS_ioprio_set"; break;
#endif

#ifdef SYS_fanotify_mark
        case __NR_fanotify_mark: return "SYS_fanotify_mark"; break;
#endif

#ifdef SYS__sysctl
        case __NR__sysctl: return "SYS__sysctl"; break;
#endif

#ifdef SYS_getegid
        case __NR_getegid: return "SYS_getegid"; break;
#endif

#ifdef SYS_sched_rr_get_interval
        case __NR_sched_rr_get_interval: return "SYS_sched_rr_get_interval"; break;
#endif

#ifdef SYS_gettid
        case __NR_gettid: return "SYS_gettid"; break;
#endif

#ifdef SYS_write
        case __NR_write: return "SYS_write"; break;
#endif

#ifdef SYS_getrlimit
        case __NR_getrlimit: return "SYS_getrlimit"; break;
#endif

#ifdef SYS_mq_timedsend
        case __NR_mq_timedsend: return "SYS_mq_timedsend"; break;
#endif

#ifdef SYS_unlink
        case __NR_unlink: return "SYS_unlink"; break;
#endif

#ifdef SYS_sched_setaffinity
        case __NR_sched_setaffinity: return "SYS_sched_setaffinity"; break;
#endif

#ifdef SYS_timer_gettime
        case __NR_timer_gettime: return "SYS_timer_gettime"; break;
#endif

#ifdef SYS_fchdir
        case __NR_fchdir: return "SYS_fchdir"; break;
#endif

#ifdef SYS_signalfd4
        case __NR_signalfd4: return "SYS_signalfd4"; break;
#endif

#ifdef SYS_msgctl
        case __NR_msgctl: return "SYS_msgctl"; break;
#endif

#ifdef SYS_timer_create
        case __NR_timer_create: return "SYS_timer_create"; break;
#endif

#ifdef SYS_waitid
        case __NR_waitid: return "SYS_waitid"; break;
#endif

#ifdef SYS_access
        case __NR_access: return "SYS_access"; break;
#endif

#ifdef SYS_lseek
        case __NR_lseek: return "SYS_lseek"; break;
#endif

#ifdef SYS_keyctl
        case __NR_keyctl: return "SYS_keyctl"; break;
#endif

#ifdef SYS_setitimer
        case __NR_setitimer: return "SYS_setitimer"; break;
#endif

#ifdef SYS_tee
        case __NR_tee: return "SYS_tee"; break;
#endif

#ifdef SYS_restart_syscall
        case __NR_restart_syscall: return "SYS_restart_syscall"; break;
#endif

#ifdef SYS_exit_group
        case __NR_exit_group: return "SYS_exit_group"; break;
#endif

#ifdef SYS_timer_getoverrun
        case __NR_timer_getoverrun: return "SYS_timer_getoverrun"; break;
#endif

#ifdef SYS_sendmmsg
        case __NR_sendmmsg: return "SYS_sendmmsg"; break;
#endif

#ifdef SYS_madvise
        case __NR_madvise: return "SYS_madvise"; break;
#endif

#ifdef SYS_socketpair
        case __NR_socketpair: return "SYS_socketpair"; break;
#endif

#ifdef SYS_fcntl
        case __NR_fcntl: return "SYS_fcntl"; break;
#endif

#ifdef SYS_settimeofday
        case __NR_settimeofday: return "SYS_settimeofday"; break;
#endif

#ifdef SYS_epoll_create1
        case __NR_epoll_create1: return "SYS_epoll_create1"; break;
#endif

#ifdef SYS_timer_settime
        case __NR_timer_settime: return "SYS_timer_settime"; break;
#endif

#ifdef SYS_semget
        case __NR_semget: return "SYS_semget"; break;
#endif

#ifdef SYS_faccessat
        case __NR_faccessat: return "SYS_faccessat"; break;
#endif

#ifdef SYS_delete_module
        case __NR_delete_module: return "SYS_delete_module"; break;
#endif

#ifdef SYS_rmdir
        case __NR_rmdir: return "SYS_rmdir"; break;
#endif

#ifdef SYS_nanosleep
        case __NR_nanosleep: return "SYS_nanosleep"; break;
#endif

#ifdef SYS_read
        case __NR_read: return "SYS_read"; break;
#endif

#ifdef SYS_utime
        case __NR_utime: return "SYS_utime"; break;
#endif

#ifdef SYS_unlinkat
        case __NR_unlinkat: return "SYS_unlinkat"; break;
#endif

#ifdef SYS_fchown
        case __NR_fchown: return "SYS_fchown"; break;
#endif

#ifdef SYS_shmget
        case __NR_shmget: return "SYS_shmget"; break;
#endif

#ifdef SYS_epoll_ctl
        case __NR_epoll_ctl: return "SYS_epoll_ctl"; break;
#endif

#ifdef SYS_sysinfo
        case __NR_sysinfo: return "SYS_sysinfo"; break;
#endif

#ifdef SYS_writev
        case __NR_writev: return "SYS_writev"; break;
#endif

#ifdef SYS_mincore
        case __NR_mincore: return "SYS_mincore"; break;
#endif

#ifdef SYS_utimensat
        case __NR_utimensat: return "SYS_utimensat"; break;
#endif

#ifdef SYS_msgsnd
        case __NR_msgsnd: return "SYS_msgsnd"; break;
#endif

#ifdef SYS_remap_file_pages
        case __NR_remap_file_pages: return "SYS_remap_file_pages"; break;
#endif

#ifdef SYS_name_to_handle_at
        case __NR_name_to_handle_at: return "SYS_name_to_handle_at"; break;
#endif

#ifdef SYS_set_mempolicy
        case __NR_set_mempolicy: return "SYS_set_mempolicy"; break;
#endif

#ifdef SYS_fork
        case __NR_fork: return "SYS_fork"; break;
#endif

#ifdef SYS_mknod
        case __NR_mknod: return "SYS_mknod"; break;
#endif

#ifdef SYS_time
        case __NR_time: return "SYS_time"; break;
#endif

#ifdef SYS_acct
        case __NR_acct: return "SYS_acct"; break;
#endif

#ifdef SYS_pwritev
        case __NR_pwritev: return "SYS_pwritev"; break;
#endif

#ifdef SYS_msgget
        case __NR_msgget: return "SYS_msgget"; break;
#endif

#ifdef SYS_bind
        case __NR_bind: return "SYS_bind"; break;
#endif

#ifdef SYS_times
        case __NR_times: return "SYS_times"; break;
#endif

#ifdef SYS_fstatfs
        case __NR_fstatfs: return "SYS_fstatfs"; break;
#endif

#ifdef SYS_lgetxattr
        case __NR_lgetxattr: return "SYS_lgetxattr"; break;
#endif

#ifdef SYS_rt_tgsigqueueinfo
        case __NR_rt_tgsigqueueinfo: return "SYS_rt_tgsigqueueinfo"; break;
#endif

#ifdef SYS_recvfrom
        case __NR_recvfrom: return "SYS_recvfrom"; break;
#endif

#ifdef SYS_rt_sigaction
        case __NR_rt_sigaction: return "SYS_rt_sigaction"; break;
#endif

#ifdef SYS_shutdown
        case __NR_shutdown: return "SYS_shutdown"; break;
#endif

#ifdef SYS_setreuid
        case __NR_setreuid: return "SYS_setreuid"; break;
#endif

#ifdef SYS_renameat2
        case __NR_renameat2: return "SYS_renameat2"; break;
#endif

#ifdef SYS_close
        case __NR_close: return "SYS_close"; break;
#endif

#ifdef SYS_getsockname
        case __NR_getsockname: return "SYS_getsockname"; break;
#endif

#ifdef SYS_splice
        case __NR_splice: return "SYS_splice"; break;
#endif

#ifdef SYS_sched_setattr
        case __NR_sched_setattr: return "SYS_sched_setattr"; break;
#endif

#ifdef SYS_select
        case __NR_select: return "SYS_select"; break;
#endif

#ifdef SYS_mount
        case __NR_mount: return "SYS_mount"; break;
#endif

#ifdef SYS_sched_getscheduler
        case __NR_sched_getscheduler: return "SYS_sched_getscheduler"; break;
#endif

#ifdef SYS_sethostname
        case __NR_sethostname: return "SYS_sethostname"; break;
#endif

#ifdef SYS_msync
        case __NR_msync: return "SYS_msync"; break;
#endif

#ifdef SYS_capget
        case __NR_capget: return "SYS_capget"; break;
#endif

#ifdef SYS_getpgid
        case __NR_getpgid: return "SYS_getpgid"; break;
#endif

#ifdef SYS_get_mempolicy
        case __NR_get_mempolicy: return "SYS_get_mempolicy"; break;
#endif

#ifdef SYS_kexec_load
        case __NR_kexec_load: return "SYS_kexec_load"; break;
#endif

#ifdef SYS_dup3
        case __NR_dup3: return "SYS_dup3"; break;
#endif

#ifdef SYS_dup2
        case __NR_dup2: return "SYS_dup2"; break;
#endif

#ifdef SYS_mq_getsetattr
        case __NR_mq_getsetattr: return "SYS_mq_getsetattr"; break;
#endif

#ifdef SYS_fsetxattr
        case __NR_fsetxattr: return "SYS_fsetxattr"; break;
#endif

#ifdef SYS_request_key
        case __NR_request_key: return "SYS_request_key"; break;
#endif

#ifdef SYS_epoll_wait_old
        case __NR_epoll_wait_old: return "SYS_epoll_wait_old"; break;
#endif

#ifdef SYS_preadv
        case __NR_preadv: return "SYS_preadv"; break;
#endif

#ifdef SYS_readlinkat
        case __NR_readlinkat: return "SYS_readlinkat"; break;
#endif

#ifdef SYS_unshare
        case __NR_unshare: return "SYS_unshare"; break;
#endif

#ifdef SYS_prlimit64
        case __NR_prlimit64: return "SYS_prlimit64"; break;
#endif

#ifdef SYS_timerfd_settime
        case __NR_timerfd_settime: return "SYS_timerfd_settime"; break;
#endif

#ifdef SYS_getpgrp
        case __NR_getpgrp: return "SYS_getpgrp"; break;
#endif

#ifdef SYS_setpriority
        case __NR_setpriority: return "SYS_setpriority"; break;
#endif

#ifdef SYS_sendmsg
        case __NR_sendmsg: return "SYS_sendmsg"; break;
#endif

#ifdef SYS_chmod
        case __NR_chmod: return "SYS_chmod"; break;
#endif

#ifdef SYS_listen
        case __NR_listen: return "SYS_listen"; break;
#endif

#ifdef SYS_process_vm_writev
        case __NR_process_vm_writev: return "SYS_process_vm_writev"; break;
#endif

#ifdef SYS_vserver
        case __NR_vserver: return "SYS_vserver"; break;
#endif

#ifdef SYS_geteuid
        case __NR_geteuid: return "SYS_geteuid"; break;
#endif

#ifdef SYS_mq_notify
        case __NR_mq_notify: return "SYS_mq_notify"; break;
#endif

#ifdef SYS_getsid
        case __NR_getsid: return "SYS_getsid"; break;
#endif

#ifdef SYS_lookup_dcookie
        case __NR_lookup_dcookie: return "SYS_lookup_dcookie"; break;
#endif

#ifdef SYS_utimes
        case __NR_utimes: return "SYS_utimes"; break;
#endif

#ifdef SYS_alarm
        case __NR_alarm: return "SYS_alarm"; break;
#endif

#ifdef SYS_sendto
        case __NR_sendto: return "SYS_sendto"; break;
#endif

#ifdef SYS_linkat
        case __NR_linkat: return "SYS_linkat"; break;
#endif

#ifdef SYS_brk
        case __NR_brk: return "SYS_brk"; break;
#endif

#ifdef SYS_flock
        case __NR_flock: return "SYS_flock"; break;
#endif

#ifdef SYS_vmsplice
        case __NR_vmsplice: return "SYS_vmsplice"; break;
#endif

#ifdef SYS_setgid
        case __NR_setgid: return "SYS_setgid"; break;
#endif

#ifdef SYS_fchownat
        case __NR_fchownat: return "SYS_fchownat"; break;
#endif

#ifdef SYS_ftruncate
        case __NR_ftruncate: return "SYS_ftruncate"; break;
#endif

#ifdef SYS_setdomainname
        case __NR_setdomainname: return "SYS_setdomainname"; break;
#endif

#ifdef SYS_getgroups
        case __NR_getgroups: return "SYS_getgroups"; break;
#endif

#ifdef SYS_fadvise64
        case __NR_fadvise64: return "SYS_fadvise64"; break;
#endif

#ifdef SYS_pread64
        case __NR_pread64: return "SYS_pread64"; break;
#endif

#ifdef SYS_flistxattr
        case __NR_flistxattr: return "SYS_flistxattr"; break;
#endif

#ifdef SYS_link
        case __NR_link: return "SYS_link"; break;
#endif

#ifdef SYS_init_module
        case __NR_init_module: return "SYS_init_module"; break;
#endif

#ifdef SYS_newfstatat
        case __NR_newfstatat: return "SYS_newfstatat"; break;
#endif

#ifdef SYS_get_thread_area
        case __NR_get_thread_area: return "SYS_get_thread_area"; break;
#endif

#ifdef SYS_chroot
        case __NR_chroot: return "SYS_chroot"; break;
#endif

#ifdef SYS_eventfd2
        case __NR_eventfd2: return "SYS_eventfd2"; break;
#endif

#ifdef SYS_futimesat
        case __NR_futimesat: return "SYS_futimesat"; break;
#endif

#ifdef SYS_capset
        case __NR_capset: return "SYS_capset"; break;
#endif

#ifdef SYS_rename
        case __NR_rename: return "SYS_rename"; break;
#endif

#ifdef SYS_setgroups
        case __NR_setgroups: return "SYS_setgroups"; break;
#endif

#ifdef SYS_wait4
        case __NR_wait4: return "SYS_wait4"; break;
#endif

#ifdef SYS_statfs
        case __NR_statfs: return "SYS_statfs"; break;
#endif

#ifdef SYS_io_getevents
        case __NR_io_getevents: return "SYS_io_getevents"; break;
#endif

#ifdef SYS_setfsuid
        case __NR_setfsuid: return "SYS_setfsuid"; break;
#endif

#ifdef SYS_fstat
        case __NR_fstat: return "SYS_fstat"; break;
#endif

#ifdef SYS_getrusage
        case __NR_getrusage: return "SYS_getrusage"; break;
#endif

#ifdef SYS_sysfs
        case __NR_sysfs: return "SYS_sysfs"; break;
#endif

#ifdef SYS_ioperm
        case __NR_ioperm: return "SYS_ioperm"; break;
#endif

#ifdef SYS_sched_setscheduler
        case __NR_sched_setscheduler: return "SYS_sched_setscheduler"; break;
#endif

#ifdef SYS_getdents
        case __NR_getdents: return "SYS_getdents"; break;
#endif

#ifdef SYS_mknodat
        case __NR_mknodat: return "SYS_mknodat"; break;
#endif

#ifdef SYS_uname
        case __NR_uname: return "SYS_uname"; break;
#endif

#ifdef SYS_sendfile
        case __NR_sendfile: return "SYS_sendfile"; break;
#endif

#ifdef SYS_fgetxattr
        case __NR_fgetxattr: return "SYS_fgetxattr"; break;
#endif

#ifdef SYS_pipe2
        case __NR_pipe2: return "SYS_pipe2"; break;
#endif

#ifdef SYS_listxattr
        case __NR_listxattr: return "SYS_listxattr"; break;
#endif

#ifdef SYS_quotactl
        case __NR_quotactl: return "SYS_quotactl"; break;
#endif

#ifdef SYS_getitimer
        case __NR_getitimer: return "SYS_getitimer"; break;
#endif

#ifdef SYS_futex
        case __NR_futex: return "SYS_futex"; break;
#endif

#ifdef SYS_tgkill
        case __NR_tgkill: return "SYS_tgkill"; break;
#endif

#ifdef SYS_inotify_add_watch
        case __NR_inotify_add_watch: return "SYS_inotify_add_watch"; break;
#endif

#ifdef SYS_setpgid
        case __NR_setpgid: return "SYS_setpgid"; break;
#endif

#ifdef SYS_sched_get_priority_max
        case __NR_sched_get_priority_max: return "SYS_sched_get_priority_max"; break;
#endif

#ifdef SYS_pwrite64
        case __NR_pwrite64: return "SYS_pwrite64"; break;
#endif

#ifdef SYS_socket
        case __NR_socket: return "SYS_socket"; break;
#endif

#ifdef SYS_setregid
        case __NR_setregid: return "SYS_setregid"; break;
#endif

#ifdef SYS_epoll_wait
        case __NR_epoll_wait: return "SYS_epoll_wait"; break;
#endif

#ifdef SYS_mmap
        case __NR_mmap: return "SYS_mmap"; break;
#endif

#ifdef SYS_ptrace
        case __NR_ptrace: return "SYS_ptrace"; break;
#endif

#ifdef SYS_gettimeofday
        case __NR_gettimeofday: return "SYS_gettimeofday"; break;
#endif

#ifdef SYS_fallocate
        case __NR_fallocate: return "SYS_fallocate"; break;
#endif

#ifdef SYS_swapoff
        case __NR_swapoff: return "SYS_swapoff"; break;
#endif

#ifdef SYS_iopl
        case __NR_iopl: return "SYS_iopl"; break;
#endif

#ifdef SYS_getpeername
        case __NR_getpeername: return "SYS_getpeername"; break;
#endif

#ifdef SYS_recvmmsg
        case __NR_recvmmsg: return "SYS_recvmmsg"; break;
#endif

#ifdef SYS_symlink
        case __NR_symlink: return "SYS_symlink"; break;
#endif

#ifdef SYS_fchmod
        case __NR_fchmod: return "SYS_fchmod"; break;
#endif

#ifdef SYS_getpid
        case __NR_getpid: return "SYS_getpid"; break;
#endif

#ifdef SYS_epoll_pwait
        case __NR_epoll_pwait: return "SYS_epoll_pwait"; break;
#endif

#ifdef SYS_move_pages
        case __NR_move_pages: return "SYS_move_pages"; break;
#endif

#ifdef SYS_mbind
        case __NR_mbind: return "SYS_mbind"; break;
#endif

#ifdef SYS_sched_setparam
        case __NR_sched_setparam: return "SYS_sched_setparam"; break;
#endif

#ifdef SYS_fdatasync
        case __NR_fdatasync: return "SYS_fdatasync"; break;
#endif

#ifdef SYS_timer_delete
        case __NR_timer_delete: return "SYS_timer_delete"; break;
#endif

        default: return "UNKNOWN"; break;
    }
}

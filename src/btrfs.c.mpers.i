typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;
typedef __int8_t __int_least8_t;
typedef __uint8_t __uint_least8_t;
typedef __int16_t __int_least16_t;
typedef __uint16_t __uint_least16_t;
typedef __int32_t __int_least32_t;
typedef __uint32_t __uint_least32_t;
typedef __int64_t __int_least64_t;
typedef __uint64_t __uint_least64_t;
typedef long int __quad_t;
typedef unsigned long int __u_quad_t;
typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;
typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;
typedef int __daddr_t;
typedef int __key_t;
typedef int __clockid_t;
typedef void * __timer_t;
typedef long int __blksize_t;
typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;
typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;
typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;
typedef long int __fsword_t;
typedef long int __ssize_t;
typedef long int __syscall_slong_t;
typedef unsigned long int __syscall_ulong_t;
typedef __off64_t __loff_t;
typedef char *__caddr_t;
typedef long int __intptr_t;
typedef unsigned int __socklen_t;
typedef int __sig_atomic_t;
typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;
typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
typedef __int_least8_t int_least8_t;
typedef __int_least16_t int_least16_t;
typedef __int_least32_t int_least32_t;
typedef __int_least64_t int_least64_t;
typedef __uint_least8_t uint_least8_t;
typedef __uint_least16_t uint_least16_t;
typedef __uint_least32_t uint_least32_t;
typedef __uint_least64_t uint_least64_t;
typedef signed char int_fast8_t;
typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
typedef unsigned char uint_fast8_t;
typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
typedef long int intptr_t;
typedef unsigned long int uintptr_t;
typedef __intmax_t intmax_t;
typedef __uintmax_t uintmax_t;
typedef int __gwchar_t;

typedef struct
  {
    long int quot;
    long int rem;
  } imaxdiv_t;
extern intmax_t imaxabs (intmax_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern imaxdiv_t imaxdiv (intmax_t __numer, intmax_t __denom)
      __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern intmax_t strtoimax (const char *__restrict __nptr,
      char **__restrict __endptr, int __base) __attribute__ ((__nothrow__ , __leaf__));
extern uintmax_t strtoumax (const char *__restrict __nptr,
       char ** __restrict __endptr, int __base) __attribute__ ((__nothrow__ , __leaf__));
extern intmax_t wcstoimax (const __gwchar_t *__restrict __nptr,
      __gwchar_t **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__));
extern uintmax_t wcstoumax (const __gwchar_t *__restrict __nptr,
       __gwchar_t ** __restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__));


typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
typedef __loff_t loff_t;
typedef __ino_t ino_t;
typedef __ino64_t ino64_t;
typedef __dev_t dev_t;
typedef __gid_t gid_t;
typedef __mode_t mode_t;
typedef __nlink_t nlink_t;
typedef __uid_t uid_t;
typedef __off_t off_t;
typedef __off64_t off64_t;
typedef __pid_t pid_t;
typedef __id_t id_t;
typedef __ssize_t ssize_t;
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
typedef __key_t key_t;
typedef __clock_t clock_t;
typedef __clockid_t clockid_t;
typedef __time_t time_t;
typedef __timer_t timer_t;
typedef __useconds_t useconds_t;
typedef __suseconds_t suseconds_t;
typedef long unsigned int size_t;
typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;
typedef __uint8_t u_int8_t;
typedef __uint16_t u_int16_t;
typedef __uint32_t u_int32_t;
typedef __uint64_t u_int64_t;
typedef int register_t __attribute__ ((__mode__ (__word__)));
static __inline __uint16_t
__bswap_16 (__uint16_t __bsx)
{
  return __builtin_bswap16 (__bsx);
}
static __inline __uint32_t
__bswap_32 (__uint32_t __bsx)
{
  return __builtin_bswap32 (__bsx);
}
__extension__ static __inline __uint64_t
__bswap_64 (__uint64_t __bsx)
{
  return __builtin_bswap64 (__bsx);
}
static __inline __uint16_t
__uint16_identity (__uint16_t __x)
{
  return __x;
}
static __inline __uint32_t
__uint32_identity (__uint32_t __x)
{
  return __x;
}
static __inline __uint64_t
__uint64_identity (__uint64_t __x)
{
  return __x;
}
typedef struct
{
  unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
} __sigset_t;
typedef __sigset_t sigset_t;
struct timeval
{
  __time_t tv_sec;
  __suseconds_t tv_usec;
};
struct timespec
{
  __time_t tv_sec;
  __syscall_slong_t tv_nsec;
};
typedef long int __fd_mask;
typedef struct
  {
    __fd_mask fds_bits[1024 / (8 * (int) sizeof (__fd_mask))];
  } fd_set;
typedef __fd_mask fd_mask;

extern int select (int __nfds, fd_set *__restrict __readfds,
     fd_set *__restrict __writefds,
     fd_set *__restrict __exceptfds,
     struct timeval *__restrict __timeout);
extern int pselect (int __nfds, fd_set *__restrict __readfds,
      fd_set *__restrict __writefds,
      fd_set *__restrict __exceptfds,
      const struct timespec *__restrict __timeout,
      const __sigset_t *__restrict __sigmask);

typedef __blksize_t blksize_t;
typedef __blkcnt_t blkcnt_t;
typedef __fsblkcnt_t fsblkcnt_t;
typedef __fsfilcnt_t fsfilcnt_t;
typedef __blkcnt64_t blkcnt64_t;
typedef __fsblkcnt64_t fsblkcnt64_t;
typedef __fsfilcnt64_t fsfilcnt64_t;
typedef struct __pthread_internal_list
{
  struct __pthread_internal_list *__prev;
  struct __pthread_internal_list *__next;
} __pthread_list_t;
typedef struct __pthread_internal_slist
{
  struct __pthread_internal_slist *__next;
} __pthread_slist_t;
struct __pthread_mutex_s
{
  int __lock;
  unsigned int __count;
  int __owner;
  unsigned int __nusers;
  int __kind;
  short __spins;
  short __elision;
  __pthread_list_t __list;
};
struct __pthread_rwlock_arch_t
{
  unsigned int __readers;
  unsigned int __writers;
  unsigned int __wrphase_futex;
  unsigned int __writers_futex;
  unsigned int __pad3;
  unsigned int __pad4;
  int __cur_writer;
  int __shared;
  signed char __rwelision;
  unsigned char __pad1[7];
  unsigned long int __pad2;
  unsigned int __flags;
};
struct __pthread_cond_s
{
  __extension__ union
  {
    __extension__ unsigned long long int __wseq;
    struct
    {
      unsigned int __low;
      unsigned int __high;
    } __wseq32;
  };
  __extension__ union
  {
    __extension__ unsigned long long int __g1_start;
    struct
    {
      unsigned int __low;
      unsigned int __high;
    } __g1_start32;
  };
  unsigned int __g_refs[2] ;
  unsigned int __g_size[2];
  unsigned int __g1_orig_size;
  unsigned int __wrefs;
  unsigned int __g_signals[2];
};
typedef unsigned long int pthread_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_mutexattr_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_condattr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;
union pthread_attr_t
{
  char __size[56];
  long int __align;
};
typedef union pthread_attr_t pthread_attr_t;
typedef union
{
  struct __pthread_mutex_s __data;
  char __size[40];
  long int __align;
} pthread_mutex_t;
typedef union
{
  struct __pthread_cond_s __data;
  char __size[48];
  __extension__ long long int __align;
} pthread_cond_t;
typedef union
{
  struct __pthread_rwlock_arch_t __data;
  char __size[56];
  long int __align;
} pthread_rwlock_t;
typedef union
{
  char __size[8];
  long int __align;
} pthread_rwlockattr_t;
typedef volatile int pthread_spinlock_t;
typedef union
{
  char __size[32];
  long int __align;
} pthread_barrier_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_barrierattr_t;

typedef long int ptrdiff_t;
typedef int wchar_t;
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;

typedef __socklen_t socklen_t;
extern int access (const char *__name, int __type) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int euidaccess (const char *__name, int __type)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int eaccess (const char *__name, int __type)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int faccessat (int __fd, const char *__file, int __type, int __flag)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2))) ;
extern __off_t lseek (int __fd, __off_t __offset, int __whence) __attribute__ ((__nothrow__ , __leaf__));
extern __off64_t lseek64 (int __fd, __off64_t __offset, int __whence)
     __attribute__ ((__nothrow__ , __leaf__));
extern int close (int __fd);
extern ssize_t read (int __fd, void *__buf, size_t __nbytes) ;
extern ssize_t write (int __fd, const void *__buf, size_t __n) ;
extern ssize_t pread (int __fd, void *__buf, size_t __nbytes,
        __off_t __offset) ;
extern ssize_t pwrite (int __fd, const void *__buf, size_t __n,
         __off_t __offset) ;
extern ssize_t pread64 (int __fd, void *__buf, size_t __nbytes,
   __off64_t __offset) ;
extern ssize_t pwrite64 (int __fd, const void *__buf, size_t __n,
    __off64_t __offset) ;
extern int pipe (int __pipedes[2]) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int pipe2 (int __pipedes[2], int __flags) __attribute__ ((__nothrow__ , __leaf__)) ;
extern unsigned int alarm (unsigned int __seconds) __attribute__ ((__nothrow__ , __leaf__));
extern unsigned int sleep (unsigned int __seconds);
extern __useconds_t ualarm (__useconds_t __value, __useconds_t __interval)
     __attribute__ ((__nothrow__ , __leaf__));
extern int usleep (__useconds_t __useconds);
extern int pause (void);
extern int chown (const char *__file, __uid_t __owner, __gid_t __group)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int fchown (int __fd, __uid_t __owner, __gid_t __group) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int lchown (const char *__file, __uid_t __owner, __gid_t __group)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int fchownat (int __fd, const char *__file, __uid_t __owner,
       __gid_t __group, int __flag)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2))) ;
extern int chdir (const char *__path) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int fchdir (int __fd) __attribute__ ((__nothrow__ , __leaf__)) ;
extern char *getcwd (char *__buf, size_t __size) __attribute__ ((__nothrow__ , __leaf__)) ;
extern char *get_current_dir_name (void) __attribute__ ((__nothrow__ , __leaf__));
extern char *getwd (char *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__deprecated__)) ;
extern int dup (int __fd) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int dup2 (int __fd, int __fd2) __attribute__ ((__nothrow__ , __leaf__));
extern int dup3 (int __fd, int __fd2, int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern char **__environ;
extern char **environ;
extern int execve (const char *__path, char *const __argv[],
     char *const __envp[]) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int fexecve (int __fd, char *const __argv[], char *const __envp[])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int execv (const char *__path, char *const __argv[])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int execle (const char *__path, const char *__arg, ...)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int execl (const char *__path, const char *__arg, ...)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int execvp (const char *__file, char *const __argv[])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int execlp (const char *__file, const char *__arg, ...)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int execvpe (const char *__file, char *const __argv[],
      char *const __envp[])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int nice (int __inc) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void _exit (int __status) __attribute__ ((__noreturn__));
enum
  {
    _PC_LINK_MAX,
    _PC_MAX_CANON,
    _PC_MAX_INPUT,
    _PC_NAME_MAX,
    _PC_PATH_MAX,
    _PC_PIPE_BUF,
    _PC_CHOWN_RESTRICTED,
    _PC_NO_TRUNC,
    _PC_VDISABLE,
    _PC_SYNC_IO,
    _PC_ASYNC_IO,
    _PC_PRIO_IO,
    _PC_SOCK_MAXBUF,
    _PC_FILESIZEBITS,
    _PC_REC_INCR_XFER_SIZE,
    _PC_REC_MAX_XFER_SIZE,
    _PC_REC_MIN_XFER_SIZE,
    _PC_REC_XFER_ALIGN,
    _PC_ALLOC_SIZE_MIN,
    _PC_SYMLINK_MAX,
    _PC_2_SYMLINKS
  };
enum
  {
    _SC_ARG_MAX,
    _SC_CHILD_MAX,
    _SC_CLK_TCK,
    _SC_NGROUPS_MAX,
    _SC_OPEN_MAX,
    _SC_STREAM_MAX,
    _SC_TZNAME_MAX,
    _SC_JOB_CONTROL,
    _SC_SAVED_IDS,
    _SC_REALTIME_SIGNALS,
    _SC_PRIORITY_SCHEDULING,
    _SC_TIMERS,
    _SC_ASYNCHRONOUS_IO,
    _SC_PRIORITIZED_IO,
    _SC_SYNCHRONIZED_IO,
    _SC_FSYNC,
    _SC_MAPPED_FILES,
    _SC_MEMLOCK,
    _SC_MEMLOCK_RANGE,
    _SC_MEMORY_PROTECTION,
    _SC_MESSAGE_PASSING,
    _SC_SEMAPHORES,
    _SC_SHARED_MEMORY_OBJECTS,
    _SC_AIO_LISTIO_MAX,
    _SC_AIO_MAX,
    _SC_AIO_PRIO_DELTA_MAX,
    _SC_DELAYTIMER_MAX,
    _SC_MQ_OPEN_MAX,
    _SC_MQ_PRIO_MAX,
    _SC_VERSION,
    _SC_PAGESIZE,
    _SC_RTSIG_MAX,
    _SC_SEM_NSEMS_MAX,
    _SC_SEM_VALUE_MAX,
    _SC_SIGQUEUE_MAX,
    _SC_TIMER_MAX,
    _SC_BC_BASE_MAX,
    _SC_BC_DIM_MAX,
    _SC_BC_SCALE_MAX,
    _SC_BC_STRING_MAX,
    _SC_COLL_WEIGHTS_MAX,
    _SC_EQUIV_CLASS_MAX,
    _SC_EXPR_NEST_MAX,
    _SC_LINE_MAX,
    _SC_RE_DUP_MAX,
    _SC_CHARCLASS_NAME_MAX,
    _SC_2_VERSION,
    _SC_2_C_BIND,
    _SC_2_C_DEV,
    _SC_2_FORT_DEV,
    _SC_2_FORT_RUN,
    _SC_2_SW_DEV,
    _SC_2_LOCALEDEF,
    _SC_PII,
    _SC_PII_XTI,
    _SC_PII_SOCKET,
    _SC_PII_INTERNET,
    _SC_PII_OSI,
    _SC_POLL,
    _SC_SELECT,
    _SC_UIO_MAXIOV,
    _SC_IOV_MAX = _SC_UIO_MAXIOV,
    _SC_PII_INTERNET_STREAM,
    _SC_PII_INTERNET_DGRAM,
    _SC_PII_OSI_COTS,
    _SC_PII_OSI_CLTS,
    _SC_PII_OSI_M,
    _SC_T_IOV_MAX,
    _SC_THREADS,
    _SC_THREAD_SAFE_FUNCTIONS,
    _SC_GETGR_R_SIZE_MAX,
    _SC_GETPW_R_SIZE_MAX,
    _SC_LOGIN_NAME_MAX,
    _SC_TTY_NAME_MAX,
    _SC_THREAD_DESTRUCTOR_ITERATIONS,
    _SC_THREAD_KEYS_MAX,
    _SC_THREAD_STACK_MIN,
    _SC_THREAD_THREADS_MAX,
    _SC_THREAD_ATTR_STACKADDR,
    _SC_THREAD_ATTR_STACKSIZE,
    _SC_THREAD_PRIORITY_SCHEDULING,
    _SC_THREAD_PRIO_INHERIT,
    _SC_THREAD_PRIO_PROTECT,
    _SC_THREAD_PROCESS_SHARED,
    _SC_NPROCESSORS_CONF,
    _SC_NPROCESSORS_ONLN,
    _SC_PHYS_PAGES,
    _SC_AVPHYS_PAGES,
    _SC_ATEXIT_MAX,
    _SC_PASS_MAX,
    _SC_XOPEN_VERSION,
    _SC_XOPEN_XCU_VERSION,
    _SC_XOPEN_UNIX,
    _SC_XOPEN_CRYPT,
    _SC_XOPEN_ENH_I18N,
    _SC_XOPEN_SHM,
    _SC_2_CHAR_TERM,
    _SC_2_C_VERSION,
    _SC_2_UPE,
    _SC_XOPEN_XPG2,
    _SC_XOPEN_XPG3,
    _SC_XOPEN_XPG4,
    _SC_CHAR_BIT,
    _SC_CHAR_MAX,
    _SC_CHAR_MIN,
    _SC_INT_MAX,
    _SC_INT_MIN,
    _SC_LONG_BIT,
    _SC_WORD_BIT,
    _SC_MB_LEN_MAX,
    _SC_NZERO,
    _SC_SSIZE_MAX,
    _SC_SCHAR_MAX,
    _SC_SCHAR_MIN,
    _SC_SHRT_MAX,
    _SC_SHRT_MIN,
    _SC_UCHAR_MAX,
    _SC_UINT_MAX,
    _SC_ULONG_MAX,
    _SC_USHRT_MAX,
    _SC_NL_ARGMAX,
    _SC_NL_LANGMAX,
    _SC_NL_MSGMAX,
    _SC_NL_NMAX,
    _SC_NL_SETMAX,
    _SC_NL_TEXTMAX,
    _SC_XBS5_ILP32_OFF32,
    _SC_XBS5_ILP32_OFFBIG,
    _SC_XBS5_LP64_OFF64,
    _SC_XBS5_LPBIG_OFFBIG,
    _SC_XOPEN_LEGACY,
    _SC_XOPEN_REALTIME,
    _SC_XOPEN_REALTIME_THREADS,
    _SC_ADVISORY_INFO,
    _SC_BARRIERS,
    _SC_BASE,
    _SC_C_LANG_SUPPORT,
    _SC_C_LANG_SUPPORT_R,
    _SC_CLOCK_SELECTION,
    _SC_CPUTIME,
    _SC_THREAD_CPUTIME,
    _SC_DEVICE_IO,
    _SC_DEVICE_SPECIFIC,
    _SC_DEVICE_SPECIFIC_R,
    _SC_FD_MGMT,
    _SC_FIFO,
    _SC_PIPE,
    _SC_FILE_ATTRIBUTES,
    _SC_FILE_LOCKING,
    _SC_FILE_SYSTEM,
    _SC_MONOTONIC_CLOCK,
    _SC_MULTI_PROCESS,
    _SC_SINGLE_PROCESS,
    _SC_NETWORKING,
    _SC_READER_WRITER_LOCKS,
    _SC_SPIN_LOCKS,
    _SC_REGEXP,
    _SC_REGEX_VERSION,
    _SC_SHELL,
    _SC_SIGNALS,
    _SC_SPAWN,
    _SC_SPORADIC_SERVER,
    _SC_THREAD_SPORADIC_SERVER,
    _SC_SYSTEM_DATABASE,
    _SC_SYSTEM_DATABASE_R,
    _SC_TIMEOUTS,
    _SC_TYPED_MEMORY_OBJECTS,
    _SC_USER_GROUPS,
    _SC_USER_GROUPS_R,
    _SC_2_PBS,
    _SC_2_PBS_ACCOUNTING,
    _SC_2_PBS_LOCATE,
    _SC_2_PBS_MESSAGE,
    _SC_2_PBS_TRACK,
    _SC_SYMLOOP_MAX,
    _SC_STREAMS,
    _SC_2_PBS_CHECKPOINT,
    _SC_V6_ILP32_OFF32,
    _SC_V6_ILP32_OFFBIG,
    _SC_V6_LP64_OFF64,
    _SC_V6_LPBIG_OFFBIG,
    _SC_HOST_NAME_MAX,
    _SC_TRACE,
    _SC_TRACE_EVENT_FILTER,
    _SC_TRACE_INHERIT,
    _SC_TRACE_LOG,
    _SC_LEVEL1_ICACHE_SIZE,
    _SC_LEVEL1_ICACHE_ASSOC,
    _SC_LEVEL1_ICACHE_LINESIZE,
    _SC_LEVEL1_DCACHE_SIZE,
    _SC_LEVEL1_DCACHE_ASSOC,
    _SC_LEVEL1_DCACHE_LINESIZE,
    _SC_LEVEL2_CACHE_SIZE,
    _SC_LEVEL2_CACHE_ASSOC,
    _SC_LEVEL2_CACHE_LINESIZE,
    _SC_LEVEL3_CACHE_SIZE,
    _SC_LEVEL3_CACHE_ASSOC,
    _SC_LEVEL3_CACHE_LINESIZE,
    _SC_LEVEL4_CACHE_SIZE,
    _SC_LEVEL4_CACHE_ASSOC,
    _SC_LEVEL4_CACHE_LINESIZE,
    _SC_IPV6 = _SC_LEVEL1_ICACHE_SIZE + 50,
    _SC_RAW_SOCKETS,
    _SC_V7_ILP32_OFF32,
    _SC_V7_ILP32_OFFBIG,
    _SC_V7_LP64_OFF64,
    _SC_V7_LPBIG_OFFBIG,
    _SC_SS_REPL_MAX,
    _SC_TRACE_EVENT_NAME_MAX,
    _SC_TRACE_NAME_MAX,
    _SC_TRACE_SYS_MAX,
    _SC_TRACE_USER_EVENT_MAX,
    _SC_XOPEN_STREAMS,
    _SC_THREAD_ROBUST_PRIO_INHERIT,
    _SC_THREAD_ROBUST_PRIO_PROTECT
  };
enum
  {
    _CS_PATH,
    _CS_V6_WIDTH_RESTRICTED_ENVS,
    _CS_GNU_LIBC_VERSION,
    _CS_GNU_LIBPTHREAD_VERSION,
    _CS_V5_WIDTH_RESTRICTED_ENVS,
    _CS_V7_WIDTH_RESTRICTED_ENVS,
    _CS_LFS_CFLAGS = 1000,
    _CS_LFS_LDFLAGS,
    _CS_LFS_LIBS,
    _CS_LFS_LINTFLAGS,
    _CS_LFS64_CFLAGS,
    _CS_LFS64_LDFLAGS,
    _CS_LFS64_LIBS,
    _CS_LFS64_LINTFLAGS,
    _CS_XBS5_ILP32_OFF32_CFLAGS = 1100,
    _CS_XBS5_ILP32_OFF32_LDFLAGS,
    _CS_XBS5_ILP32_OFF32_LIBS,
    _CS_XBS5_ILP32_OFF32_LINTFLAGS,
    _CS_XBS5_ILP32_OFFBIG_CFLAGS,
    _CS_XBS5_ILP32_OFFBIG_LDFLAGS,
    _CS_XBS5_ILP32_OFFBIG_LIBS,
    _CS_XBS5_ILP32_OFFBIG_LINTFLAGS,
    _CS_XBS5_LP64_OFF64_CFLAGS,
    _CS_XBS5_LP64_OFF64_LDFLAGS,
    _CS_XBS5_LP64_OFF64_LIBS,
    _CS_XBS5_LP64_OFF64_LINTFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_CFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_LDFLAGS,
    _CS_XBS5_LPBIG_OFFBIG_LIBS,
    _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS,
    _CS_POSIX_V6_ILP32_OFF32_CFLAGS,
    _CS_POSIX_V6_ILP32_OFF32_LDFLAGS,
    _CS_POSIX_V6_ILP32_OFF32_LIBS,
    _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS,
    _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS,
    _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS,
    _CS_POSIX_V6_ILP32_OFFBIG_LIBS,
    _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS,
    _CS_POSIX_V6_LP64_OFF64_CFLAGS,
    _CS_POSIX_V6_LP64_OFF64_LDFLAGS,
    _CS_POSIX_V6_LP64_OFF64_LIBS,
    _CS_POSIX_V6_LP64_OFF64_LINTFLAGS,
    _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS,
    _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS,
    _CS_POSIX_V6_LPBIG_OFFBIG_LIBS,
    _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS,
    _CS_POSIX_V7_ILP32_OFF32_CFLAGS,
    _CS_POSIX_V7_ILP32_OFF32_LDFLAGS,
    _CS_POSIX_V7_ILP32_OFF32_LIBS,
    _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS,
    _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS,
    _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS,
    _CS_POSIX_V7_ILP32_OFFBIG_LIBS,
    _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS,
    _CS_POSIX_V7_LP64_OFF64_CFLAGS,
    _CS_POSIX_V7_LP64_OFF64_LDFLAGS,
    _CS_POSIX_V7_LP64_OFF64_LIBS,
    _CS_POSIX_V7_LP64_OFF64_LINTFLAGS,
    _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS,
    _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS,
    _CS_POSIX_V7_LPBIG_OFFBIG_LIBS,
    _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS,
    _CS_V6_ENV,
    _CS_V7_ENV
  };
extern long int pathconf (const char *__path, int __name)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern long int fpathconf (int __fd, int __name) __attribute__ ((__nothrow__ , __leaf__));
extern long int sysconf (int __name) __attribute__ ((__nothrow__ , __leaf__));
extern size_t confstr (int __name, char *__buf, size_t __len) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t getpid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t getppid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t getpgrp (void) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t __getpgid (__pid_t __pid) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t getpgid (__pid_t __pid) __attribute__ ((__nothrow__ , __leaf__));
extern int setpgid (__pid_t __pid, __pid_t __pgid) __attribute__ ((__nothrow__ , __leaf__));
extern int setpgrp (void) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t setsid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __pid_t getsid (__pid_t __pid) __attribute__ ((__nothrow__ , __leaf__));
extern __uid_t getuid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __uid_t geteuid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __gid_t getgid (void) __attribute__ ((__nothrow__ , __leaf__));
extern __gid_t getegid (void) __attribute__ ((__nothrow__ , __leaf__));
extern int getgroups (int __size, __gid_t __list[]) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int group_member (__gid_t __gid) __attribute__ ((__nothrow__ , __leaf__));
extern int setuid (__uid_t __uid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int setreuid (__uid_t __ruid, __uid_t __euid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int seteuid (__uid_t __uid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int setgid (__gid_t __gid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int setregid (__gid_t __rgid, __gid_t __egid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int setegid (__gid_t __gid) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int getresuid (__uid_t *__ruid, __uid_t *__euid, __uid_t *__suid)
     __attribute__ ((__nothrow__ , __leaf__));
extern int getresgid (__gid_t *__rgid, __gid_t *__egid, __gid_t *__sgid)
     __attribute__ ((__nothrow__ , __leaf__));
extern int setresuid (__uid_t __ruid, __uid_t __euid, __uid_t __suid)
     __attribute__ ((__nothrow__ , __leaf__)) ;
extern int setresgid (__gid_t __rgid, __gid_t __egid, __gid_t __sgid)
     __attribute__ ((__nothrow__ , __leaf__)) ;
extern __pid_t fork (void) __attribute__ ((__nothrow__));
extern __pid_t vfork (void) __attribute__ ((__nothrow__ , __leaf__));
extern char *ttyname (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern int ttyname_r (int __fd, char *__buf, size_t __buflen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2))) ;
extern int isatty (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern int ttyslot (void) __attribute__ ((__nothrow__ , __leaf__));
extern int link (const char *__from, const char *__to)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2))) ;
extern int linkat (int __fromfd, const char *__from, int __tofd,
     const char *__to, int __flags)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 4))) ;
extern int symlink (const char *__from, const char *__to)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2))) ;
extern ssize_t readlink (const char *__restrict __path,
    char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2))) ;
extern int symlinkat (const char *__from, int __tofd,
        const char *__to) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3))) ;
extern ssize_t readlinkat (int __fd, const char *__restrict __path,
      char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3))) ;
extern int unlink (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int unlinkat (int __fd, const char *__name, int __flag)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int rmdir (const char *__path) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern __pid_t tcgetpgrp (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern int tcsetpgrp (int __fd, __pid_t __pgrp_id) __attribute__ ((__nothrow__ , __leaf__));
extern char *getlogin (void);
extern int getlogin_r (char *__name, size_t __name_len) __attribute__ ((__nonnull__ (1)));
extern int setlogin (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;
extern int getopt (int ___argc, char *const *___argv, const char *__shortopts)
       __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));



extern int gethostname (char *__name, size_t __len) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sethostname (const char *__name, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int sethostid (long int __id) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int getdomainname (char *__name, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int setdomainname (const char *__name, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int vhangup (void) __attribute__ ((__nothrow__ , __leaf__));
extern int revoke (const char *__file) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int profil (unsigned short int *__sample_buffer, size_t __size,
     size_t __offset, unsigned int __scale)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int acct (const char *__name) __attribute__ ((__nothrow__ , __leaf__));
extern char *getusershell (void) __attribute__ ((__nothrow__ , __leaf__));
extern void endusershell (void) __attribute__ ((__nothrow__ , __leaf__));
extern void setusershell (void) __attribute__ ((__nothrow__ , __leaf__));
extern int daemon (int __nochdir, int __noclose) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int chroot (const char *__path) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern char *getpass (const char *__prompt) __attribute__ ((__nonnull__ (1)));
extern int fsync (int __fd);
extern int syncfs (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern long int gethostid (void);
extern void sync (void) __attribute__ ((__nothrow__ , __leaf__));
extern int getpagesize (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int getdtablesize (void) __attribute__ ((__nothrow__ , __leaf__));
extern int truncate (const char *__file, __off_t __length)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int truncate64 (const char *__file, __off64_t __length)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int ftruncate (int __fd, __off_t __length) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int ftruncate64 (int __fd, __off64_t __length) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int brk (void *__addr) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void *sbrk (intptr_t __delta) __attribute__ ((__nothrow__ , __leaf__));
extern long int syscall (long int __sysno, ...) __attribute__ ((__nothrow__ , __leaf__));
extern int lockf (int __fd, int __cmd, __off_t __len) ;
extern int lockf64 (int __fd, int __cmd, __off64_t __len) ;
ssize_t copy_file_range (int __infd, __off64_t *__pinoff,
    int __outfd, __off64_t *__poutoff,
    size_t __length, unsigned int __flags);
extern int fdatasync (int __fildes);
extern char *crypt (const char *__key, const char *__salt)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void swab (const void *__restrict __from, void *__restrict __to,
    ssize_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
int getentropy (void *__buffer, size_t __length) ;
extern __pid_t gettid (void) __attribute__ ((__nothrow__ , __leaf__));


typedef enum
{
  P_ALL,
  P_PID,
  P_PGID
} idtype_t;
typedef struct
  {
    int quot;
    int rem;
  } div_t;
typedef struct
  {
    long int quot;
    long int rem;
  } ldiv_t;
__extension__ typedef struct
  {
    long long int quot;
    long long int rem;
  } lldiv_t;
extern size_t __ctype_get_mb_cur_max (void) __attribute__ ((__nothrow__ , __leaf__)) ;
extern double atof (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;
extern int atoi (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;
extern long int atol (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;
__extension__ extern long long int atoll (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;
extern double strtod (const char *__restrict __nptr,
        char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern float strtof (const char *__restrict __nptr,
       char **__restrict __endptr) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern long double strtold (const char *__restrict __nptr,
       char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern _Float32 strtof32 (const char *__restrict __nptr,
     char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern _Float64 strtof64 (const char *__restrict __nptr,
     char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern _Float128 strtof128 (const char *__restrict __nptr,
       char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern _Float32x strtof32x (const char *__restrict __nptr,
       char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern _Float64x strtof64x (const char *__restrict __nptr,
       char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern long int strtol (const char *__restrict __nptr,
   char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern unsigned long int strtoul (const char *__restrict __nptr,
      char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
__extension__
extern long long int strtoq (const char *__restrict __nptr,
        char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
__extension__
extern unsigned long long int strtouq (const char *__restrict __nptr,
           char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
__extension__
extern long long int strtoll (const char *__restrict __nptr,
         char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
__extension__
extern unsigned long long int strtoull (const char *__restrict __nptr,
     char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int strfromd (char *__dest, size_t __size, const char *__format,
       double __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf (char *__dest, size_t __size, const char *__format,
       float __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfroml (char *__dest, size_t __size, const char *__format,
       long double __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf32 (char *__dest, size_t __size, const char * __format,
         _Float32 __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf64 (char *__dest, size_t __size, const char * __format,
         _Float64 __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf128 (char *__dest, size_t __size, const char * __format,
   _Float128 __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf32x (char *__dest, size_t __size, const char * __format,
   _Float32x __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
extern int strfromf64x (char *__dest, size_t __size, const char * __format,
   _Float64x __f)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));
struct __locale_struct
{
  struct __locale_data *__locales[13];
  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;
  const char *__names[13];
};
typedef struct __locale_struct *__locale_t;
typedef __locale_t locale_t;
extern long int strtol_l (const char *__restrict __nptr,
     char **__restrict __endptr, int __base,
     locale_t __loc) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 4)));
extern unsigned long int strtoul_l (const char *__restrict __nptr,
        char **__restrict __endptr,
        int __base, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 4)));
__extension__
extern long long int strtoll_l (const char *__restrict __nptr,
    char **__restrict __endptr, int __base,
    locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 4)));
__extension__
extern unsigned long long int strtoull_l (const char *__restrict __nptr,
       char **__restrict __endptr,
       int __base, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 4)));
extern double strtod_l (const char *__restrict __nptr,
   char **__restrict __endptr, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern float strtof_l (const char *__restrict __nptr,
         char **__restrict __endptr, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern long double strtold_l (const char *__restrict __nptr,
         char **__restrict __endptr,
         locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern _Float32 strtof32_l (const char *__restrict __nptr,
       char **__restrict __endptr,
       locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern _Float64 strtof64_l (const char *__restrict __nptr,
       char **__restrict __endptr,
       locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern _Float128 strtof128_l (const char *__restrict __nptr,
         char **__restrict __endptr,
         locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern _Float32x strtof32x_l (const char *__restrict __nptr,
         char **__restrict __endptr,
         locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern _Float64x strtof64x_l (const char *__restrict __nptr,
         char **__restrict __endptr,
         locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));
extern char *l64a (long int __n) __attribute__ ((__nothrow__ , __leaf__)) ;
extern long int a64l (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;
extern long int random (void) __attribute__ ((__nothrow__ , __leaf__));
extern void srandom (unsigned int __seed) __attribute__ ((__nothrow__ , __leaf__));
extern char *initstate (unsigned int __seed, char *__statebuf,
   size_t __statelen) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern char *setstate (char *__statebuf) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
struct random_data
  {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
  };
extern int random_r (struct random_data *__restrict __buf,
       int32_t *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int srandom_r (unsigned int __seed, struct random_data *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int initstate_r (unsigned int __seed, char *__restrict __statebuf,
   size_t __statelen,
   struct random_data *__restrict __buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 4)));
extern int setstate_r (char *__restrict __statebuf,
         struct random_data *__restrict __buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int rand (void) __attribute__ ((__nothrow__ , __leaf__));
extern void srand (unsigned int __seed) __attribute__ ((__nothrow__ , __leaf__));
extern int rand_r (unsigned int *__seed) __attribute__ ((__nothrow__ , __leaf__));
extern double drand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern double erand48 (unsigned short int __xsubi[3]) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern long int lrand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern long int nrand48 (unsigned short int __xsubi[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern long int mrand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern long int jrand48 (unsigned short int __xsubi[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern void srand48 (long int __seedval) __attribute__ ((__nothrow__ , __leaf__));
extern unsigned short int *seed48 (unsigned short int __seed16v[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern void lcong48 (unsigned short int __param[7]) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
struct drand48_data
  {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    __extension__ unsigned long long int __a;
  };
extern int drand48_r (struct drand48_data *__restrict __buffer,
        double *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int erand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        double *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int lrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int nrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int mrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int jrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int seed48_r (unsigned short int __seed16v[3],
       struct drand48_data *__buffer) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int lcong48_r (unsigned short int __param[7],
        struct drand48_data *__buffer)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *malloc (size_t __size) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__))
     __attribute__ ((__alloc_size__ (1))) ;
extern void *calloc (size_t __nmemb, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__alloc_size__ (1, 2))) ;
extern void *realloc (void *__ptr, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__warn_unused_result__)) __attribute__ ((__alloc_size__ (2)));
extern void *reallocarray (void *__ptr, size_t __nmemb, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__warn_unused_result__))
     __attribute__ ((__alloc_size__ (2, 3)));
extern void free (void *__ptr) __attribute__ ((__nothrow__ , __leaf__));

extern void *alloca (size_t __size) __attribute__ ((__nothrow__ , __leaf__));

extern void *valloc (size_t __size) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__))
     __attribute__ ((__alloc_size__ (1))) ;
extern int posix_memalign (void **__memptr, size_t __alignment, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern void *aligned_alloc (size_t __alignment, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__alloc_size__ (2))) ;
extern void abort (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern int atexit (void (*__func) (void)) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int at_quick_exit (void (*__func) (void)) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern void exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void quick_exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void _Exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern char *getenv (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern char *secure_getenv (const char *__name)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int putenv (char *__string) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int setenv (const char *__name, const char *__value, int __replace)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int unsetenv (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int clearenv (void) __attribute__ ((__nothrow__ , __leaf__));
extern char *mktemp (char *__template) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int mkstemp (char *__template) __attribute__ ((__nonnull__ (1))) ;
extern int mkstemp64 (char *__template) __attribute__ ((__nonnull__ (1))) ;
extern int mkstemps (char *__template, int __suffixlen) __attribute__ ((__nonnull__ (1))) ;
extern int mkstemps64 (char *__template, int __suffixlen)
     __attribute__ ((__nonnull__ (1))) ;
extern char *mkdtemp (char *__template) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int mkostemp (char *__template, int __flags) __attribute__ ((__nonnull__ (1))) ;
extern int mkostemp64 (char *__template, int __flags) __attribute__ ((__nonnull__ (1))) ;
extern int mkostemps (char *__template, int __suffixlen, int __flags)
     __attribute__ ((__nonnull__ (1))) ;
extern int mkostemps64 (char *__template, int __suffixlen, int __flags)
     __attribute__ ((__nonnull__ (1))) ;
extern int system (const char *__command) ;
extern char *canonicalize_file_name (const char *__name)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern char *realpath (const char *__restrict __name,
         char *__restrict __resolved) __attribute__ ((__nothrow__ , __leaf__)) ;
typedef int (*__compar_fn_t) (const void *, const void *);
typedef __compar_fn_t comparison_fn_t;
typedef int (*__compar_d_fn_t) (const void *, const void *, void *);
extern void *bsearch (const void *__key, const void *__base,
        size_t __nmemb, size_t __size, __compar_fn_t __compar)
     __attribute__ ((__nonnull__ (1, 2, 5))) ;
extern void qsort (void *__base, size_t __nmemb, size_t __size,
     __compar_fn_t __compar) __attribute__ ((__nonnull__ (1, 4)));
extern void qsort_r (void *__base, size_t __nmemb, size_t __size,
       __compar_d_fn_t __compar, void *__arg)
  __attribute__ ((__nonnull__ (1, 4)));
extern int abs (int __x) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern long int labs (long int __x) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
__extension__ extern long long int llabs (long long int __x)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern div_t div (int __numer, int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern ldiv_t ldiv (long int __numer, long int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
__extension__ extern lldiv_t lldiv (long long int __numer,
        long long int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *gcvt (double __value, int __ndigit, char *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3))) ;
extern char *qecvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *qfcvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *qgcvt (long double __value, int __ndigit, char *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3))) ;
extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int qecvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int qfcvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int mblen (const char *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));
extern int mbtowc (wchar_t *__restrict __pwc,
     const char *__restrict __s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));
extern int wctomb (char *__s, wchar_t __wchar) __attribute__ ((__nothrow__ , __leaf__));
extern size_t mbstowcs (wchar_t *__restrict __pwcs,
   const char *__restrict __s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));
extern size_t wcstombs (char *__restrict __s,
   const wchar_t *__restrict __pwcs, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__));
extern int rpmatch (const char *__response) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
extern int getsubopt (char **__restrict __optionp,
        char *const *__restrict __tokens,
        char **__restrict __valuep)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2, 3))) ;
extern int posix_openpt (int __oflag) ;
extern int grantpt (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern int unlockpt (int __fd) __attribute__ ((__nothrow__ , __leaf__));
extern char *ptsname (int __fd) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int ptsname_r (int __fd, char *__buf, size_t __buflen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int getpt (void);
extern int getloadavg (double __loadavg[], int __nelem)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


typedef __builtin_va_list __gnuc_va_list;
typedef struct
{
  int __count;
  union
  {
    unsigned int __wch;
    char __wchb[4];
  } __value;
} __mbstate_t;
typedef struct _G_fpos_t
{
  __off_t __pos;
  __mbstate_t __state;
} __fpos_t;
typedef struct _G_fpos64_t
{
  __off64_t __pos;
  __mbstate_t __state;
} __fpos64_t;
struct _IO_FILE;
typedef struct _IO_FILE __FILE;
struct _IO_FILE;
typedef struct _IO_FILE FILE;
struct _IO_FILE;
struct _IO_marker;
struct _IO_codecvt;
struct _IO_wide_data;
typedef void _IO_lock_t;
struct _IO_FILE
{
  int _flags;
  char *_IO_read_ptr;
  char *_IO_read_end;
  char *_IO_read_base;
  char *_IO_write_base;
  char *_IO_write_ptr;
  char *_IO_write_end;
  char *_IO_buf_base;
  char *_IO_buf_end;
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset;
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
  __off64_t _offset;
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
typedef __ssize_t cookie_read_function_t (void *__cookie, char *__buf,
                                          size_t __nbytes);
typedef __ssize_t cookie_write_function_t (void *__cookie, const char *__buf,
                                           size_t __nbytes);
typedef int cookie_seek_function_t (void *__cookie, __off64_t *__pos, int __w);
typedef int cookie_close_function_t (void *__cookie);
typedef struct _IO_cookie_io_functions_t
{
  cookie_read_function_t *read;
  cookie_write_function_t *write;
  cookie_seek_function_t *seek;
  cookie_close_function_t *close;
} cookie_io_functions_t;
typedef __gnuc_va_list va_list;
typedef __fpos_t fpos_t;
typedef __fpos64_t fpos64_t;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;
extern int remove (const char *__filename) __attribute__ ((__nothrow__ , __leaf__));
extern int rename (const char *__old, const char *__new) __attribute__ ((__nothrow__ , __leaf__));
extern int renameat (int __oldfd, const char *__old, int __newfd,
       const char *__new) __attribute__ ((__nothrow__ , __leaf__));
extern int renameat2 (int __oldfd, const char *__old, int __newfd,
        const char *__new, unsigned int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern FILE *tmpfile (void) ;
extern FILE *tmpfile64 (void) ;
extern char *tmpnam (char *__s) __attribute__ ((__nothrow__ , __leaf__)) ;
extern char *tmpnam_r (char *__s) __attribute__ ((__nothrow__ , __leaf__)) ;
extern char *tempnam (const char *__dir, const char *__pfx)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) ;
extern int fclose (FILE *__stream);
extern int fflush (FILE *__stream);
extern int fflush_unlocked (FILE *__stream);
extern int fcloseall (void);
extern FILE *fopen (const char *__restrict __filename,
      const char *__restrict __modes) ;
extern FILE *freopen (const char *__restrict __filename,
        const char *__restrict __modes,
        FILE *__restrict __stream) ;
extern FILE *fopen64 (const char *__restrict __filename,
        const char *__restrict __modes) ;
extern FILE *freopen64 (const char *__restrict __filename,
   const char *__restrict __modes,
   FILE *__restrict __stream) ;
extern FILE *fdopen (int __fd, const char *__modes) __attribute__ ((__nothrow__ , __leaf__)) ;
extern FILE *fopencookie (void *__restrict __magic_cookie,
     const char *__restrict __modes,
     cookie_io_functions_t __io_funcs) __attribute__ ((__nothrow__ , __leaf__)) ;
extern FILE *fmemopen (void *__s, size_t __len, const char *__modes)
  __attribute__ ((__nothrow__ , __leaf__)) ;
extern FILE *open_memstream (char **__bufloc, size_t *__sizeloc) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void setbuf (FILE *__restrict __stream, char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));
extern int setvbuf (FILE *__restrict __stream, char *__restrict __buf,
      int __modes, size_t __n) __attribute__ ((__nothrow__ , __leaf__));
extern void setbuffer (FILE *__restrict __stream, char *__restrict __buf,
         size_t __size) __attribute__ ((__nothrow__ , __leaf__));
extern void setlinebuf (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int fprintf (FILE *__restrict __stream,
      const char *__restrict __format, ...);
extern int printf (const char *__restrict __format, ...);
extern int sprintf (char *__restrict __s,
      const char *__restrict __format, ...) __attribute__ ((__nothrow__));
extern int vfprintf (FILE *__restrict __s, const char *__restrict __format,
       __gnuc_va_list __arg);
extern int vprintf (const char *__restrict __format, __gnuc_va_list __arg);
extern int vsprintf (char *__restrict __s, const char *__restrict __format,
       __gnuc_va_list __arg) __attribute__ ((__nothrow__));
extern int snprintf (char *__restrict __s, size_t __maxlen,
       const char *__restrict __format, ...)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 4)));
extern int vsnprintf (char *__restrict __s, size_t __maxlen,
        const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 0)));
extern int vasprintf (char **__restrict __ptr, const char *__restrict __f,
        __gnuc_va_list __arg)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 2, 0))) ;
extern int __asprintf (char **__restrict __ptr,
         const char *__restrict __fmt, ...)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 2, 3))) ;
extern int asprintf (char **__restrict __ptr,
       const char *__restrict __fmt, ...)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 2, 3))) ;
extern int vdprintf (int __fd, const char *__restrict __fmt,
       __gnuc_va_list __arg)
     __attribute__ ((__format__ (__printf__, 2, 0)));
extern int dprintf (int __fd, const char *__restrict __fmt, ...)
     __attribute__ ((__format__ (__printf__, 2, 3)));
extern int fscanf (FILE *__restrict __stream,
     const char *__restrict __format, ...) ;
extern int scanf (const char *__restrict __format, ...) ;
extern int sscanf (const char *__restrict __s,
     const char *__restrict __format, ...) __attribute__ ((__nothrow__ , __leaf__));
extern int fscanf (FILE *__restrict __stream, const char *__restrict __format, ...) __asm__ ("" "__isoc99_fscanf") ;
extern int scanf (const char *__restrict __format, ...) __asm__ ("" "__isoc99_scanf") ;
extern int sscanf (const char *__restrict __s, const char *__restrict __format, ...) __asm__ ("" "__isoc99_sscanf") __attribute__ ((__nothrow__ , __leaf__));
extern int vfscanf (FILE *__restrict __s, const char *__restrict __format,
      __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 2, 0))) ;
extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 1, 0))) ;
extern int vsscanf (const char *__restrict __s,
      const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__format__ (__scanf__, 2, 0)));
extern int vfscanf (FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vfscanf")
     __attribute__ ((__format__ (__scanf__, 2, 0))) ;
extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vscanf")
     __attribute__ ((__format__ (__scanf__, 1, 0))) ;
extern int vsscanf (const char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vsscanf") __attribute__ ((__nothrow__ , __leaf__))
     __attribute__ ((__format__ (__scanf__, 2, 0)));
extern int fgetc (FILE *__stream);
extern int getc (FILE *__stream);
extern int getchar (void);
extern int getc_unlocked (FILE *__stream);
extern int getchar_unlocked (void);
extern int fgetc_unlocked (FILE *__stream);
extern int fputc (int __c, FILE *__stream);
extern int putc (int __c, FILE *__stream);
extern int putchar (int __c);
extern int fputc_unlocked (int __c, FILE *__stream);
extern int putc_unlocked (int __c, FILE *__stream);
extern int putchar_unlocked (int __c);
extern int getw (FILE *__stream);
extern int putw (int __w, FILE *__stream);
extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
     ;
extern char *fgets_unlocked (char *__restrict __s, int __n,
        FILE *__restrict __stream) ;
extern __ssize_t __getdelim (char **__restrict __lineptr,
                             size_t *__restrict __n, int __delimiter,
                             FILE *__restrict __stream) ;
extern __ssize_t getdelim (char **__restrict __lineptr,
                           size_t *__restrict __n, int __delimiter,
                           FILE *__restrict __stream) ;
extern __ssize_t getline (char **__restrict __lineptr,
                          size_t *__restrict __n,
                          FILE *__restrict __stream) ;
extern int fputs (const char *__restrict __s, FILE *__restrict __stream);
extern int puts (const char *__s);
extern int ungetc (int __c, FILE *__stream);
extern size_t fread (void *__restrict __ptr, size_t __size,
       size_t __n, FILE *__restrict __stream) ;
extern size_t fwrite (const void *__restrict __ptr, size_t __size,
        size_t __n, FILE *__restrict __s);
extern int fputs_unlocked (const char *__restrict __s,
      FILE *__restrict __stream);
extern size_t fread_unlocked (void *__restrict __ptr, size_t __size,
         size_t __n, FILE *__restrict __stream) ;
extern size_t fwrite_unlocked (const void *__restrict __ptr, size_t __size,
          size_t __n, FILE *__restrict __stream);
extern int fseek (FILE *__stream, long int __off, int __whence);
extern long int ftell (FILE *__stream) ;
extern void rewind (FILE *__stream);
extern int fseeko (FILE *__stream, __off_t __off, int __whence);
extern __off_t ftello (FILE *__stream) ;
extern int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos);
extern int fsetpos (FILE *__stream, const fpos_t *__pos);
extern int fseeko64 (FILE *__stream, __off64_t __off, int __whence);
extern __off64_t ftello64 (FILE *__stream) ;
extern int fgetpos64 (FILE *__restrict __stream, fpos64_t *__restrict __pos);
extern int fsetpos64 (FILE *__stream, const fpos64_t *__pos);
extern void clearerr (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int feof (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int ferror (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void clearerr_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int feof_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int ferror_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void perror (const char *__s);
extern int sys_nerr;
extern const char *const sys_errlist[];
extern int _sys_nerr;
extern const char *const _sys_errlist[];
extern int fileno (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int fileno_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern FILE *popen (const char *__command, const char *__modes) ;
extern int pclose (FILE *__stream);
extern char *ctermid (char *__s) __attribute__ ((__nothrow__ , __leaf__));
extern char *cuserid (char *__s);
struct obstack;
extern int obstack_printf (struct obstack *__restrict __obstack,
      const char *__restrict __format, ...)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 2, 3)));
extern int obstack_vprintf (struct obstack *__restrict __obstack,
       const char *__restrict __format,
       __gnuc_va_list __args)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 2, 0)));
extern void flockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int ftrylockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void funlockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int __uflow (FILE *);
extern int __overflow (FILE *, int);


extern void *memcpy (void *__restrict __dest, const void *__restrict __src,
       size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *memmove (void *__dest, const void *__src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *memccpy (void *__restrict __dest, const void *__restrict __src,
        int __c, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *memset (void *__s, int __c, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int memcmp (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *memchr (const void *__s, int __c, size_t __n)
      __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern void *rawmemchr (const void *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern void *memrchr (const void *__s, int __c, size_t __n)
      __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern char *strcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strncpy (char *__restrict __dest,
        const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strcat (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strncat (char *__restrict __dest, const char *__restrict __src,
        size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strcmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strncmp (const char *__s1, const char *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strcoll (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern size_t strxfrm (char *__restrict __dest,
         const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int strcoll_l (const char *__s1, const char *__s2, locale_t __l)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 3)));
extern size_t strxfrm_l (char *__dest, const char *__src, size_t __n,
    locale_t __l) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 4)));
extern char *strdup (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__nonnull__ (1)));
extern char *strndup (const char *__string, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__nonnull__ (1)));
extern char *strchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern char *strrchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern char *strchrnul (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern size_t strcspn (const char *__s, const char *__reject)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern size_t strspn (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strpbrk (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strstr (const char *__haystack, const char *__needle)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strtok (char *__restrict __s, const char *__restrict __delim)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern char *__strtok_r (char *__restrict __s,
    const char *__restrict __delim,
    char **__restrict __save_ptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));
extern char *strtok_r (char *__restrict __s, const char *__restrict __delim,
         char **__restrict __save_ptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));
extern char *strcasestr (const char *__haystack, const char *__needle)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *memmem (const void *__haystack, size_t __haystacklen,
       const void *__needle, size_t __needlelen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 3)));
extern void *__mempcpy (void *__restrict __dest,
   const void *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void *mempcpy (void *__restrict __dest,
        const void *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern size_t strlen (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern size_t strnlen (const char *__string, size_t __maxlen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern char *strerror (int __errnum) __attribute__ ((__nothrow__ , __leaf__));
extern char *strerror_r (int __errnum, char *__buf, size_t __buflen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2))) ;
extern char *strerror_l (int __errnum, locale_t __l) __attribute__ ((__nothrow__ , __leaf__));

extern int bcmp (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern void bcopy (const void *__src, void *__dest, size_t __n)
  __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern void bzero (void *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern char *index (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern char *rindex (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
extern int ffs (int __i) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int ffsl (long int __l) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
__extension__ extern int ffsll (long long int __ll)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int strcasecmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strncasecmp (const char *__s1, const char *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strcasecmp_l (const char *__s1, const char *__s2, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 3)));
extern int strncasecmp_l (const char *__s1, const char *__s2,
     size_t __n, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 4)));

extern void explicit_bzero (void *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern char *strsep (char **__restrict __stringp,
       const char *__restrict __delim)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strsignal (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern char *__stpcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *stpcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *__stpncpy (char *__restrict __dest,
   const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *stpncpy (char *__restrict __dest,
        const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int strverscmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *strfry (char *__string) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern void *memfrob (void *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern char *basename (const char *__filename) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int *__errno_location (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern char *program_invocation_name;
extern char *program_invocation_short_name;
typedef int error_t;

struct timex
{
  unsigned int modes;
  __syscall_slong_t offset;
  __syscall_slong_t freq;
  __syscall_slong_t maxerror;
  __syscall_slong_t esterror;
  int status;
  __syscall_slong_t constant;
  __syscall_slong_t precision;
  __syscall_slong_t tolerance;
  struct timeval time;
  __syscall_slong_t tick;
  __syscall_slong_t ppsfreq;
  __syscall_slong_t jitter;
  int shift;
  __syscall_slong_t stabil;
  __syscall_slong_t jitcnt;
  __syscall_slong_t calcnt;
  __syscall_slong_t errcnt;
  __syscall_slong_t stbcnt;
  int tai;
  int :32; int :32; int :32; int :32;
  int :32; int :32; int :32; int :32;
  int :32; int :32; int :32;
};

extern int clock_adjtime (__clockid_t __clock_id, struct timex *__utx) __attribute__ ((__nothrow__ , __leaf__));

struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
  long int tm_gmtoff;
  const char *tm_zone;
};
struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };
struct sigevent;

extern clock_t clock (void) __attribute__ ((__nothrow__ , __leaf__));
extern time_t time (time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));
extern double difftime (time_t __time1, time_t __time0)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern time_t mktime (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));
extern size_t strftime (char *__restrict __s, size_t __maxsize,
   const char *__restrict __format,
   const struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));
extern char *strptime (const char *__restrict __s,
         const char *__restrict __fmt, struct tm *__tp)
     __attribute__ ((__nothrow__ , __leaf__));
extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     const char *__restrict __format,
     const struct tm *__restrict __tp,
     locale_t __loc) __attribute__ ((__nothrow__ , __leaf__));
extern char *strptime_l (const char *__restrict __s,
    const char *__restrict __fmt, struct tm *__tp,
    locale_t __loc) __attribute__ ((__nothrow__ , __leaf__));
extern struct tm *gmtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));
extern struct tm *localtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));
extern struct tm *gmtime_r (const time_t *__restrict __timer,
       struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));
extern struct tm *localtime_r (const time_t *__restrict __timer,
          struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));
extern char *asctime (const struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));
extern char *ctime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));
extern char *asctime_r (const struct tm *__restrict __tp,
   char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));
extern char *ctime_r (const time_t *__restrict __timer,
        char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));
extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;
extern char *tzname[2];
extern void tzset (void) __attribute__ ((__nothrow__ , __leaf__));
extern int daylight;
extern long int timezone;
extern time_t timegm (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));
extern time_t timelocal (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));
extern int dysize (int __year) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int nanosleep (const struct timespec *__requested_time,
        struct timespec *__remaining);
extern int clock_getres (clockid_t __clock_id, struct timespec *__res) __attribute__ ((__nothrow__ , __leaf__));
extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) __attribute__ ((__nothrow__ , __leaf__));
extern int clock_settime (clockid_t __clock_id, const struct timespec *__tp)
     __attribute__ ((__nothrow__ , __leaf__));
extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       const struct timespec *__req,
       struct timespec *__rem);
extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) __attribute__ ((__nothrow__ , __leaf__));
extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) __attribute__ ((__nothrow__ , __leaf__));
extern int timer_delete (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));
extern int timer_settime (timer_t __timerid, int __flags,
     const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) __attribute__ ((__nothrow__ , __leaf__));
extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     __attribute__ ((__nothrow__ , __leaf__));
extern int timer_getoverrun (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));
extern int timespec_get (struct timespec *__ts, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int getdate_err;
extern struct tm *getdate (const char *__string);
extern int getdate_r (const char *__restrict __string,
        struct tm *__restrict __resbufp);


struct timezone
  {
    int tz_minuteswest;
    int tz_dsttime;
  };
extern int gettimeofday (struct timeval *__restrict __tv,
    void *__restrict __tz) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int settimeofday (const struct timeval *__tv,
    const struct timezone *__tz)
     __attribute__ ((__nothrow__ , __leaf__));
extern int adjtime (const struct timeval *__delta,
      struct timeval *__olddelta) __attribute__ ((__nothrow__ , __leaf__));
enum __itimer_which
  {
    ITIMER_REAL = 0,
    ITIMER_VIRTUAL = 1,
    ITIMER_PROF = 2
  };
struct itimerval
  {
    struct timeval it_interval;
    struct timeval it_value;
  };
typedef enum __itimer_which __itimer_which_t;
extern int getitimer (__itimer_which_t __which,
        struct itimerval *__value) __attribute__ ((__nothrow__ , __leaf__));
extern int setitimer (__itimer_which_t __which,
        const struct itimerval *__restrict __new,
        struct itimerval *__restrict __old) __attribute__ ((__nothrow__ , __leaf__));
extern int utimes (const char *__file, const struct timeval __tvp[2])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int lutimes (const char *__file, const struct timeval __tvp[2])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int futimes (int __fd, const struct timeval __tvp[2]) __attribute__ ((__nothrow__ , __leaf__));
extern int futimesat (int __fd, const char *__file,
        const struct timeval __tvp[2]) __attribute__ ((__nothrow__ , __leaf__));

extern _Bool debug_flag;
void die(void) __attribute__((__noreturn__));
void error_msg(const char *fmt, ...) __attribute__((__format__ (printf, 1, 2)));
void perror_msg(const char *fmt, ...) __attribute__((__format__ (printf, 1, 2)));
void perror_msg_and_die(const char *fmt, ...)
 __attribute__((__format__ (printf, 1, 2))) __attribute__((__noreturn__));
void error_msg_and_help(const char *fmt, ...)
 __attribute__((__format__ (printf, 1, 2))) __attribute__((__noreturn__));
void error_msg_and_die(const char *fmt, ...)
 __attribute__((__format__ (printf, 1, 2))) __attribute__((__noreturn__));
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
typedef unsigned long __kernel_old_dev_t;
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_ino_t;
typedef unsigned int __kernel_mode_t;
typedef int __kernel_pid_t;
typedef int __kernel_ipc_pid_t;
typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;
typedef __kernel_long_t __kernel_suseconds_t;
typedef int __kernel_daddr_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;
typedef struct {
 int val[2];
} __kernel_fsid_t;
typedef __kernel_long_t __kernel_off_t;
typedef long long __kernel_loff_t;
typedef __kernel_long_t __kernel_time_t;
typedef long long __kernel_time64_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef char * __kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef __kernel_long_t kernel_long_t;
typedef __kernel_ulong_t kernel_ulong_t;

extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void __assert_perror_fail (int __errnum, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void __assert (const char *__assertion, const char *__file, int __line)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));

static inline _Bool
is_filled(const char *ptr, char fill, size_t size)
{
 while (size--)
  if (*ptr++ != fill)
   return 0;
 return 1;
}
struct list_item {
 struct list_item *prev;
 struct list_item *next;
};
static inline void
list_init(struct list_item *l)
{
 l->prev = l;
 l->next = l;
}
static inline _Bool
list_is_empty(const struct list_item *l)
{
 return ((l->next == l) && (l->prev == l))
  || (!l->next && !l->prev);
}
static inline void
list_insert(struct list_item *head, struct list_item *item)
{
 item->next = head->next;
 item->prev = head;
 head->next->prev = item;
 head->next = item;
}
static inline void
list_append(struct list_item *head, struct list_item *item)
{
 item->next = head;
 item->prev = head->prev;
 head->prev->next = item;
 head->prev = item;
}
static inline _Bool
list_remove(struct list_item *item)
{
 if (!item->next || !item->prev || list_is_empty(item))
  return 0;
 item->prev->next = item->next;
 item->next->prev = item->prev;
 item->next = item->prev = item;
 return 1;
}
static inline struct list_item *
list_remove_tail(struct list_item *head)
{
 struct list_item *t = list_is_empty(head) ? ((void *)0) : head->prev;
 if (t)
  list_remove(t);
 return t;
}
static inline struct list_item *
list_remove_head(struct list_item *head)
{
 struct list_item *h = list_is_empty(head) ? ((void *)0) : head->next;
 if (h)
  list_remove(h);
 return h;
}
static inline _Bool
list_replace(struct list_item *old, struct list_item *new)
{
 if (!old->next || !old->prev || list_is_empty(old))
  return 0;
 new->next = old->next;
 new->prev = old->prev;
 old->prev->next = new;
 old->next->prev = new;
 old->next = old->prev = old;
 return 1;
}
typedef unsigned long mpers_ptr_t;
extern long long
string_to_uint_ex(const char *str, char **endptr,
    unsigned long long max_val, const char *accepted_ending);
static inline long long
string_to_uint_upto(const char *const str, const unsigned long long max_val)
{
 return string_to_uint_ex(str, ((void *)0), max_val, ((void *)0));
}
static inline int
string_to_uint(const char *str)
{
 return string_to_uint_upto(str, 0x7fffffff);
}
static inline long
string_to_ulong(const char *str)
{
 return string_to_uint_upto(str, 0x7fffffffffffffffL);
}
static inline kernel_long_t
string_to_kulong(const char *str)
{
 return string_to_uint_upto(str, ((kernel_ulong_t) -1ULL) >> 1);
}
static inline long long
string_to_ulonglong(const char *str)
{
 return string_to_uint_upto(str, 0x7fffffffffffffffLL);
}
struct tcb;
typedef struct sysent {
 unsigned nargs;
 int sys_flags;
 int sen;
 int (*sys_func)(struct tcb *);
 const char *sys_name;
} struct_sysent;
void *strace_malloc(size_t size) __attribute__((__malloc__)) __attribute__((__alloc_size__ (1)));
void *strace_calloc(size_t nmemb, size_t size)
 __attribute__((__malloc__)) __attribute__((__alloc_size__ (1, 2)));
__attribute__((__malloc__)) __attribute__((__alloc_size__ (1)))
static inline void *
xzalloc(size_t size)
{
 return strace_calloc(1, size);
}
void *xallocarray(size_t nmemb, size_t size)
 __attribute__((__malloc__)) __attribute__((__alloc_size__ (1, 2)));
void *xreallocarray(void *ptr, size_t nmemb, size_t size)
 __attribute__((__alloc_size__ (2, 3)));
void *xgrowarray(void *ptr, size_t *nmemb, size_t memb_size);
char *xstrdup(const char *str) __attribute__((__malloc__));
char *xstrndup(const char *str, size_t n) __attribute__((__malloc__));
void *xmemdup(const void *src, size_t size)
 __attribute__((__malloc__)) __attribute__((__alloc_size__ (2)));
void *xarraydup(const void *src, size_t nmemb, size_t memb_size)
 __attribute__((__malloc__)) __attribute__((__alloc_size__ (2, 3)));
char *xasprintf(const char *fmt, ...)
 __attribute__((__format__ (printf, 1, 2))) __attribute__((__malloc__));
extern void set_personality(unsigned int personality);
extern unsigned current_personality;
extern unsigned current_wordsize;
extern unsigned current_klongsize;
typedef struct ioctlent {
 const char *symbol;
 unsigned int code;
} struct_ioctlent;
struct inject_data {
 uint8_t flags;
 uint8_t signo;
 uint16_t rval_idx;
 uint16_t delay_idx;
 uint16_t poke_idx;
 uint16_t scno;
};
struct inject_opts {
 uint16_t first;
 uint16_t last;
 uint16_t step;
 struct inject_data data;
};
struct tcb {
 int flags;
 int pid;
 int qual_flg;
 unsigned int currpers;
 unsigned long u_error;
 kernel_ulong_t scno;
 kernel_ulong_t true_scno;
 kernel_ulong_t u_arg[6];
 kernel_long_t u_rval;
 int sys_func_rval;
 int curcol;
 FILE *outf;
 struct staged_output_data *staged_output_data;
 const char *auxstr;
 void *_priv_data;
 void (*_free_priv_data)(void *);
 const struct_sysent *s_ent;
 const struct_sysent *s_prev_ent;
 struct inject_opts *inject_vec[3];
 struct timespec stime;
 struct timespec ltime;
 struct timespec atime;
 struct timespec etime;
 struct timespec delay_expiration_time;
 unsigned int pid_ns;
 int last_dirfd;
 struct mmap_cache_t *mmap_cache;
 size_t wait_data_idx;
 struct tcb_wait_data *delayed_wait_data;
 struct list_item wait_list;
 struct vcpu_info *vcpu_info_list;
 void *unwind_ctx;
 struct unwind_queue_t *unwind_queue;
 char comm[16];
};
extern const struct_sysent stub_sysent;
enum xlat_type {
 XT_NORMAL,
 XT_SORTED,
 XT_INDEXED,
};
enum xlat_style {
 XLAT_STYLE_DEFAULT = 0,
 XLAT_STYLE_RAW = 1 << 0,
 XLAT_STYLE_ABBREV = 1 << 1,
 XLAT_STYLE_VERBOSE = XLAT_STYLE_RAW | XLAT_STYLE_ABBREV,
 XLAT_STYLE_FMT_X = 0 << 2,
 XLAT_STYLE_FMT_U = 1 << 2,
 XLAT_STYLE_FMT_D = 2 << 2,
};
struct xlat_data {
 uint64_t val;
 const char *str;
};
struct xlat {
 const struct xlat_data *data;
 size_t flags_strsz;
 uint32_t size;
 enum xlat_type type;
 uint64_t flags_mask;
};
extern const struct xlat addrfams[];
extern const struct xlat arp_hardware_types[];
extern const struct xlat at_flags[];
extern const struct xlat clocknames[];
extern const struct xlat dirent_types[];
extern const struct xlat ethernet_protocols[];
extern const struct xlat inet_protocols[];
extern const struct xlat evdev_abs[];
extern const struct xlat audit_arch[];
extern const struct xlat evdev_ev[];
extern const struct xlat iffflags[];
extern const struct xlat ip_type_of_services[];
extern const struct xlat ipc_private[];
extern const struct xlat msg_flags[];
extern const struct xlat netlink_protocols[];
extern const struct xlat nl_bridge_vlan_flags[];
extern const struct xlat nl_netfilter_msg_types[];
extern const struct xlat nl_route_types[];
extern const struct xlat open_access_modes[];
extern const struct xlat open_mode_flags[];
extern const struct xlat perf_type_id[];
extern const struct xlat pollflags[];
extern const struct xlat ptrace_cmds[];
extern const struct xlat resource_flags[];
extern const struct xlat route_nexthop_flags[];
extern const struct xlat routing_protocols[];
extern const struct xlat routing_scopes[];
extern const struct xlat routing_table_ids[];
extern const struct xlat routing_types[];
extern const struct xlat rwf_flags[];
extern const struct xlat seccomp_filter_flags[];
extern const struct xlat seccomp_ret_action[];
extern const struct xlat setns_types[];
extern const struct xlat sg_io_info[];
extern const struct xlat socketlayers[];
extern const struct xlat socktypes[];
extern const struct xlat tcp_state_flags[];
extern const struct xlat tcp_states[];
extern const struct xlat whence_codes[];
enum pid_type {
 PT_TID,
 PT_TGID,
 PT_PGID,
 PT_SID,
 PT_COUNT,
 PT_NONE = -1
};
enum sock_proto {
 SOCK_PROTO_UNKNOWN,
 SOCK_PROTO_UNIX,
 SOCK_PROTO_UNIX_STREAM,
 SOCK_PROTO_TCP,
 SOCK_PROTO_UDP,
 SOCK_PROTO_UDPLITE,
 SOCK_PROTO_DCCP,
 SOCK_PROTO_SCTP,
 SOCK_PROTO_L2TP_IP,
 SOCK_PROTO_PING,
 SOCK_PROTO_RAW,
 SOCK_PROTO_TCPv6,
 SOCK_PROTO_UDPv6,
 SOCK_PROTO_UDPLITEv6,
 SOCK_PROTO_DCCPv6,
 SOCK_PROTO_L2TP_IPv6,
 SOCK_PROTO_SCTPv6,
 SOCK_PROTO_PINGv6,
 SOCK_PROTO_RAWv6,
 SOCK_PROTO_NETLINK,
};
extern enum sock_proto get_proto_by_name(const char *);
extern int get_family_by_proto(enum sock_proto proto);
typedef enum {
 CFLAG_NONE = 0,
 CFLAG_ONLY_STATS,
 CFLAG_BOTH
} cflag_t;
extern cflag_t cflag;
extern _Bool Tflag;
extern int Tflag_scale;
extern int Tflag_width;
extern _Bool iflag;
extern _Bool count_wallclock;
struct path_set_item {
 const char *path;
};
extern struct path_set {
 struct path_set_item *paths_selected;
 size_t num_selected;
 size_t size;
} global_path_set;
enum xflag_opts {
 HEXSTR_NONE,
 HEXSTR_NON_ASCII,
 HEXSTR_ALL,
 HEXSTR_NON_ASCII_CHARS,
 NUM_HEXSTR_OPTS
};
extern unsigned xflag;
extern _Bool followfork;
extern _Bool output_separately;
extern _Bool stack_trace_enabled;
extern unsigned ptrace_setoptions;
extern unsigned max_strlen;
extern unsigned os_release;
extern int read_int_from_file(const char *, int *);
extern void set_sortby(const char *);
extern int set_overhead(const char *);
extern void set_count_summary_columns(const char *columns);
extern _Bool get_instruction_pointer(struct tcb *, kernel_ulong_t *);
extern _Bool get_stack_pointer(struct tcb *, kernel_ulong_t *);
extern void print_instruction_pointer(struct tcb *);
extern void print_syscall_number(struct tcb *);
extern void print_syscall_resume(struct tcb *tcp);
extern int syscall_entering_decode(struct tcb *);
extern int syscall_entering_trace(struct tcb *, unsigned int *);
extern void syscall_entering_finish(struct tcb *, int);
extern int syscall_exiting_decode(struct tcb *, struct timespec *);
extern int syscall_exiting_trace(struct tcb *, struct timespec *, int);
extern void syscall_exiting_finish(struct tcb *);
extern void count_syscall(struct tcb *, const struct timespec *);
extern void call_summary(FILE *);
extern void clear_regs(struct tcb *tcp);
extern int get_scno(struct tcb *);
extern kernel_ulong_t get_rt_sigframe_addr(struct tcb *);
extern const char *syscall_name_arch(kernel_ulong_t nr, unsigned int arch,
         const char **prefix);
extern kernel_long_t scno_by_name(const char *s, unsigned p,
      kernel_long_t start);
extern kernel_ulong_t shuffle_scno_pers(kernel_ulong_t scno, int pers);
static inline kernel_ulong_t
shuffle_scno(kernel_ulong_t scno)
{
 return shuffle_scno_pers(scno, current_personality);
}
extern void print_err(int64_t err, _Bool negated);
extern _Bool is_erestart(struct tcb *);
extern void temporarily_clear_syserror(struct tcb *);
extern void restore_cleared_syserror(struct tcb *);
extern void *get_tcb_priv_data(const struct tcb *);
extern int set_tcb_priv_data(struct tcb *, void *priv_data,
        void (*free_priv_data)(void *));
extern void free_tcb_priv_data(struct tcb *);
static inline unsigned long get_tcb_priv_ulong(const struct tcb *tcp)
{
 return (unsigned long) get_tcb_priv_data(tcp);
}
static inline int set_tcb_priv_ulong(struct tcb *tcp, unsigned long val)
{
 return set_tcb_priv_data(tcp, (void *) val, 0);
}
extern int
umoven(struct tcb *, kernel_ulong_t addr, unsigned int len, void *laddr);
extern unsigned int
upoken(struct tcb *, kernel_ulong_t addr, unsigned int len, void *laddr);
extern _Bool
tfetch_mem64(struct tcb *, uint64_t addr, unsigned int len, void *laddr);
static inline _Bool
tfetch_mem(struct tcb *tcp, const kernel_ulong_t addr,
    unsigned int len, void *laddr)
{
 return tfetch_mem64(tcp, addr, len, laddr);
}
extern _Bool
tfetch_mem64_ignore_syserror(struct tcb *, uint64_t addr,
        unsigned int len, void *laddr);
static inline _Bool
tfetch_mem_ignore_syserror(struct tcb *tcp, const kernel_ulong_t addr,
      unsigned int len, void *laddr)
{
 return tfetch_mem64_ignore_syserror(tcp, addr, len, laddr);
}
extern int
umoven_or_printaddr64(struct tcb *, uint64_t addr,
        unsigned int len, void *laddr);
static inline int
umoven_or_printaddr(struct tcb *tcp, const kernel_ulong_t addr,
      unsigned int len, void *laddr)
{
 return umoven_or_printaddr64(tcp, addr, len, laddr);
}
extern int
umoven_to_uint64_or_printaddr64(struct tcb *, uint64_t addr,
    unsigned int len, uint64_t *laddr);
static inline int
umoven_to_uint64_or_printaddr(struct tcb *tcp, const kernel_ulong_t addr,
         unsigned int len, uint64_t *laddr)
{
 return umoven_to_uint64_or_printaddr64(tcp, addr, len, laddr);
}
extern int
umoven_or_printaddr64_ignore_syserror(struct tcb *, uint64_t addr,
          unsigned int len, void *laddr);
static inline int
umoven_or_printaddr_ignore_syserror(struct tcb *tcp, const kernel_ulong_t addr,
        unsigned int len, void *laddr)
{
 return umoven_or_printaddr64_ignore_syserror(tcp, addr, len, laddr);
}
extern int
umovestr(struct tcb *, kernel_ulong_t addr, unsigned int len, char *laddr);
extern void invalidate_umove_cache(void);
extern int upeek(struct tcb *tcp, unsigned long, kernel_ulong_t *);
extern int upoke(struct tcb *tcp, unsigned long, kernel_ulong_t);
extern const char *signame(const int);
extern const char *sprintsigname(const int);
extern void pathtrace_select_set(const char *, struct path_set *);
extern _Bool pathtrace_match_set(struct tcb *, struct path_set *);
static inline void
pathtrace_select(const char *path)
{
 return pathtrace_select_set(path, &global_path_set);
}
static inline _Bool
pathtrace_match(struct tcb *tcp)
{
 return pathtrace_match_set(tcp, &global_path_set);
}
extern int get_proc_pid_fd_path(int proc_pid, int fd, char *buf,
    unsigned bufsize, _Bool *deleted);
extern int getfdpath_pid(pid_t pid, int fd, char *buf, unsigned bufsize,
    _Bool *deleted);
static inline int
getfdpath(struct tcb *tcp, int fd, char *buf, unsigned bufsize)
{
 return getfdpath_pid(tcp->pid, fd, buf, bufsize, ((void *)0));
}
extern unsigned long getfdinode(struct tcb *, int);
extern enum sock_proto getfdproto(struct tcb *, int);
extern const char *xlookup(const struct xlat *, const uint64_t);
extern const char *xlookup_le(const struct xlat *, uint64_t *);
struct dyxlat;
struct dyxlat *dyxlat_alloc(size_t nmemb);
void dyxlat_free(struct dyxlat *);
const struct xlat *dyxlat_get(const struct dyxlat *);
void dyxlat_add_pair(struct dyxlat *, uint64_t val, const char *str, size_t len);
const struct xlat *genl_families_xlat(struct tcb *tcp);
extern unsigned long get_pagesize(void);
extern int next_set_bit(const void *bit_array, unsigned cur_bit, unsigned size_bits);
static inline const char *
str_strip_prefix_len(const char *str, const char *prefix, size_t prefix_len)
{
 return strncmp(str, prefix, prefix_len) ? str : str + prefix_len;
}
_Static_assert((NUM_HEXSTR_OPTS - 1) <= ((0x3 << 8) >> 8),
       "xflag options do not fit into QUOTE_HEXSTR_MASK");
extern int string_quote(const char *, char *, unsigned int, unsigned int,
   const char *escape_chars);
extern int print_quoted_string_ex(const char *, unsigned int, unsigned int,
      const char *escape_chars);
extern int print_quoted_string(const char *, unsigned int, unsigned int);
extern int print_quoted_cstring(const char *, unsigned int);
extern unsigned int getllval(struct tcb *, unsigned long long *, unsigned int);
extern unsigned int print_arg_lld(struct tcb *, unsigned int);
extern unsigned int print_arg_llu(struct tcb *, unsigned int);
extern void printaddr64(uint64_t addr);
static inline void
printaddr(const kernel_ulong_t addr)
{
 printaddr64(addr);
}
extern enum xlat_style xlat_verbosity;
extern int printxvals_ex(uint64_t val, const char *dflt,
    enum xlat_style, const struct xlat *, ...)
 __attribute__((__sentinel__));
extern int sprintxval_ex(char *buf, size_t size, const struct xlat *,
    unsigned int val, const char *dflt, enum xlat_style);
static inline int
sprintxval(char *buf, size_t size, const struct xlat *xlat, unsigned int val,
    const char *dflt)
{
 return sprintxval_ex(buf, size, xlat, val, dflt, XLAT_STYLE_DEFAULT);
}
enum xlat_style_private_flag_bits {
 PAF_PRINT_INDICES_BIT = (2 + 2) + 1,
 PAF_ARRAY_TRUNCATED_BIT,
 PXF_DEFAULT_STR_BIT,
 SPFF_AUXSTR_MODE_BIT,
};
enum xlat_style_private_flags {
 PAF_PRINT_INDICES = (1U << (PAF_PRINT_INDICES_BIT)),
 PAF_ARRAY_TRUNCATED = (1U << (PAF_ARRAY_TRUNCATED_BIT)),
 PXF_DEFAULT_STR = (1U << (PXF_DEFAULT_STR_BIT)),
 SPFF_AUXSTR_MODE = (1U << (SPFF_AUXSTR_MODE_BIT)),
};
extern void print_xlat_ex(uint64_t val, const char *str, uint32_t style);
extern int printargs(struct tcb *);
extern int printargs_u(struct tcb *);
extern int printargs_d(struct tcb *);
extern int printflags_ex(uint64_t flags, const char *dflt,
    enum xlat_style, const struct xlat *, ...)
 __attribute__((__sentinel__));
extern const char *sprintflags_ex(const char *prefix, const struct xlat *,
      uint64_t flags, char sep, enum xlat_style);
static inline const char *
sprintflags(const char *prefix, const struct xlat *xlat, uint64_t flags)
{
 return sprintflags_ex(prefix, xlat, flags, '\0', XLAT_STYLE_DEFAULT);
}
extern const char *sprinttime(long long sec);
extern const char *sprinttime_nsec(long long sec, unsigned long long nsec);
extern const char *sprinttime_usec(long long sec, unsigned long long usec);
extern void print_mac_addr(const char *prefix,
      const uint8_t addr[], size_t size);
extern void print_hwaddr(const char *prefix,
    const uint8_t addr[], size_t size, uint32_t devtype);
extern void print_uuid(const unsigned char *uuid);
extern void print_symbolic_mode_t(unsigned int);
extern void print_numeric_umode_t(unsigned short);
extern void print_numeric_ll_umode_t(unsigned long long);
extern void print_dev_t(unsigned long long dev);
extern void print_kernel_version(unsigned long version);
extern void print_abnormal_hi(kernel_ulong_t);
extern void print_ioprio(unsigned int ioprio);
extern _Bool print_int_array_member(struct tcb *, void *elem_buf,
       size_t elem_size, void *data);
extern _Bool print_uint_array_member(struct tcb *, void *elem_buf,
        size_t elem_size, void *data);
extern _Bool print_xint_array_member(struct tcb *, void *elem_buf,
        size_t elem_size, void *data);
extern _Bool print_fd_array_member(struct tcb *, void *elem_buf,
      size_t elem_size, void *data);
typedef _Bool (*tfetch_mem_fn)(struct tcb *, kernel_ulong_t addr,
         unsigned int size, void *dest);
typedef _Bool (*print_fn)(struct tcb *, void *elem_buf,
    size_t elem_size, void *opaque_data);
typedef int (*print_obj_by_addr_fn)(struct tcb *, kernel_ulong_t);
typedef const char * (*sprint_obj_by_addr_fn)(struct tcb *, kernel_ulong_t);
typedef void (*print_obj_by_addr_size_fn)(struct tcb *,
       kernel_ulong_t addr,
       kernel_ulong_t size,
       void *opaque_data);
extern _Bool
print_array_ex(struct tcb *,
        kernel_ulong_t start_addr,
        size_t nmemb,
        void *elem_buf,
        size_t elem_size,
        tfetch_mem_fn tfetch_mem_func,
        print_fn print_func,
        void *opaque_data,
        unsigned int flags,
        const struct xlat *index_xlat,
        const char *index_dflt);
static inline _Bool
print_array(struct tcb *const tcp,
     const kernel_ulong_t start_addr,
     const size_t nmemb,
     void *const elem_buf,
     const size_t elem_size,
     tfetch_mem_fn tfetch_mem_func,
     print_fn print_func,
     void *const opaque_data)
{
 return print_array_ex(tcp, start_addr, nmemb, elem_buf, elem_size,
         tfetch_mem_func, print_func, opaque_data,
         0, ((void *)0), ((void *)0));
}
static inline _Bool
print_local_array_ex(struct tcb *tcp,
       const void *start_addr,
       const size_t nmemb,
       const size_t elem_size,
       print_fn print_func,
       void *const opaque_data,
       unsigned int flags,
       const struct xlat *index_xlat,
       const char *index_dflt)
{
 return print_array_ex(tcp, (uintptr_t) start_addr, nmemb,
         ((void *)0), elem_size, ((void *)0), print_func,
         opaque_data, flags, index_xlat, index_dflt);
}
extern kernel_ulong_t *
fetch_indirect_syscall_args(struct tcb *, kernel_ulong_t addr, unsigned int n_args);
extern void pidns_init(void);
extern int get_proc_pid(int pid);
extern int translate_pid(struct tcb *, int dest_id, enum pid_type type,
      int *proc_pid_ptr);
extern void
dumpiov_in_msghdr(struct tcb *, kernel_ulong_t addr, kernel_ulong_t data_size);
extern void
dumpiov_in_mmsghdr(struct tcb *, kernel_ulong_t addr);
extern void
dumpiov_upto(struct tcb *, int len, kernel_ulong_t addr, kernel_ulong_t data_size);
extern void
dumpstr(struct tcb *, kernel_ulong_t addr, kernel_ulong_t len);
extern int
printstr_ex(struct tcb *, kernel_ulong_t addr, kernel_ulong_t len,
     unsigned int user_style);
extern _Bool print_nonzero_bytes(struct tcb *const tcp,
    void (*prefix_fun)(void),
    const kernel_ulong_t start_addr,
    const unsigned int start_offs,
    const unsigned int total_len,
    const unsigned int style);
extern int
printpathn(struct tcb *, kernel_ulong_t addr, unsigned int n);
extern int
printpath(struct tcb *, kernel_ulong_t addr);
extern pid_t pidfd_get_pid(pid_t pid_of_fd, int fd);
extern void printfd_pid(struct tcb *tcp, pid_t pid, int fd);
static inline void
printfd(struct tcb *tcp, int fd)
{
 printfd_pid(tcp, tcp->pid, fd);
}
extern const char *pid_to_str(pid_t pid);
extern size_t proc_status_get_id_list(int proc_pid,
          int *id_buf, size_t id_buf_size,
          const char *str, size_t str_size);
extern void printfd_pid_tracee_ns(struct tcb *tcp, pid_t pid, int fd);
extern void printpid(struct tcb *, int pid, enum pid_type type);
extern void printpid_tgid_pgid(struct tcb *, int pid);
extern void print_sockaddr(struct tcb *, const void *sa, int len);
extern _Bool
print_inet_addr(int af, const void *addr, unsigned int len, const char *var_name);
extern _Bool
decode_inet_addr(struct tcb *, kernel_ulong_t addr,
   unsigned int len, int family, const char *var_name);
extern void print_ax25_addr(const void *addr);
extern void print_x25_addr(const void *addr);
extern const char *get_sockaddr_by_inode(struct tcb *, int fd, unsigned long inode);
extern void print_dirfd(struct tcb *, int);
extern int
decode_sockaddr(struct tcb *, kernel_ulong_t addr, int addrlen);
extern void printuid(const unsigned int);
extern void
print_sigset_addr_len(struct tcb *, kernel_ulong_t addr, kernel_ulong_t len);
extern void
print_sigset_addr(struct tcb *, kernel_ulong_t addr);
extern const char *sprintsigmask_n(const char *, const void *, unsigned int);
extern void printsignal(int);
extern void
tprint_iov_upto(struct tcb *, kernel_ulong_t len, kernel_ulong_t addr,
  kernel_ulong_t data_size, print_obj_by_addr_size_fn,
  void *opaque_data);
extern void
iov_decode_addr(struct tcb *, kernel_ulong_t addr, kernel_ulong_t size,
  void *opaque_data);
extern void
iov_decode_str(struct tcb *, kernel_ulong_t addr, kernel_ulong_t size,
        void *opaque_data);
extern void
decode_netlink(struct tcb *, int fd, kernel_ulong_t addr, kernel_ulong_t len);
extern void tprint_open_modes(unsigned int);
extern const char *sprint_open_modes(unsigned int);
extern void
decode_seccomp_fprog(struct tcb *, kernel_ulong_t addr);
extern void
print_seccomp_fprog(struct tcb *, kernel_ulong_t addr, unsigned short len);
extern void
decode_sock_fprog(struct tcb *, kernel_ulong_t addr);
extern void
print_sock_fprog(struct tcb *, kernel_ulong_t addr, unsigned short len);
struct strace_stat;
extern void print_struct_stat(struct tcb *, const struct strace_stat *const st);
struct strace_statfs;
struct strace_keyctl_kdf_params;
extern void
print_struct_statfs(struct tcb *, kernel_ulong_t addr);
extern void
print_struct_statfs64(struct tcb *, kernel_ulong_t addr, kernel_ulong_t size);
extern int
fetch_perf_event_attr(struct tcb *const tcp, const kernel_ulong_t addr);
extern void
print_perf_event_attr(struct tcb *const tcp, const kernel_ulong_t addr);
extern const char *get_ifname(const unsigned int ifindex);
extern void print_ifindex(unsigned int);
struct tcpvegas_info;
extern void print_tcpvegas_info(struct tcb *tcp,
    const struct tcpvegas_info *vegas,
    unsigned int len);
struct tcp_dctcp_info;
extern void print_tcp_dctcp_info(struct tcb *tcp,
     const struct tcp_dctcp_info *dctcp,
     unsigned int len);
struct tcp_bbr_info;
extern void print_tcp_bbr_info(struct tcb *tcp, const struct tcp_bbr_info *bbr,
          unsigned int len);
extern void print_bpf_filter_code(const uint16_t code, _Bool extended);
extern void print_affinitylist(struct tcb *const tcp, const kernel_ulong_t addr,
          const unsigned int len);
extern void qualify(const char *);
extern void qualify_trace(const char *);
extern void qualify_abbrev(const char *);
extern void qualify_verbose(const char *);
extern void qualify_raw(const char *);
extern void qualify_signals(const char *);
extern void qualify_status(const char *);
extern void qualify_quiet(const char *);
extern void qualify_decode_fd(const char *);
extern void qualify_decode_pid(const char *);
extern void qualify_read(const char *);
extern void qualify_write(const char *);
extern void qualify_fault(const char *);
extern void qualify_inject(const char *);
extern void qualify_kvm(const char *);
extern unsigned int qual_flags(const unsigned int);
extern int counter_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int dm_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int evdev_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int fs_0x94_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int fs_f_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int fs_x_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int gpio_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int inotify_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int kd_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int kvm_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int lirc_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int nbd_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int nsfs_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int ptp_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int random_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int seccomp_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int scsi_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int tee_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int term_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int ubi_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int uffdio_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int watchdog_ioctl(struct tcb *, unsigned int request, kernel_ulong_t arg);
extern int decode_sg_io_v4(struct tcb *, const kernel_ulong_t arg);
extern void print_evdev_ff_type(const kernel_ulong_t val);
struct nlmsghdr;
typedef _Bool (*netlink_decoder_t)(struct tcb *, const struct nlmsghdr *,
      kernel_ulong_t addr, unsigned int len);
extern _Bool decode_netlink_crypto(struct tcb *, const struct nlmsghdr *, kernel_ulong_t addr, unsigned int len);
extern _Bool decode_netlink_netfilter(struct tcb *, const struct nlmsghdr *, kernel_ulong_t addr, unsigned int len);
extern _Bool decode_netlink_route(struct tcb *, const struct nlmsghdr *, kernel_ulong_t addr, unsigned int len);
extern _Bool decode_netlink_selinux(struct tcb *, const struct nlmsghdr *, kernel_ulong_t addr, unsigned int len);
extern _Bool decode_netlink_sock_diag(struct tcb *, const struct nlmsghdr *, kernel_ulong_t addr, unsigned int len);
extern void
decode_netlink_kobject_uevent(struct tcb *, kernel_ulong_t addr,
         kernel_ulong_t len);
enum find_xlat_flag_bits {
 FXL_CASE_SENSITIVE_BIT,
};
enum find_xlat_flags {
 FXL_CASE_SENSITIVE = (1U << (FXL_CASE_SENSITIVE_BIT)),
};
extern const struct xlat_data *find_xlat_val_ex(const struct xlat_data *items,
      const char *s, size_t num_items,
      unsigned int flags);
extern uint64_t find_arg_val_(const char *arg, const struct xlat_data *strs,
         size_t strs_size, uint64_t default_val,
         uint64_t not_found);
extern int str2timescale_ex(const char *arg, int empty_dflt, int null_dflt,
       int *width);
extern int ts_nz(const struct timespec *);
extern int ts_cmp(const struct timespec *, const struct timespec *);
extern double ts_float(const struct timespec *);
extern void ts_add(struct timespec *, const struct timespec *, const struct timespec *);
extern void ts_sub(struct timespec *, const struct timespec *, const struct timespec *);
extern void ts_div(struct timespec *, const struct timespec *, uint64_t);
extern const struct timespec *ts_min(const struct timespec *, const struct timespec *);
extern const struct timespec *ts_max(const struct timespec *, const struct timespec *);
extern int parse_ts(const char *s, struct timespec *t);
extern void print_clock_t(uint64_t val);
extern void unwind_init(void);
extern void unwind_tcb_init(struct tcb *);
extern void unwind_tcb_fin(struct tcb *);
extern void unwind_tcb_print(struct tcb *);
extern void unwind_tcb_capture(struct tcb *);
extern void kvm_run_structure_decoder_init(void);
extern void kvm_vcpu_info_free(struct tcb *);
extern void maybe_load_task_comm(struct tcb *tcp);
extern void print_pid_comm(int pid);
static inline int
printstrn(struct tcb *tcp, kernel_ulong_t addr, kernel_ulong_t len)
{
 return printstr_ex(tcp, addr, len, 0);
}
static inline int
printstr(struct tcb *tcp, kernel_ulong_t addr)
{
 return printstr_ex(tcp, addr, -1, 0x01);
}
static inline int
printflags64_in(const struct xlat *x, uint64_t flags, const char *dflt)
{
 return printflags_ex(flags, dflt, XLAT_STYLE_DEFAULT, x, ((void *)0));
}
static inline int
printflags_in(const struct xlat *x, unsigned int flags, const char *dflt)
{
 return printflags64_in(x, flags, dflt);
}
static inline int
printxval64(const struct xlat *x, const uint64_t val, const char *dflt)
{
 return printxvals_ex((val), (dflt), XLAT_STYLE_DEFAULT, x, ((void *)0));
}
static inline int
printxval(const struct xlat *x, const unsigned int val, const char *dflt)
{
 return printxvals_ex((val), (dflt), XLAT_STYLE_DEFAULT, x, ((void *)0));
}
static inline int
printxval64_u(const struct xlat *x, const uint64_t val, const char *dflt)
{
 return printxvals_ex(val, dflt, XLAT_STYLE_FMT_U, x, ((void *)0));
}
static inline int
printxval_u(const struct xlat *x, const unsigned int val, const char *dflt)
{
 return printxvals_ex(val, dflt, XLAT_STYLE_FMT_U, x, ((void *)0));
}
static inline int
printxval64_d(const struct xlat *x, const int64_t val, const char *dflt)
{
 return printxvals_ex(val, dflt, XLAT_STYLE_FMT_D, x, ((void *)0));
}
static inline int
printxval_d(const struct xlat *x, const int val, const char *dflt)
{
 return printxvals_ex(val, dflt, XLAT_STYLE_FMT_D, x, ((void *)0));
}
static inline void
tprint_iov(struct tcb *tcp, kernel_ulong_t len, kernel_ulong_t addr,
    print_obj_by_addr_size_fn print_func)
{
 tprint_iov_upto(tcp, len, addr, -1, print_func, ((void *)0));
}
extern _Bool print_timespec32_data_size(const void *arg, size_t size);
extern _Bool print_timespec32_array_data_size(const void *arg,
          unsigned int nmemb,
          size_t size);
extern int print_timespec32(struct tcb *, kernel_ulong_t);
extern const char *sprint_timespec32(struct tcb *, kernel_ulong_t);
extern int print_timespec32_utime_pair(struct tcb *, kernel_ulong_t);
extern int print_itimerspec32(struct tcb *, kernel_ulong_t);
extern int print_timex32(struct tcb *, kernel_ulong_t);
extern _Bool print_timespec64_data_size(const void *arg, size_t size);
extern _Bool print_timespec64_array_data_size(const void *arg,
          unsigned int nmemb,
          size_t size);
extern int print_timespec64(struct tcb *, kernel_ulong_t);
extern const char *sprint_timespec64(struct tcb *, kernel_ulong_t);
extern int print_timespec64_utime_pair(struct tcb *, kernel_ulong_t);
extern int print_itimerspec64(struct tcb *, kernel_ulong_t);
extern _Bool print_timeval64_data_size(const void *arg, size_t size);
extern int print_timex64(struct tcb *, kernel_ulong_t);
enum user_desc_print_filter {
 USER_DESC_ENTERING = 1,
 USER_DESC_EXITING = 2,
 USER_DESC_BOTH = USER_DESC_ENTERING | USER_DESC_EXITING,
};
extern void print_user_desc(struct tcb *, kernel_ulong_t addr,
       enum user_desc_print_filter filter);
extern struct tcb *printing_tcp;
extern void printleader(struct tcb *);
extern void line_ended(void);
extern void tabto(void);
extern void tprintf_string(const char *fmt, ...) __attribute__((__format__ (printf, 1, 2)));
extern void tprints_string(const char *str);
extern void tprintf_comment(const char *fmt, ...) __attribute__((__format__ (printf, 1, 2)));
extern void tprints_comment(const char *str);
extern FILE *strace_open_memstream(struct tcb *tcp);
extern void strace_close_memstream(struct tcb *tcp, _Bool publish);
static inline void
printaddr_comment(const kernel_ulong_t addr)
{
 tprintf_comment("%#llx", (unsigned long long) addr);
}
extern _Bool printnum_short(struct tcb *, kernel_ulong_t addr, const char *fmt) __attribute__((__format__ (printf, 3, 0)));
extern _Bool printnum_int(struct tcb *, kernel_ulong_t addr, const char *fmt) __attribute__((__format__ (printf, 3, 0)));
extern _Bool printnum_int64(struct tcb *, kernel_ulong_t addr, const char *fmt) __attribute__((__format__ (printf, 3, 0)));
extern _Bool printnum_addr_int(struct tcb *, kernel_ulong_t addr);
extern _Bool printnum_addr_int64(struct tcb *, kernel_ulong_t addr);
extern _Bool
printnum_fd(struct tcb *, kernel_ulong_t addr);
extern _Bool
printnum_pid(struct tcb *const tcp, const kernel_ulong_t addr, enum pid_type type);
static inline _Bool
printnum_slong(struct tcb *tcp, kernel_ulong_t addr)
{
 return ((current_wordsize > sizeof(uint32_t)) ? (printnum_int64)(tcp, addr, ((current_wordsize > sizeof(uint32_t)) ? ("%" "l" "d") : ("%d"))) : (printnum_int)(tcp, addr, ((current_wordsize > sizeof(uint32_t)) ? ("%" "l" "d") : ("%d"))));
}
static inline _Bool
printnum_ulong(struct tcb *tcp, kernel_ulong_t addr)
{
 return ((current_wordsize > sizeof(uint32_t)) ? (printnum_int64)(tcp, addr, ((current_wordsize > sizeof(uint32_t)) ? ("%" "l" "u") : ("%u"))) : (printnum_int)(tcp, addr, ((current_wordsize > sizeof(uint32_t)) ? ("%" "l" "u") : ("%u"))));
}
static inline _Bool
printnum_ptr(struct tcb *tcp, kernel_ulong_t addr)
{
 return ((current_wordsize > sizeof(uint32_t)) ? (printnum_addr_int64)(tcp, addr) : (printnum_addr_int)(tcp, addr));
}
static inline _Bool
printnum_kptr(struct tcb *tcp, kernel_ulong_t addr)
{
 return ((current_klongsize > sizeof(uint32_t)) ? (printnum_addr_int64)(tcp, addr) : (printnum_addr_int)(tcp, addr));
}
extern _Bool printpair_int(struct tcb *, kernel_ulong_t addr, const char *fmt) __attribute__((__format__ (printf, 3, 0)));
extern _Bool printpair_int64(struct tcb *, kernel_ulong_t addr, const char *fmt) __attribute__((__format__ (printf, 3, 0)));
static inline kernel_long_t
truncate_klong_to_current_wordsize(const kernel_long_t v)
{
 if (current_wordsize < sizeof(v)) {
  return (int) v;
 } else
 {
  return v;
 }
}
static inline kernel_ulong_t
truncate_kulong_to_current_wordsize(const kernel_ulong_t v)
{
 if (current_wordsize < sizeof(v)) {
  return (unsigned int) v;
 } else
 {
  return v;
 }
}
static inline kernel_long_t
truncate_klong_to_current_klongsize(const kernel_long_t v)
{
 if (current_klongsize < sizeof(v)) {
  return (int) v;
 } else
 {
  return v;
 }
}
static inline kernel_ulong_t
truncate_kulong_to_current_klongsize(const kernel_ulong_t v)
{
 if (current_klongsize < sizeof(v)) {
  return (unsigned int) v;
 } else
 {
  return v;
 }
}
static inline unsigned int
popcount32(const uint32_t *a, unsigned int size)
{
 unsigned int count = 0;
 for (; size; ++a, --size) {
  uint32_t x = *a;
  count += __builtin_popcount(x);
 }
 return count;
}
extern const char *const errnoent[];
extern const char *const signalent[];
extern const unsigned int nerrnos;
extern const unsigned int nsignals;
extern const struct_sysent sysent0[];
extern const struct_ioctlent ioctlent0[];
extern const char *const personality_names[];
extern const struct_sysent *sysent;
extern const struct_ioctlent *ioctlent;
extern unsigned nsyscalls;
extern unsigned nioctlents;
extern const unsigned int nsyscall_vec[3];
extern const struct_sysent *const sysent_vec[3];
extern struct inject_opts *inject_vec[3];
struct audit_arch_t {
 unsigned int arch;
 unsigned int flag;
};
extern const struct audit_arch_t audit_arch_vec[3];
static inline _Bool
scno_in_range(kernel_ulong_t scno)
{
 return scno < nsyscalls;
}
static inline _Bool
scno_pers_in_range(kernel_ulong_t scno, unsigned int pers)
{
 return scno < nsyscall_vec[pers];
}
static inline _Bool
scno_is_valid(kernel_ulong_t scno)
{
 return scno_in_range(scno)
        && sysent[scno].sys_func
        && !(sysent[scno].sys_flags & 000002000);
}
static inline _Bool
scno_pers_is_valid(kernel_ulong_t scno, unsigned int pers)
{
 return scno_pers_in_range(scno, pers)
        && sysent_vec[pers][scno].sys_func
        && !(sysent_vec[pers][scno].sys_flags & 000002000);
}
static inline unsigned int
ilog2_64(uint64_t val)
{
 unsigned int ret = 0;
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (5))) - 1)) << (5); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (4))) - 1)) << (4); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (3))) - 1)) << (3); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (2))) - 1)) << (2); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (1))) - 1)) << (1); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (0))) - 1)) << (0); (val) >>= shift_; (ret) |= shift_; } while (0);
 return ret;
}
static inline unsigned int
ilog2_32(uint32_t val)
{
 unsigned int ret = 0;
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (4))) - 1)) << (4); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (3))) - 1)) << (3); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (2))) - 1)) << (2); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (1))) - 1)) << (1); (val) >>= shift_; (ret) |= shift_; } while (0);
 do { typeof(ret) shift_ = ((val) > ((((typeof(val)) 1) << (1 << (0))) - 1)) << (0); (val) >>= shift_; (ret) |= shift_; } while (0);
 return ret;
}
static inline void
tprint_struct_begin(void)
{
 tprints_string("{");
}
static inline void
tprint_struct_next(void)
{
 tprints_string(", ");
}
static inline void
tprint_struct_end(void)
{
 tprints_string("}");
}
static inline void
tprint_union_begin(void)
{
 tprints_string("{");
}
static inline void
tprint_union_next(void)
{
 tprints_string(", ");
}
static inline void
tprint_union_end(void)
{
 tprints_string("}");
}
static inline void
tprint_array_begin(void)
{
 tprints_string("[");
}
static inline void
tprint_array_next(void)
{
 tprints_string(", ");
}
static inline void
tprint_array_end(void)
{
 tprints_string("]");
}
static inline void
tprint_array_index_begin(void)
{
 tprints_string("[");
}
static inline void
tprint_array_index_equal(void)
{
 tprints_string("]=");
}
static inline void
tprint_array_index_end(void)
{
}
static inline void
tprint_arg_next(void)
{
 tprints_string(", ");
}
static inline void
tprint_arg_end(void)
{
 tprints_string(")");
}
static inline void
tprint_bitset_begin(void)
{
 tprints_string("[");
}
static inline void
tprint_bitset_next(void)
{
 tprints_string(" ");
}
static inline void
tprint_bitset_end(void)
{
 tprints_string("]");
}
static inline void
tprint_comment_begin(void)
{
 tprints_string(" /* ");
}
static inline void
tprint_comment_end(void)
{
 tprints_string(" */");
}
static inline void
tprint_indirect_begin(void)
{
 tprints_string("[");
}
static inline void
tprint_indirect_end(void)
{
 tprints_string("]");
}
static inline void
tprint_attribute_begin(void)
{
 tprints_string("[");
}
static inline void
tprint_attribute_end(void)
{
 tprints_string("]");
}
static inline void
tprint_associated_info_begin(void)
{
 tprints_string("<");
}
static inline void
tprint_associated_info_end(void)
{
 tprints_string(">");
}
static inline void
tprint_more_data_follows(void)
{
 tprints_string("...");
}
static inline void
tprint_value_changed(void)
{
 tprints_string(" => ");
}
static inline void
tprint_alternative_value(void)
{
 tprints_string(" or ");
}
static inline void
tprint_unavailable(void)
{
 tprints_string("???");
}
static inline void
tprint_shift_begin(void)
{
}
static inline void
tprint_shift_end(void)
{
}
static inline void
tprint_shift(void)
{
 tprints_string("<<");
}
static inline void
tprint_flags_begin(void)
{
}
static inline void
tprint_flags_or(void)
{
 tprints_string("|");
}
static inline void
tprint_flags_end(void)
{
}
static inline void
tprint_plus(void)
{
 tprints_string("+");
}
static inline void
tprint_space(void)
{
 tprints_string(" ");
}
static inline void
tprint_null(void)
{
 tprints_string("NULL");
}
static inline void
tprint_newline(void)
{
 tprints_string("\n");
}
static inline void
tprints_field_name(const char *name)
{
 tprintf_string("%s=", name);
}
static inline void
tprints_arg_name_begin(const char *name)
{
 tprintf_string("%s=", name);
}
static inline void
tprint_arg_name_end(void)
{
}
static inline void
tprints_arg_begin(const char *name)
{
 tprintf_string("%s(", name);
}
static inline void
tprint_sysret_begin(void)
{
 tprints_string("=");
}
static inline void
tprints_sysret_next(const char *name)
{
 tprint_space();
}
static inline void
tprints_sysret_string(const char *name, const char *str)
{
 tprints_sysret_next(name);
 tprintf_string("(%s)", str);
}
static inline void
tprint_sysret_pseudo_rval(void)
{
 tprints_string("?");
}
static inline void
tprint_sysret_end(void)
{
}
static inline int
printflags64(const struct xlat *x, uint64_t flags, const char *dflt)
{
 tprint_flags_begin();
 int r = printflags64_in(x, flags, dflt);
 tprint_flags_end();
 return r;
}
static inline int
printflags(const struct xlat *x, unsigned int flags, const char *dflt)
{
 return printflags64(x, flags, dflt);
}
typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __signed__ int __s32;
typedef unsigned int __u32;
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
typedef struct {
 unsigned long fds_bits[1024 / (8 * sizeof(long))];
} __kernel_fd_set;
typedef void (*__kernel_sighandler_t)(int);
typedef int __kernel_key_t;
typedef int __kernel_mqd_t;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;
typedef unsigned __poll_t;
struct fscrypt_policy_v1 {
 __u8 version;
 __u8 contents_encryption_mode;
 __u8 filenames_encryption_mode;
 __u8 flags;
 __u8 master_key_descriptor[8];
};
struct fscrypt_key {
 __u32 mode;
 __u8 raw[64];
 __u32 size;
};
struct fscrypt_policy_v2 {
 __u8 version;
 __u8 contents_encryption_mode;
 __u8 filenames_encryption_mode;
 __u8 flags;
 __u8 __reserved[4];
 __u8 master_key_identifier[16];
};
struct fscrypt_get_policy_ex_arg {
 __u64 policy_size;
 union {
  __u8 version;
  struct fscrypt_policy_v1 v1;
  struct fscrypt_policy_v2 v2;
 } policy;
};
struct fscrypt_key_specifier {
 __u32 type;
 __u32 __reserved;
 union {
  __u8 __reserved[32];
  __u8 descriptor[8];
  __u8 identifier[16];
 } u;
};
struct fscrypt_provisioning_key_payload {
 __u32 type;
 __u32 __reserved;
 __u8 raw[];
};
struct fscrypt_add_key_arg {
 struct fscrypt_key_specifier key_spec;
 __u32 raw_size;
 __u32 key_id;
 __u32 __reserved[8];
 __u8 raw[];
};
struct fscrypt_remove_key_arg {
 struct fscrypt_key_specifier key_spec;
 __u32 removal_status_flags;
 __u32 __reserved[5];
};
struct fscrypt_get_key_status_arg {
 struct fscrypt_key_specifier key_spec;
 __u32 __reserved[6];
 __u32 status;
 __u32 status_flags;
 __u32 user_count;
 __u32 __out_reserved[13];
};
enum fsconfig_command {
 FSCONFIG_SET_FLAG = 0,
 FSCONFIG_SET_STRING = 1,
 FSCONFIG_SET_BINARY = 2,
 FSCONFIG_SET_PATH = 3,
 FSCONFIG_SET_PATH_EMPTY = 4,
 FSCONFIG_SET_FD = 5,
 FSCONFIG_CMD_CREATE = 6,
 FSCONFIG_CMD_RECONFIGURE = 7,
};
struct mount_attr {
 __u64 attr_set;
 __u64 attr_clr;
 __u64 propagation;
 __u64 userns_fd;
};
struct file_clone_range {
 __s64 src_fd;
 __u64 src_offset;
 __u64 src_length;
 __u64 dest_offset;
};
struct fstrim_range {
 __u64 start;
 __u64 len;
 __u64 minlen;
};
struct file_dedupe_range_info {
 __s64 dest_fd;
 __u64 dest_offset;
 __u64 bytes_deduped;
 __s32 status;
 __u32 reserved;
};
struct file_dedupe_range {
 __u64 src_offset;
 __u64 src_length;
 __u16 dest_count;
 __u16 reserved1;
 __u32 reserved2;
 struct file_dedupe_range_info info[];
};
struct files_stat_struct {
 unsigned long nr_files;
 unsigned long nr_free_files;
 unsigned long max_files;
};
struct inodes_stat_t {
 long nr_inodes;
 long nr_unused;
 long dummy[5];
};
struct fsxattr {
 __u32 fsx_xflags;
 __u32 fsx_extsize;
 __u32 fsx_nextents;
 __u32 fsx_projid;
 __u32 fsx_cowextsize;
 unsigned char fsx_pad[8];
};
typedef int __kernel_rwf_t;
struct btrfs_ioctl_vol_args {
 __s64 fd;
 char name[4087 + 1];
};
struct btrfs_qgroup_limit {
 __u64 flags;
 __u64 max_rfer;
 __u64 max_excl;
 __u64 rsv_rfer;
 __u64 rsv_excl;
};
struct btrfs_qgroup_inherit {
 __u64 flags;
 __u64 num_qgroups;
 __u64 num_ref_copies;
 __u64 num_excl_copies;
 struct btrfs_qgroup_limit lim;
 __u64 qgroups[];
};
struct btrfs_ioctl_qgroup_limit_args {
 __u64 qgroupid;
 struct btrfs_qgroup_limit lim;
};
struct btrfs_ioctl_vol_args_v2 {
 __s64 fd;
 __u64 transid;
 __u64 flags;
 union {
  struct {
   __u64 size;
   struct btrfs_qgroup_inherit *qgroup_inherit;
  };
  __u64 unused[4];
 };
 union {
  char name[4039 + 1];
  __u64 devid;
  __u64 subvolid;
 };
};
struct btrfs_scrub_progress {
 __u64 data_extents_scrubbed;
 __u64 tree_extents_scrubbed;
 __u64 data_bytes_scrubbed;
 __u64 tree_bytes_scrubbed;
 __u64 read_errors;
 __u64 csum_errors;
 __u64 verify_errors;
 __u64 no_csum;
 __u64 csum_discards;
 __u64 super_errors;
 __u64 malloc_errors;
 __u64 uncorrectable_errors;
 __u64 corrected_errors;
 __u64 last_physical;
 __u64 unverified_errors;
};
struct btrfs_ioctl_scrub_args {
 __u64 devid;
 __u64 start;
 __u64 end;
 __u64 flags;
 struct btrfs_scrub_progress progress;
 __u64 unused[(1024-32-sizeof(struct btrfs_scrub_progress))/8];
};
struct btrfs_ioctl_dev_replace_start_params {
 __u64 srcdevid;
 __u64 cont_reading_from_srcdev_mode;
 __u8 srcdev_name[1024 + 1];
 __u8 tgtdev_name[1024 + 1];
};
struct btrfs_ioctl_dev_replace_status_params {
 __u64 replace_state;
 __u64 progress_1000;
 __u64 time_started;
 __u64 time_stopped;
 __u64 num_write_errors;
 __u64 num_uncorrectable_read_errors;
};
struct btrfs_ioctl_dev_replace_args {
 __u64 cmd;
 __u64 result;
 union {
  struct btrfs_ioctl_dev_replace_start_params start;
  struct btrfs_ioctl_dev_replace_status_params status;
 };
 __u64 spare[64];
};
struct btrfs_ioctl_dev_info_args {
 __u64 devid;
 __u8 uuid[16];
 __u64 bytes_used;
 __u64 total_bytes;
 __u64 unused[379];
 __u8 path[1024];
};
struct btrfs_ioctl_fs_info_args {
 __u64 max_id;
 __u64 num_devices;
 __u8 fsid[16];
 __u32 nodesize;
 __u32 sectorsize;
 __u32 clone_alignment;
 __u16 csum_type;
 __u16 csum_size;
 __u64 flags;
 __u64 generation;
 __u8 metadata_uuid[16];
 __u8 reserved[944];
};
struct btrfs_ioctl_feature_flags {
 __u64 compat_flags;
 __u64 compat_ro_flags;
 __u64 incompat_flags;
};
struct btrfs_balance_args {
 __u64 profiles;
 union {
  __u64 usage;
  struct {
   __u32 usage_min;
   __u32 usage_max;
  };
 };
 __u64 devid;
 __u64 pstart;
 __u64 pend;
 __u64 vstart;
 __u64 vend;
 __u64 target;
 __u64 flags;
 union {
  __u64 limit;
  struct {
   __u32 limit_min;
   __u32 limit_max;
  };
 };
 __u32 stripes_min;
 __u32 stripes_max;
 __u64 unused[6];
} __attribute__ ((__packed__));
struct btrfs_balance_progress {
 __u64 expected;
 __u64 considered;
 __u64 completed;
};
struct btrfs_ioctl_balance_args {
 __u64 flags;
 __u64 state;
 struct btrfs_balance_args data;
 struct btrfs_balance_args meta;
 struct btrfs_balance_args sys;
 struct btrfs_balance_progress stat;
 __u64 unused[72];
};
struct btrfs_ioctl_ino_lookup_args {
 __u64 treeid;
 __u64 objectid;
 char name[4080];
};
struct btrfs_ioctl_ino_lookup_user_args {
 __u64 dirid;
 __u64 treeid;
 char name[255 + 1];
 char path[(4080 - 255 - 1)];
};
struct btrfs_ioctl_search_key {
 __u64 tree_id;
 __u64 min_objectid;
 __u64 max_objectid;
 __u64 min_offset;
 __u64 max_offset;
 __u64 min_transid;
 __u64 max_transid;
 __u32 min_type;
 __u32 max_type;
 __u32 nr_items;
 __u32 unused;
 __u64 unused1;
 __u64 unused2;
 __u64 unused3;
 __u64 unused4;
};
struct btrfs_ioctl_search_header {
 __u64 transid;
 __u64 objectid;
 __u64 offset;
 __u32 type;
 __u32 len;
} __attribute__ ((__may_alias__));
struct btrfs_ioctl_search_args {
 struct btrfs_ioctl_search_key key;
 char buf[(4096 - sizeof(struct btrfs_ioctl_search_key))];
};
struct btrfs_ioctl_search_args_v2 {
 struct btrfs_ioctl_search_key key;
 __u64 buf_size;
 __u64 buf[];
};
struct btrfs_ioctl_clone_range_args {
 __s64 src_fd;
 __u64 src_offset, src_length;
 __u64 dest_offset;
};
struct btrfs_ioctl_defrag_range_args {
 __u64 start;
 __u64 len;
 __u64 flags;
 __u32 extent_thresh;
 __u32 compress_type;
 __u32 unused[4];
};
struct btrfs_ioctl_same_extent_info {
 __s64 fd;
 __u64 logical_offset;
 __u64 bytes_deduped;
 __s32 status;
 __u32 reserved;
};
struct btrfs_ioctl_same_args {
 __u64 logical_offset;
 __u64 length;
 __u16 dest_count;
 __u16 reserved1;
 __u32 reserved2;
 struct btrfs_ioctl_same_extent_info info[];
};
struct btrfs_ioctl_space_info {
 __u64 flags;
 __u64 total_bytes;
 __u64 used_bytes;
};
struct btrfs_ioctl_space_args {
 __u64 space_slots;
 __u64 total_spaces;
 struct btrfs_ioctl_space_info spaces[];
};
struct btrfs_data_container {
 __u32 bytes_left;
 __u32 bytes_missing;
 __u32 elem_cnt;
 __u32 elem_missed;
 __u64 val[];
};
struct btrfs_ioctl_ino_path_args {
 __u64 inum;
 __u64 size;
 __u64 reserved[4];
 __u64 fspath;
};
struct btrfs_ioctl_logical_ino_args {
 __u64 logical;
 __u64 size;
 __u64 reserved[3];
 __u64 flags;
 __u64 inodes;
};
enum btrfs_dev_stat_values {
 BTRFS_DEV_STAT_WRITE_ERRS,
 BTRFS_DEV_STAT_READ_ERRS,
 BTRFS_DEV_STAT_FLUSH_ERRS,
 BTRFS_DEV_STAT_CORRUPTION_ERRS,
 BTRFS_DEV_STAT_GENERATION_ERRS,
 BTRFS_DEV_STAT_VALUES_MAX
};
struct btrfs_ioctl_get_dev_stats {
 __u64 devid;
 __u64 nr_items;
 __u64 flags;
 __u64 values[BTRFS_DEV_STAT_VALUES_MAX];
 __u64 unused[128 - 2 - BTRFS_DEV_STAT_VALUES_MAX];
};
struct btrfs_ioctl_quota_ctl_args {
 __u64 cmd;
 __u64 status;
};
struct btrfs_ioctl_quota_rescan_args {
 __u64 flags;
 __u64 progress;
 __u64 reserved[6];
};
struct btrfs_ioctl_qgroup_assign_args {
 __u64 assign;
 __u64 src;
 __u64 dst;
};
struct btrfs_ioctl_qgroup_create_args {
 __u64 create;
 __u64 qgroupid;
};
struct btrfs_ioctl_timespec {
 __u64 sec;
 __u32 nsec;
};
struct btrfs_ioctl_received_subvol_args {
 char uuid[16];
 __u64 stransid;
 __u64 rtransid;
 struct btrfs_ioctl_timespec stime;
 struct btrfs_ioctl_timespec rtime;
 __u64 flags;
 __u64 reserved[16];
};
struct btrfs_ioctl_send_args {
 __s64 send_fd;
 __u64 clone_sources_count;
 __u64 *clone_sources;
 __u64 parent_root;
 __u64 flags;
 __u32 version;
 __u8 reserved[28];
};
struct btrfs_ioctl_get_subvol_info_args {
 __u64 treeid;
 char name[255 + 1];
 __u64 parent_id;
 __u64 dirid;
 __u64 generation;
 __u64 flags;
 __u8 uuid[16];
 __u8 parent_uuid[16];
 __u8 received_uuid[16];
 __u64 ctransid;
 __u64 otransid;
 __u64 stransid;
 __u64 rtransid;
 struct btrfs_ioctl_timespec ctime;
 struct btrfs_ioctl_timespec otime;
 struct btrfs_ioctl_timespec stime;
 struct btrfs_ioctl_timespec rtime;
 __u64 reserved[8];
};
struct btrfs_ioctl_get_subvol_rootref_args {
  __u64 min_treeid;
  struct {
   __u64 treeid;
   __u64 dirid;
  } rootref[255];
  __u8 num_items;
  __u8 align[7];
};
struct btrfs_ioctl_encoded_io_args {
 const struct iovec *iov;
 unsigned long iovcnt;
 __s64 offset;
 __u64 flags;
 __u64 len;
 __u64 unencoded_len;
 __u64 unencoded_offset;
 __u32 compression;
 __u32 encryption;
 __u8 reserved[64];
};
enum btrfs_err_code {
 BTRFS_ERROR_DEV_RAID1_MIN_NOT_MET = 1,
 BTRFS_ERROR_DEV_RAID10_MIN_NOT_MET,
 BTRFS_ERROR_DEV_RAID5_MIN_NOT_MET,
 BTRFS_ERROR_DEV_RAID6_MIN_NOT_MET,
 BTRFS_ERROR_DEV_TGT_REPLACE,
 BTRFS_ERROR_DEV_MISSING_NOT_FOUND,
 BTRFS_ERROR_DEV_ONLY_WRITABLE,
 BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS,
 BTRFS_ERROR_DEV_RAID1C3_MIN_NOT_MET,
 BTRFS_ERROR_DEV_RAID1C4_MIN_NOT_MET,
};
enum btrfs_csum_type {
 BTRFS_CSUM_TYPE_CRC32 = 0,
 BTRFS_CSUM_TYPE_XXHASH = 1,
 BTRFS_CSUM_TYPE_SHA256 = 2,
 BTRFS_CSUM_TYPE_BLAKE2 = 3,
};
static inline __u8 btrfs_dir_flags_to_ftype(__u8 flags)
{
 return flags & ~0x80;
}
struct btrfs_disk_key {
 __le64 objectid;
 __u8 type;
 __le64 offset;
} __attribute__ ((__packed__));
struct btrfs_key {
 __u64 objectid;
 __u8 type;
 __u64 offset;
} __attribute__ ((__packed__));
struct btrfs_header {
 __u8 csum[32];
 __u8 fsid[16];
 __le64 bytenr;
 __le64 flags;
 __u8 chunk_tree_uuid[16];
 __le64 generation;
 __le64 owner;
 __le32 nritems;
 __u8 level;
} __attribute__ ((__packed__));
struct btrfs_root_backup {
 __le64 tree_root;
 __le64 tree_root_gen;
 __le64 chunk_root;
 __le64 chunk_root_gen;
 __le64 extent_root;
 __le64 extent_root_gen;
 __le64 fs_root;
 __le64 fs_root_gen;
 __le64 dev_root;
 __le64 dev_root_gen;
 __le64 csum_root;
 __le64 csum_root_gen;
 __le64 total_bytes;
 __le64 bytes_used;
 __le64 num_devices;
 __le64 unused_64[4];
 __u8 tree_root_level;
 __u8 chunk_root_level;
 __u8 extent_root_level;
 __u8 fs_root_level;
 __u8 dev_root_level;
 __u8 csum_root_level;
 __u8 unused_8[10];
} __attribute__ ((__packed__));
struct btrfs_item {
 struct btrfs_disk_key key;
 __le32 offset;
 __le32 size;
} __attribute__ ((__packed__));
struct btrfs_leaf {
 struct btrfs_header header;
 struct btrfs_item items[];
} __attribute__ ((__packed__));
struct btrfs_key_ptr {
 struct btrfs_disk_key key;
 __le64 blockptr;
 __le64 generation;
} __attribute__ ((__packed__));
struct btrfs_node {
 struct btrfs_header header;
 struct btrfs_key_ptr ptrs[];
} __attribute__ ((__packed__));
struct btrfs_dev_item {
 __le64 devid;
 __le64 total_bytes;
 __le64 bytes_used;
 __le32 io_align;
 __le32 io_width;
 __le32 sector_size;
 __le64 type;
 __le64 generation;
 __le64 start_offset;
 __le32 dev_group;
 __u8 seek_speed;
 __u8 bandwidth;
 __u8 uuid[16];
 __u8 fsid[16];
} __attribute__ ((__packed__));
struct btrfs_stripe {
 __le64 devid;
 __le64 offset;
 __u8 dev_uuid[16];
} __attribute__ ((__packed__));
struct btrfs_chunk {
 __le64 length;
 __le64 owner;
 __le64 stripe_len;
 __le64 type;
 __le32 io_align;
 __le32 io_width;
 __le32 sector_size;
 __le16 num_stripes;
 __le16 sub_stripes;
 struct btrfs_stripe stripe;
} __attribute__ ((__packed__));
struct btrfs_super_block {
 __u8 csum[32];
 __u8 fsid[16];
 __le64 bytenr;
 __le64 flags;
 __le64 magic;
 __le64 generation;
 __le64 root;
 __le64 chunk_root;
 __le64 log_root;
 __le64 __unused_log_root_transid;
 __le64 total_bytes;
 __le64 bytes_used;
 __le64 root_dir_objectid;
 __le64 num_devices;
 __le32 sectorsize;
 __le32 nodesize;
 __le32 __unused_leafsize;
 __le32 stripesize;
 __le32 sys_chunk_array_size;
 __le64 chunk_root_generation;
 __le64 compat_flags;
 __le64 compat_ro_flags;
 __le64 incompat_flags;
 __le16 csum_type;
 __u8 root_level;
 __u8 chunk_root_level;
 __u8 log_root_level;
 struct btrfs_dev_item dev_item;
 char label[256];
 __le64 cache_generation;
 __le64 uuid_tree_generation;
 __u8 metadata_uuid[16];
 __u64 nr_global_roots;
 __le64 reserved[27];
 __u8 sys_chunk_array[2048];
 struct btrfs_root_backup super_roots[4];
 __u8 padding[565];
} __attribute__ ((__packed__));
struct btrfs_free_space_entry {
 __le64 offset;
 __le64 bytes;
 __u8 type;
} __attribute__ ((__packed__));
struct btrfs_free_space_header {
 struct btrfs_disk_key location;
 __le64 generation;
 __le64 num_entries;
 __le64 num_bitmaps;
} __attribute__ ((__packed__));
struct btrfs_extent_item {
 __le64 refs;
 __le64 generation;
 __le64 flags;
} __attribute__ ((__packed__));
struct btrfs_extent_item_v0 {
 __le32 refs;
} __attribute__ ((__packed__));
struct btrfs_tree_block_info {
 struct btrfs_disk_key key;
 __u8 level;
} __attribute__ ((__packed__));
struct btrfs_extent_data_ref {
 __le64 root;
 __le64 objectid;
 __le64 offset;
 __le32 count;
} __attribute__ ((__packed__));
struct btrfs_shared_data_ref {
 __le32 count;
} __attribute__ ((__packed__));
struct btrfs_extent_inline_ref {
 __u8 type;
 __le64 offset;
} __attribute__ ((__packed__));
struct btrfs_dev_extent {
 __le64 chunk_tree;
 __le64 chunk_objectid;
 __le64 chunk_offset;
 __le64 length;
 __u8 chunk_tree_uuid[16];
} __attribute__ ((__packed__));
struct btrfs_inode_ref {
 __le64 index;
 __le16 name_len;
} __attribute__ ((__packed__));
struct btrfs_inode_extref {
 __le64 parent_objectid;
 __le64 index;
 __le16 name_len;
 __u8 name[];
} __attribute__ ((__packed__));
struct btrfs_timespec {
 __le64 sec;
 __le32 nsec;
} __attribute__ ((__packed__));
struct btrfs_inode_item {
 __le64 generation;
 __le64 transid;
 __le64 size;
 __le64 nbytes;
 __le64 block_group;
 __le32 nlink;
 __le32 uid;
 __le32 gid;
 __le32 mode;
 __le64 rdev;
 __le64 flags;
 __le64 sequence;
 __le64 reserved[4];
 struct btrfs_timespec atime;
 struct btrfs_timespec ctime;
 struct btrfs_timespec mtime;
 struct btrfs_timespec otime;
} __attribute__ ((__packed__));
struct btrfs_dir_log_item {
 __le64 end;
} __attribute__ ((__packed__));
struct btrfs_dir_item {
 struct btrfs_disk_key location;
 __le64 transid;
 __le16 data_len;
 __le16 name_len;
 __u8 type;
} __attribute__ ((__packed__));
struct btrfs_root_item {
 struct btrfs_inode_item inode;
 __le64 generation;
 __le64 root_dirid;
 __le64 bytenr;
 __le64 byte_limit;
 __le64 bytes_used;
 __le64 last_snapshot;
 __le64 flags;
 __le32 refs;
 struct btrfs_disk_key drop_progress;
 __u8 drop_level;
 __u8 level;
 __le64 generation_v2;
 __u8 uuid[16];
 __u8 parent_uuid[16];
 __u8 received_uuid[16];
 __le64 ctransid;
 __le64 otransid;
 __le64 stransid;
 __le64 rtransid;
 struct btrfs_timespec ctime;
 struct btrfs_timespec otime;
 struct btrfs_timespec stime;
 struct btrfs_timespec rtime;
 __le64 reserved[8];
} __attribute__ ((__packed__));
static __inline__ __u32 btrfs_legacy_root_item_size(void)
{
 return __builtin_offsetof (struct btrfs_root_item, generation_v2);
}
struct btrfs_root_ref {
 __le64 dirid;
 __le64 sequence;
 __le16 name_len;
} __attribute__ ((__packed__));
struct btrfs_disk_balance_args {
 __le64 profiles;
 union {
  __le64 usage;
  struct {
   __le32 usage_min;
   __le32 usage_max;
  };
 };
 __le64 devid;
 __le64 pstart;
 __le64 pend;
 __le64 vstart;
 __le64 vend;
 __le64 target;
 __le64 flags;
 union {
  __le64 limit;
  struct {
   __le32 limit_min;
   __le32 limit_max;
  };
 };
 __le32 stripes_min;
 __le32 stripes_max;
 __le64 unused[6];
} __attribute__ ((__packed__));
struct btrfs_balance_item {
 __le64 flags;
 struct btrfs_disk_balance_args data;
 struct btrfs_disk_balance_args meta;
 struct btrfs_disk_balance_args sys;
 __le64 unused[4];
} __attribute__ ((__packed__));
enum {
 BTRFS_FILE_EXTENT_INLINE = 0,
 BTRFS_FILE_EXTENT_REG = 1,
 BTRFS_FILE_EXTENT_PREALLOC = 2,
 BTRFS_NR_FILE_EXTENT_TYPES = 3,
};
struct btrfs_file_extent_item {
 __le64 generation;
 __le64 ram_bytes;
 __u8 compression;
 __u8 encryption;
 __le16 other_encoding;
 __u8 type;
 __le64 disk_bytenr;
 __le64 disk_num_bytes;
 __le64 offset;
 __le64 num_bytes;
} __attribute__ ((__packed__));
struct btrfs_csum_item {
 __u8 csum;
} __attribute__ ((__packed__));
struct btrfs_dev_stats_item {
 __le64 values[BTRFS_DEV_STAT_VALUES_MAX];
} __attribute__ ((__packed__));
struct btrfs_dev_replace_item {
 __le64 src_devid;
 __le64 cursor_left;
 __le64 cursor_right;
 __le64 cont_reading_from_srcdev_mode;
 __le64 replace_state;
 __le64 time_started;
 __le64 time_stopped;
 __le64 num_write_errors;
 __le64 num_uncorrectable_read_errors;
} __attribute__ ((__packed__));
static __inline__ __u64 chunk_to_extended(__u64 flags)
{
 if ((flags & ((1ULL << 3) | (1ULL << 4) | (1ULL << 9) | (1ULL << 10) | (1ULL << 7) | (1ULL << 8) | (1ULL << 5) | (1ULL << 6))) == 0)
  flags |= (1ULL << 48);
 return flags;
}
static __inline__ __u64 extended_to_chunk(__u64 flags)
{
 return flags & ~(1ULL << 48);
}
struct btrfs_block_group_item {
 __le64 used;
 __le64 chunk_objectid;
 __le64 flags;
} __attribute__ ((__packed__));
struct btrfs_free_space_info {
 __le32 extent_count;
 __le32 flags;
} __attribute__ ((__packed__));
static __inline__ __u16 btrfs_qgroup_level(__u64 qgroupid)
{
 return (__u16)(qgroupid >> 48);
}
struct btrfs_qgroup_status_item {
 __le64 version;
 __le64 generation;
 __le64 flags;
 __le64 rescan;
} __attribute__ ((__packed__));
struct btrfs_qgroup_info_item {
 __le64 generation;
 __le64 rfer;
 __le64 rfer_cmpr;
 __le64 excl;
 __le64 excl_cmpr;
} __attribute__ ((__packed__));
struct btrfs_qgroup_limit_item {
 __le64 flags;
 __le64 max_rfer;
 __le64 max_excl;
 __le64 rsv_rfer;
 __le64 rsv_excl;
} __attribute__ ((__packed__));
struct btrfs_verity_descriptor_item {
 __le64 size;
 __le64 reserved[2];
 __u8 encryption;
} __attribute__ ((__packed__));
typedef struct btrfs_ioctl_dev_replace_args
 struct_btrfs_ioctl_dev_replace_args;
typedef struct btrfs_ioctl_send_args
 struct_btrfs_ioctl_send_args;
typedef struct btrfs_ioctl_received_subvol_args
 struct_btrfs_ioctl_received_subvol_args;
typedef struct btrfs_ioctl_timespec
 struct_btrfs_ioctl_timespec;
typedef struct btrfs_ioctl_vol_args_v2
 struct_btrfs_ioctl_vol_args_v2;

static const struct xlat_data btrfs_balance_args_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_BALANCE_ARGS_PROFILES" },
 { (uint64_t)((1ULL << 1)), "BTRFS_BALANCE_ARGS_USAGE" },
 { (uint64_t)((1ULL << 2)), "BTRFS_BALANCE_ARGS_DEVID" },
 { (uint64_t)((1ULL << 3)), "BTRFS_BALANCE_ARGS_DRANGE" },
 { (uint64_t)((1ULL << 4)), "BTRFS_BALANCE_ARGS_VRANGE" },
 { (uint64_t)((1ULL << 5)), "BTRFS_BALANCE_ARGS_LIMIT" },
 { (uint64_t)((1ULL << 6)), "BTRFS_BALANCE_ARGS_LIMIT_RANGE" },
 { (uint64_t)((1ULL << 7)), "BTRFS_BALANCE_ARGS_STRIPES_RANGE" },
 { (uint64_t)((1ULL << 8)), "BTRFS_BALANCE_ARGS_CONVERT" },
 { (uint64_t)((1ULL << 9)), "BTRFS_BALANCE_ARGS_SOFT" },
 { (uint64_t)((1ULL << 10)), "BTRFS_BALANCE_ARGS_USAGE_RANGE" },
};
const struct xlat btrfs_balance_args[1] = { {
 .data = btrfs_balance_args_xdata,
 .size = (sizeof(btrfs_balance_args_xdata) / sizeof((btrfs_balance_args_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_balance_args_xdata)), __typeof__(&(btrfs_balance_args_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  | ((uint64_t) ((1ULL << 4)))
  | ((uint64_t) ((1ULL << 5)))
  | ((uint64_t) ((1ULL << 6)))
  | ((uint64_t) ((1ULL << 7)))
  | ((uint64_t) ((1ULL << 8)))
  | ((uint64_t) ((1ULL << 9)))
  | ((uint64_t) ((1ULL << 10)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_BALANCE_ARGS_PROFILES")
  + sizeof("BTRFS_BALANCE_ARGS_USAGE")
  + sizeof("BTRFS_BALANCE_ARGS_DEVID")
  + sizeof("BTRFS_BALANCE_ARGS_DRANGE")
  + sizeof("BTRFS_BALANCE_ARGS_VRANGE")
  + sizeof("BTRFS_BALANCE_ARGS_LIMIT")
  + sizeof("BTRFS_BALANCE_ARGS_LIMIT_RANGE")
  + sizeof("BTRFS_BALANCE_ARGS_STRIPES_RANGE")
  + sizeof("BTRFS_BALANCE_ARGS_CONVERT")
  + sizeof("BTRFS_BALANCE_ARGS_SOFT")
  + sizeof("BTRFS_BALANCE_ARGS_USAGE_RANGE")
  ,
} };


static const struct xlat_data btrfs_balance_ctl_cmds_xdata[] = {
 [1] = { (unsigned)(1), "BTRFS_BALANCE_CTL_PAUSE" },
 [2] = { (unsigned)(2), "BTRFS_BALANCE_CTL_CANCEL" },
};
const struct xlat btrfs_balance_ctl_cmds[1] = { {
 .data = btrfs_balance_ctl_cmds_xdata,
 .size = (sizeof(btrfs_balance_ctl_cmds_xdata) / sizeof((btrfs_balance_ctl_cmds_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_balance_ctl_cmds_xdata)), __typeof__(&(btrfs_balance_ctl_cmds_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (1))
  | ((unsigned) (2))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_BALANCE_CTL_PAUSE")
  + sizeof("BTRFS_BALANCE_CTL_CANCEL")
  ,
} };


static const struct xlat_data btrfs_balance_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_BALANCE_DATA" },
 { (uint64_t)((1ULL << 1)), "BTRFS_BALANCE_SYSTEM" },
 { (uint64_t)((1ULL << 2)), "BTRFS_BALANCE_METADATA" },
 { (uint64_t)((1ULL << 3)), "BTRFS_BALANCE_FORCE" },
 { (uint64_t)((1ULL << 4)), "BTRFS_BALANCE_RESUME" },
};
const struct xlat btrfs_balance_flags[1] = { {
 .data = btrfs_balance_flags_xdata,
 .size = (sizeof(btrfs_balance_flags_xdata) / sizeof((btrfs_balance_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_balance_flags_xdata)), __typeof__(&(btrfs_balance_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  | ((uint64_t) ((1ULL << 4)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_BALANCE_DATA")
  + sizeof("BTRFS_BALANCE_SYSTEM")
  + sizeof("BTRFS_BALANCE_METADATA")
  + sizeof("BTRFS_BALANCE_FORCE")
  + sizeof("BTRFS_BALANCE_RESUME")
  ,
} };


static const struct xlat_data btrfs_balance_state_xdata[] = {
 { (unsigned)((1ULL << 0)), "BTRFS_BALANCE_STATE_RUNNING" },
 { (unsigned)((1ULL << 1)), "BTRFS_BALANCE_STATE_PAUSE_REQ" },
 { (unsigned)((1ULL << 2)), "BTRFS_BALANCE_STATE_CANCEL_REQ" },
};
const struct xlat btrfs_balance_state[1] = { {
 .data = btrfs_balance_state_xdata,
 .size = (sizeof(btrfs_balance_state_xdata) / sizeof((btrfs_balance_state_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_balance_state_xdata)), __typeof__(&(btrfs_balance_state_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((1ULL << 0)))
  | ((unsigned) ((1ULL << 1)))
  | ((unsigned) ((1ULL << 2)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_BALANCE_STATE_RUNNING")
  + sizeof("BTRFS_BALANCE_STATE_PAUSE_REQ")
  + sizeof("BTRFS_BALANCE_STATE_CANCEL_REQ")
  ,
} };


static const struct xlat_data btrfs_compress_types_xdata[] = {
 [0] = { (unsigned)(0), "BTRFS_COMPRESS_NONE" },
 [1] = { (unsigned)(1), "BTRFS_COMPRESS_ZLIB" },
 [2] = { (unsigned)(2), "BTRFS_COMPRESS_LZO" },
 [3] = { (unsigned)(3), "BTRFS_COMPRESS_ZSTD" },
};
const struct xlat btrfs_compress_types[1] = { {
 .data = btrfs_compress_types_xdata,
 .size = (sizeof(btrfs_compress_types_xdata) / sizeof((btrfs_compress_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_compress_types_xdata)), __typeof__(&(btrfs_compress_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (0))
  | ((unsigned) (1))
  | ((unsigned) (2))
  | ((unsigned) (3))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_COMPRESS_NONE")
  + sizeof("BTRFS_COMPRESS_ZLIB")
  + sizeof("BTRFS_COMPRESS_LZO")
  + sizeof("BTRFS_COMPRESS_ZSTD")
  ,
} };


static const struct xlat_data btrfs_cont_reading_from_srcdev_mode_xdata[] = {
 [0] = { (unsigned)(0), "BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_ALWAYS" },
 [1] = { (unsigned)(1), "BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_AVOID" },
};
const struct xlat btrfs_cont_reading_from_srcdev_mode[1] = { {
 .data = btrfs_cont_reading_from_srcdev_mode_xdata,
 .size = (sizeof(btrfs_cont_reading_from_srcdev_mode_xdata) / sizeof((btrfs_cont_reading_from_srcdev_mode_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_cont_reading_from_srcdev_mode_xdata)), __typeof__(&(btrfs_cont_reading_from_srcdev_mode_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (0))
  | ((unsigned) (1))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_ALWAYS")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_AVOID")
  ,
} };


static const struct xlat_data btrfs_csum_types_xdata[] = {
 [BTRFS_CSUM_TYPE_CRC32] = { (unsigned)(BTRFS_CSUM_TYPE_CRC32), "BTRFS_CSUM_TYPE_CRC32" },
 [BTRFS_CSUM_TYPE_XXHASH] = { (unsigned)(BTRFS_CSUM_TYPE_XXHASH), "BTRFS_CSUM_TYPE_XXHASH" },
 [BTRFS_CSUM_TYPE_SHA256] = { (unsigned)(BTRFS_CSUM_TYPE_SHA256), "BTRFS_CSUM_TYPE_SHA256" },
 [BTRFS_CSUM_TYPE_BLAKE2] = { (unsigned)(BTRFS_CSUM_TYPE_BLAKE2), "BTRFS_CSUM_TYPE_BLAKE2" },
};
const struct xlat btrfs_csum_types[1] = { {
 .data = btrfs_csum_types_xdata,
 .size = (sizeof(btrfs_csum_types_xdata) / sizeof((btrfs_csum_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_csum_types_xdata)), __typeof__(&(btrfs_csum_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (BTRFS_CSUM_TYPE_CRC32))
  | ((unsigned) (BTRFS_CSUM_TYPE_XXHASH))
  | ((unsigned) (BTRFS_CSUM_TYPE_SHA256))
  | ((unsigned) (BTRFS_CSUM_TYPE_BLAKE2))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_CSUM_TYPE_CRC32")
  + sizeof("BTRFS_CSUM_TYPE_XXHASH")
  + sizeof("BTRFS_CSUM_TYPE_SHA256")
  + sizeof("BTRFS_CSUM_TYPE_BLAKE2")
  ,
} };


static const struct xlat_data btrfs_defrag_flags_xdata[] = {
 { (uint64_t)(1), "BTRFS_DEFRAG_RANGE_COMPRESS" },
 { (uint64_t)(2), "BTRFS_DEFRAG_RANGE_START_IO" },
};
const struct xlat btrfs_defrag_flags[1] = { {
 .data = btrfs_defrag_flags_xdata,
 .size = (sizeof(btrfs_defrag_flags_xdata) / sizeof((btrfs_defrag_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_defrag_flags_xdata)), __typeof__(&(btrfs_defrag_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (1))
  | ((uint64_t) (2))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_DEFRAG_RANGE_COMPRESS")
  + sizeof("BTRFS_DEFRAG_RANGE_START_IO")
  ,
} };


static const struct xlat_data btrfs_dev_replace_cmds_xdata[] = {
 { (uint64_t)(0), "BTRFS_IOCTL_DEV_REPLACE_CMD_START" },
 { (uint64_t)(1), "BTRFS_IOCTL_DEV_REPLACE_CMD_STATUS" },
 { (uint64_t)(2), "BTRFS_IOCTL_DEV_REPLACE_CMD_CANCEL" },
};
const struct xlat btrfs_dev_replace_cmds[1] = { {
 .data = btrfs_dev_replace_cmds_xdata,
 .size = (sizeof(btrfs_dev_replace_cmds_xdata) / sizeof((btrfs_dev_replace_cmds_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_dev_replace_cmds_xdata)), __typeof__(&(btrfs_dev_replace_cmds_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (0))
  | ((uint64_t) (1))
  | ((uint64_t) (2))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_CMD_START")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_CMD_STATUS")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_CMD_CANCEL")
  ,
} };


static const struct xlat_data btrfs_dev_replace_results_xdata[] = {
 { (uint64_t)(0), "BTRFS_IOCTL_DEV_REPLACE_RESULT_NO_ERROR" },
 { (uint64_t)(1), "BTRFS_IOCTL_DEV_REPLACE_RESULT_NOT_STARTED" },
 { (uint64_t)(2), "BTRFS_IOCTL_DEV_REPLACE_RESULT_ALREADY_STARTED" },
 { (uint64_t)(3), "BTRFS_IOCTL_DEV_REPLACE_RESULT_SCRUB_INPROGRESS" },
};
const struct xlat btrfs_dev_replace_results[1] = { {
 .data = btrfs_dev_replace_results_xdata,
 .size = (sizeof(btrfs_dev_replace_results_xdata) / sizeof((btrfs_dev_replace_results_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_dev_replace_results_xdata)), __typeof__(&(btrfs_dev_replace_results_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (0))
  | ((uint64_t) (1))
  | ((uint64_t) (2))
  | ((uint64_t) (3))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_RESULT_NO_ERROR")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_RESULT_NOT_STARTED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_RESULT_ALREADY_STARTED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_RESULT_SCRUB_INPROGRESS")
  ,
} };


static const struct xlat_data btrfs_dev_replace_state_xdata[] = {
 { (uint64_t)(0), "BTRFS_IOCTL_DEV_REPLACE_STATE_NEVER_STARTED" },
 { (uint64_t)(1), "BTRFS_IOCTL_DEV_REPLACE_STATE_STARTED" },
 { (uint64_t)(2), "BTRFS_IOCTL_DEV_REPLACE_STATE_FINISHED" },
 { (uint64_t)(3), "BTRFS_IOCTL_DEV_REPLACE_STATE_CANCELED" },
 { (uint64_t)(4), "BTRFS_IOCTL_DEV_REPLACE_STATE_SUSPENDED" },
};
const struct xlat btrfs_dev_replace_state[1] = { {
 .data = btrfs_dev_replace_state_xdata,
 .size = (sizeof(btrfs_dev_replace_state_xdata) / sizeof((btrfs_dev_replace_state_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_dev_replace_state_xdata)), __typeof__(&(btrfs_dev_replace_state_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (0))
  | ((uint64_t) (1))
  | ((uint64_t) (2))
  | ((uint64_t) (3))
  | ((uint64_t) (4))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_STATE_NEVER_STARTED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_STATE_STARTED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_STATE_FINISHED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_STATE_CANCELED")
  + sizeof("BTRFS_IOCTL_DEV_REPLACE_STATE_SUSPENDED")
  ,
} };


static const struct xlat_data btrfs_dev_stats_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_DEV_STATS_RESET" },
};
const struct xlat btrfs_dev_stats_flags[1] = { {
 .data = btrfs_dev_stats_flags_xdata,
 .size = (sizeof(btrfs_dev_stats_flags_xdata) / sizeof((btrfs_dev_stats_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_dev_stats_flags_xdata)), __typeof__(&(btrfs_dev_stats_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_DEV_STATS_RESET")
  ,
} };


static const struct xlat_data btrfs_dev_stats_values_xdata[] = {
 [BTRFS_DEV_STAT_WRITE_ERRS] = { (uint64_t)(BTRFS_DEV_STAT_WRITE_ERRS), "BTRFS_DEV_STAT_WRITE_ERRS" },
 [BTRFS_DEV_STAT_READ_ERRS] = { (uint64_t)(BTRFS_DEV_STAT_READ_ERRS), "BTRFS_DEV_STAT_READ_ERRS" },
 [BTRFS_DEV_STAT_FLUSH_ERRS] = { (uint64_t)(BTRFS_DEV_STAT_FLUSH_ERRS), "BTRFS_DEV_STAT_FLUSH_ERRS" },
 [BTRFS_DEV_STAT_CORRUPTION_ERRS] = { (uint64_t)(BTRFS_DEV_STAT_CORRUPTION_ERRS), "BTRFS_DEV_STAT_CORRUPTION_ERRS" },
 [BTRFS_DEV_STAT_GENERATION_ERRS] = { (uint64_t)(BTRFS_DEV_STAT_GENERATION_ERRS), "BTRFS_DEV_STAT_GENERATION_ERRS" },
};
const struct xlat btrfs_dev_stats_values[1] = { {
 .data = btrfs_dev_stats_values_xdata,
 .size = (sizeof(btrfs_dev_stats_values_xdata) / sizeof((btrfs_dev_stats_values_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_dev_stats_values_xdata)), __typeof__(&(btrfs_dev_stats_values_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((uint64_t) (BTRFS_DEV_STAT_WRITE_ERRS))
  | ((uint64_t) (BTRFS_DEV_STAT_READ_ERRS))
  | ((uint64_t) (BTRFS_DEV_STAT_FLUSH_ERRS))
  | ((uint64_t) (BTRFS_DEV_STAT_CORRUPTION_ERRS))
  | ((uint64_t) (BTRFS_DEV_STAT_GENERATION_ERRS))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_DEV_STAT_WRITE_ERRS")
  + sizeof("BTRFS_DEV_STAT_READ_ERRS")
  + sizeof("BTRFS_DEV_STAT_FLUSH_ERRS")
  + sizeof("BTRFS_DEV_STAT_CORRUPTION_ERRS")
  + sizeof("BTRFS_DEV_STAT_GENERATION_ERRS")
  ,
} };


static const struct xlat_data btrfs_features_compat_xdata[] = {
};
const struct xlat btrfs_features_compat[1] = { {
 .data = btrfs_features_compat_xdata,
 .size = (sizeof(btrfs_features_compat_xdata) / sizeof((btrfs_features_compat_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_features_compat_xdata)), __typeof__(&(btrfs_features_compat_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  ,
 .flags_strsz = 0
  ,
} };


static const struct xlat_data btrfs_features_compat_ro_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE" },
 { (uint64_t)((1ULL << 1)), "BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID" },
 { (uint64_t)((1ULL << 2)), "BTRFS_FEATURE_COMPAT_RO_VERITY" },
 { (uint64_t)((1ULL << 3)), "BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE" },
};
const struct xlat btrfs_features_compat_ro[1] = { {
 .data = btrfs_features_compat_ro_xdata,
 .size = (sizeof(btrfs_features_compat_ro_xdata) / sizeof((btrfs_features_compat_ro_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_features_compat_ro_xdata)), __typeof__(&(btrfs_features_compat_ro_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE")
  + sizeof("BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID")
  + sizeof("BTRFS_FEATURE_COMPAT_RO_VERITY")
  + sizeof("BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE")
  ,
} };


static const struct xlat_data btrfs_features_incompat_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF" },
 { (uint64_t)((1ULL << 1)), "BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL" },
 { (uint64_t)((1ULL << 2)), "BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS" },
 { (uint64_t)((1ULL << 3)), "BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO" },
 { (uint64_t)((1ULL << 4)), "BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD" },
 { (uint64_t)((1ULL << 5)), "BTRFS_FEATURE_INCOMPAT_BIG_METADATA" },
 { (uint64_t)((1ULL << 6)), "BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF" },
 { (uint64_t)((1ULL << 7)), "BTRFS_FEATURE_INCOMPAT_RAID56" },
 { (uint64_t)((1ULL << 8)), "BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA" },
 { (uint64_t)((1ULL << 9)), "BTRFS_FEATURE_INCOMPAT_NO_HOLES" },
 { (uint64_t)((1ULL << 10)), "BTRFS_FEATURE_INCOMPAT_METADATA_UUID" },
 { (uint64_t)((1ULL << 11)), "BTRFS_FEATURE_INCOMPAT_RAID1C34" },
 { (uint64_t)((1ULL << 12)), "BTRFS_FEATURE_INCOMPAT_ZONED" },
 { (uint64_t)((1ULL << 13)), "BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2" },
};
const struct xlat btrfs_features_incompat[1] = { {
 .data = btrfs_features_incompat_xdata,
 .size = (sizeof(btrfs_features_incompat_xdata) / sizeof((btrfs_features_incompat_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_features_incompat_xdata)), __typeof__(&(btrfs_features_incompat_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  | ((uint64_t) ((1ULL << 4)))
  | ((uint64_t) ((1ULL << 5)))
  | ((uint64_t) ((1ULL << 6)))
  | ((uint64_t) ((1ULL << 7)))
  | ((uint64_t) ((1ULL << 8)))
  | ((uint64_t) ((1ULL << 9)))
  | ((uint64_t) ((1ULL << 10)))
  | ((uint64_t) ((1ULL << 11)))
  | ((uint64_t) ((1ULL << 12)))
  | ((uint64_t) ((1ULL << 13)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF")
  + sizeof("BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL")
  + sizeof("BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS")
  + sizeof("BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO")
  + sizeof("BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD")
  + sizeof("BTRFS_FEATURE_INCOMPAT_BIG_METADATA")
  + sizeof("BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF")
  + sizeof("BTRFS_FEATURE_INCOMPAT_RAID56")
  + sizeof("BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA")
  + sizeof("BTRFS_FEATURE_INCOMPAT_NO_HOLES")
  + sizeof("BTRFS_FEATURE_INCOMPAT_METADATA_UUID")
  + sizeof("BTRFS_FEATURE_INCOMPAT_RAID1C34")
  + sizeof("BTRFS_FEATURE_INCOMPAT_ZONED")
  + sizeof("BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2")
  ,
} };


static const struct xlat_data btrfs_fs_info_flags_xdata[] = {
 { (unsigned)((1 << 0)), "BTRFS_FS_INFO_FLAG_CSUM_INFO" },
 { (unsigned)((1 << 1)), "BTRFS_FS_INFO_FLAG_GENERATION" },
 { (unsigned)((1 << 2)), "BTRFS_FS_INFO_FLAG_METADATA_UUID" },
};
const struct xlat btrfs_fs_info_flags[1] = { {
 .data = btrfs_fs_info_flags_xdata,
 .size = (sizeof(btrfs_fs_info_flags_xdata) / sizeof((btrfs_fs_info_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_fs_info_flags_xdata)), __typeof__(&(btrfs_fs_info_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((1 << 0)))
  | ((unsigned) ((1 << 1)))
  | ((unsigned) ((1 << 2)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_FS_INFO_FLAG_CSUM_INFO")
  + sizeof("BTRFS_FS_INFO_FLAG_GENERATION")
  + sizeof("BTRFS_FS_INFO_FLAG_METADATA_UUID")
  ,
} };

_Static_assert((unsigned long long) (12)
      > (unsigned long long) ((1)),
      "Incorrect order in #sorted xlat: BTRFS_INODE_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (13)
      > (unsigned long long) ((12)),
      "Incorrect order in #sorted xlat: BTRFS_INODE_EXTREF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (24)
      > (unsigned long long) ((13)),
      "Incorrect order in #sorted xlat: BTRFS_XATTR_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (36)
      > (unsigned long long) ((24)),
      "Incorrect order in #sorted xlat: BTRFS_VERITY_DESC_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (37)
      > (unsigned long long) ((36)),
      "Incorrect order in #sorted xlat: BTRFS_VERITY_MERKLE_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (48)
      > (unsigned long long) ((37)),
      "Incorrect order in #sorted xlat: BTRFS_ORPHAN_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (60)
      > (unsigned long long) ((48)),
      "Incorrect order in #sorted xlat: BTRFS_DIR_LOG_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (72)
      > (unsigned long long) ((60)),
      "Incorrect order in #sorted xlat: BTRFS_DIR_LOG_INDEX_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (84)
      > (unsigned long long) ((72)),
      "Incorrect order in #sorted xlat: BTRFS_DIR_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (96)
      > (unsigned long long) ((84)),
      "Incorrect order in #sorted xlat: BTRFS_DIR_INDEX_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (108)
      > (unsigned long long) ((96)),
      "Incorrect order in #sorted xlat: BTRFS_EXTENT_DATA_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (128)
      > (unsigned long long) ((108)),
      "Incorrect order in #sorted xlat: BTRFS_EXTENT_CSUM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (132)
      > (unsigned long long) ((128)),
      "Incorrect order in #sorted xlat: BTRFS_ROOT_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (144)
      > (unsigned long long) ((132)),
      "Incorrect order in #sorted xlat: BTRFS_ROOT_BACKREF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (156)
      > (unsigned long long) ((144)),
      "Incorrect order in #sorted xlat: BTRFS_ROOT_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (168)
      > (unsigned long long) ((156)),
      "Incorrect order in #sorted xlat: BTRFS_EXTENT_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (169)
      > (unsigned long long) ((168)),
      "Incorrect order in #sorted xlat: BTRFS_METADATA_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (176)
      > (unsigned long long) ((169)),
      "Incorrect order in #sorted xlat: BTRFS_TREE_BLOCK_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (178)
      > (unsigned long long) ((176)),
      "Incorrect order in #sorted xlat: BTRFS_EXTENT_DATA_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (180)
      > (unsigned long long) ((178)),
      "Incorrect order in #sorted xlat: BTRFS_EXTENT_REF_V0_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (182)
      > (unsigned long long) ((180)),
      "Incorrect order in #sorted xlat: BTRFS_SHARED_BLOCK_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (184)
      > (unsigned long long) ((182)),
      "Incorrect order in #sorted xlat: BTRFS_SHARED_DATA_REF_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (192)
      > (unsigned long long) ((184)),
      "Incorrect order in #sorted xlat: BTRFS_BLOCK_GROUP_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (198)
      > (unsigned long long) ((192)),
      "Incorrect order in #sorted xlat: BTRFS_FREE_SPACE_INFO_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (199)
      > (unsigned long long) ((198)),
      "Incorrect order in #sorted xlat: BTRFS_FREE_SPACE_EXTENT_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (200)
      > (unsigned long long) ((199)),
      "Incorrect order in #sorted xlat: BTRFS_FREE_SPACE_BITMAP_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (204)
      > (unsigned long long) ((200)),
      "Incorrect order in #sorted xlat: BTRFS_DEV_EXTENT_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (216)
      > (unsigned long long) ((204)),
      "Incorrect order in #sorted xlat: BTRFS_DEV_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (228)
      > (unsigned long long) ((216)),
      "Incorrect order in #sorted xlat: BTRFS_CHUNK_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (240)
      > (unsigned long long) ((228)),
      "Incorrect order in #sorted xlat: BTRFS_QGROUP_STATUS_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (242)
      > (unsigned long long) ((240)),
      "Incorrect order in #sorted xlat: BTRFS_QGROUP_INFO_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (244)
      > (unsigned long long) ((242)),
      "Incorrect order in #sorted xlat: BTRFS_QGROUP_LIMIT_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (246)
      > (unsigned long long) ((244)),
      "Incorrect order in #sorted xlat: BTRFS_QGROUP_RELATION_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (248)
      > (unsigned long long) ((246)),
      "Incorrect order in #sorted xlat: BTRFS_TEMPORARY_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (249)
      > (unsigned long long) ((248)),
      "Incorrect order in #sorted xlat: BTRFS_PERSISTENT_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (250)
      > (unsigned long long) ((249)),
      "Incorrect order in #sorted xlat: BTRFS_DEV_REPLACE_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (251)
      > (unsigned long long) ((250)),
      "Incorrect order in #sorted xlat: BTRFS_UUID_KEY_SUBVOL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (252)
      > (unsigned long long) ((251)),
      "Incorrect order in #sorted xlat: BTRFS_UUID_KEY_RECEIVED_SUBVOL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (253)
      > (unsigned long long) ((252)),
      "Incorrect order in #sorted xlat: BTRFS_STRING_ITEM_KEY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) ((4294967295U))
      > (unsigned long long) ((253)),
      "Incorrect order in #sorted xlat: UINT32_MAX"
      " is not larger than the previous value");

static const struct xlat_data btrfs_key_types_xdata[] = {
 { (uint64_t)(1), "BTRFS_INODE_ITEM_KEY" },
 { (uint64_t)(12), "BTRFS_INODE_REF_KEY" },
 { (uint64_t)(13), "BTRFS_INODE_EXTREF_KEY" },
 { (uint64_t)(24), "BTRFS_XATTR_ITEM_KEY" },
 { (uint64_t)(36), "BTRFS_VERITY_DESC_ITEM_KEY" },
 { (uint64_t)(37), "BTRFS_VERITY_MERKLE_ITEM_KEY" },
 { (uint64_t)(48), "BTRFS_ORPHAN_ITEM_KEY" },
 { (uint64_t)(60), "BTRFS_DIR_LOG_ITEM_KEY" },
 { (uint64_t)(72), "BTRFS_DIR_LOG_INDEX_KEY" },
 { (uint64_t)(84), "BTRFS_DIR_ITEM_KEY" },
 { (uint64_t)(96), "BTRFS_DIR_INDEX_KEY" },
 { (uint64_t)(108), "BTRFS_EXTENT_DATA_KEY" },
 { (uint64_t)(128), "BTRFS_EXTENT_CSUM_KEY" },
 { (uint64_t)(132), "BTRFS_ROOT_ITEM_KEY" },
 { (uint64_t)(144), "BTRFS_ROOT_BACKREF_KEY" },
 { (uint64_t)(156), "BTRFS_ROOT_REF_KEY" },
 { (uint64_t)(168), "BTRFS_EXTENT_ITEM_KEY" },
 { (uint64_t)(169), "BTRFS_METADATA_ITEM_KEY" },
 { (uint64_t)(176), "BTRFS_TREE_BLOCK_REF_KEY" },
 { (uint64_t)(178), "BTRFS_EXTENT_DATA_REF_KEY" },
 { (uint64_t)(180), "BTRFS_EXTENT_REF_V0_KEY" },
 { (uint64_t)(182), "BTRFS_SHARED_BLOCK_REF_KEY" },
 { (uint64_t)(184), "BTRFS_SHARED_DATA_REF_KEY" },
 { (uint64_t)(192), "BTRFS_BLOCK_GROUP_ITEM_KEY" },
 { (uint64_t)(198), "BTRFS_FREE_SPACE_INFO_KEY" },
 { (uint64_t)(199), "BTRFS_FREE_SPACE_EXTENT_KEY" },
 { (uint64_t)(200), "BTRFS_FREE_SPACE_BITMAP_KEY" },
 { (uint64_t)(204), "BTRFS_DEV_EXTENT_KEY" },
 { (uint64_t)(216), "BTRFS_DEV_ITEM_KEY" },
 { (uint64_t)(228), "BTRFS_CHUNK_ITEM_KEY" },
 { (uint64_t)(240), "BTRFS_QGROUP_STATUS_KEY" },
 { (uint64_t)(242), "BTRFS_QGROUP_INFO_KEY" },
 { (uint64_t)(244), "BTRFS_QGROUP_LIMIT_KEY" },
 { (uint64_t)(246), "BTRFS_QGROUP_RELATION_KEY" },
 { (uint64_t)(248), "BTRFS_TEMPORARY_ITEM_KEY" },
 { (uint64_t)(249), "BTRFS_PERSISTENT_ITEM_KEY" },
 { (uint64_t)(250), "BTRFS_DEV_REPLACE_KEY" },
 { (uint64_t)(251), "BTRFS_UUID_KEY_SUBVOL" },
 { (uint64_t)(252), "BTRFS_UUID_KEY_RECEIVED_SUBVOL" },
 { (uint64_t)(253), "BTRFS_STRING_ITEM_KEY" },
 { (uint64_t)((4294967295U)), "UINT32_MAX" },
};
const struct xlat btrfs_key_types[1] = { {
 .data = btrfs_key_types_xdata,
 .size = (sizeof(btrfs_key_types_xdata) / sizeof((btrfs_key_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_key_types_xdata)), __typeof__(&(btrfs_key_types_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((uint64_t) (1))
  | ((uint64_t) (12))
  | ((uint64_t) (13))
  | ((uint64_t) (24))
  | ((uint64_t) (36))
  | ((uint64_t) (37))
  | ((uint64_t) (48))
  | ((uint64_t) (60))
  | ((uint64_t) (72))
  | ((uint64_t) (84))
  | ((uint64_t) (96))
  | ((uint64_t) (108))
  | ((uint64_t) (128))
  | ((uint64_t) (132))
  | ((uint64_t) (144))
  | ((uint64_t) (156))
  | ((uint64_t) (168))
  | ((uint64_t) (169))
  | ((uint64_t) (176))
  | ((uint64_t) (178))
  | ((uint64_t) (180))
  | ((uint64_t) (182))
  | ((uint64_t) (184))
  | ((uint64_t) (192))
  | ((uint64_t) (198))
  | ((uint64_t) (199))
  | ((uint64_t) (200))
  | ((uint64_t) (204))
  | ((uint64_t) (216))
  | ((uint64_t) (228))
  | ((uint64_t) (240))
  | ((uint64_t) (242))
  | ((uint64_t) (244))
  | ((uint64_t) (246))
  | ((uint64_t) (248))
  | ((uint64_t) (249))
  | ((uint64_t) (250))
  | ((uint64_t) (251))
  | ((uint64_t) (252))
  | ((uint64_t) (253))
  | ((uint64_t) ((4294967295U)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_INODE_ITEM_KEY")
  + sizeof("BTRFS_INODE_REF_KEY")
  + sizeof("BTRFS_INODE_EXTREF_KEY")
  + sizeof("BTRFS_XATTR_ITEM_KEY")
  + sizeof("BTRFS_VERITY_DESC_ITEM_KEY")
  + sizeof("BTRFS_VERITY_MERKLE_ITEM_KEY")
  + sizeof("BTRFS_ORPHAN_ITEM_KEY")
  + sizeof("BTRFS_DIR_LOG_ITEM_KEY")
  + sizeof("BTRFS_DIR_LOG_INDEX_KEY")
  + sizeof("BTRFS_DIR_ITEM_KEY")
  + sizeof("BTRFS_DIR_INDEX_KEY")
  + sizeof("BTRFS_EXTENT_DATA_KEY")
  + sizeof("BTRFS_EXTENT_CSUM_KEY")
  + sizeof("BTRFS_ROOT_ITEM_KEY")
  + sizeof("BTRFS_ROOT_BACKREF_KEY")
  + sizeof("BTRFS_ROOT_REF_KEY")
  + sizeof("BTRFS_EXTENT_ITEM_KEY")
  + sizeof("BTRFS_METADATA_ITEM_KEY")
  + sizeof("BTRFS_TREE_BLOCK_REF_KEY")
  + sizeof("BTRFS_EXTENT_DATA_REF_KEY")
  + sizeof("BTRFS_EXTENT_REF_V0_KEY")
  + sizeof("BTRFS_SHARED_BLOCK_REF_KEY")
  + sizeof("BTRFS_SHARED_DATA_REF_KEY")
  + sizeof("BTRFS_BLOCK_GROUP_ITEM_KEY")
  + sizeof("BTRFS_FREE_SPACE_INFO_KEY")
  + sizeof("BTRFS_FREE_SPACE_EXTENT_KEY")
  + sizeof("BTRFS_FREE_SPACE_BITMAP_KEY")
  + sizeof("BTRFS_DEV_EXTENT_KEY")
  + sizeof("BTRFS_DEV_ITEM_KEY")
  + sizeof("BTRFS_CHUNK_ITEM_KEY")
  + sizeof("BTRFS_QGROUP_STATUS_KEY")
  + sizeof("BTRFS_QGROUP_INFO_KEY")
  + sizeof("BTRFS_QGROUP_LIMIT_KEY")
  + sizeof("BTRFS_QGROUP_RELATION_KEY")
  + sizeof("BTRFS_TEMPORARY_ITEM_KEY")
  + sizeof("BTRFS_PERSISTENT_ITEM_KEY")
  + sizeof("BTRFS_DEV_REPLACE_KEY")
  + sizeof("BTRFS_UUID_KEY_SUBVOL")
  + sizeof("BTRFS_UUID_KEY_RECEIVED_SUBVOL")
  + sizeof("BTRFS_STRING_ITEM_KEY")
  + sizeof("UINT32_MAX")
  ,
} };


static const struct xlat_data btrfs_logical_ino_args_flags_xdata[] = {
 { (unsigned)((1ULL << 0)), "BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET" },
};
const struct xlat btrfs_logical_ino_args_flags[1] = { {
 .data = btrfs_logical_ino_args_flags_xdata,
 .size = (sizeof(btrfs_logical_ino_args_flags_xdata) / sizeof((btrfs_logical_ino_args_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_logical_ino_args_flags_xdata)), __typeof__(&(btrfs_logical_ino_args_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((1ULL << 0)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET")
  ,
} };


static const struct xlat_data btrfs_qgroup_ctl_cmds_xdata[] = {
 { (uint64_t)(1), "BTRFS_QUOTA_CTL_ENABLE" },
 { (uint64_t)(2), "BTRFS_QUOTA_CTL_DISABLE" },
 { (uint64_t)(3), "BTRFS_QUOTA_CTL_RESCAN__NOTUSED" },
};
const struct xlat btrfs_qgroup_ctl_cmds[1] = { {
 .data = btrfs_qgroup_ctl_cmds_xdata,
 .size = (sizeof(btrfs_qgroup_ctl_cmds_xdata) / sizeof((btrfs_qgroup_ctl_cmds_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_qgroup_ctl_cmds_xdata)), __typeof__(&(btrfs_qgroup_ctl_cmds_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (1))
  | ((uint64_t) (2))
  | ((uint64_t) (3))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_QUOTA_CTL_ENABLE")
  + sizeof("BTRFS_QUOTA_CTL_DISABLE")
  + sizeof("BTRFS_QUOTA_CTL_RESCAN__NOTUSED")
  ,
} };


static const struct xlat_data btrfs_qgroup_inherit_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_QGROUP_INHERIT_SET_LIMITS" },
};
const struct xlat btrfs_qgroup_inherit_flags[1] = { {
 .data = btrfs_qgroup_inherit_flags_xdata,
 .size = (sizeof(btrfs_qgroup_inherit_flags_xdata) / sizeof((btrfs_qgroup_inherit_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_qgroup_inherit_flags_xdata)), __typeof__(&(btrfs_qgroup_inherit_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_QGROUP_INHERIT_SET_LIMITS")
  ,
} };


static const struct xlat_data btrfs_qgroup_limit_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_QGROUP_LIMIT_MAX_RFER" },
 { (uint64_t)((1ULL << 1)), "BTRFS_QGROUP_LIMIT_MAX_EXCL" },
 { (uint64_t)((1ULL << 2)), "BTRFS_QGROUP_LIMIT_RSV_RFER" },
 { (uint64_t)((1ULL << 3)), "BTRFS_QGROUP_LIMIT_RSV_EXCL" },
 { (uint64_t)((1ULL << 4)), "BTRFS_QGROUP_LIMIT_RFER_CMPR" },
 { (uint64_t)((1ULL << 5)), "BTRFS_QGROUP_LIMIT_EXCL_CMPR" },
};
const struct xlat btrfs_qgroup_limit_flags[1] = { {
 .data = btrfs_qgroup_limit_flags_xdata,
 .size = (sizeof(btrfs_qgroup_limit_flags_xdata) / sizeof((btrfs_qgroup_limit_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_qgroup_limit_flags_xdata)), __typeof__(&(btrfs_qgroup_limit_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  | ((uint64_t) ((1ULL << 4)))
  | ((uint64_t) ((1ULL << 5)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_QGROUP_LIMIT_MAX_RFER")
  + sizeof("BTRFS_QGROUP_LIMIT_MAX_EXCL")
  + sizeof("BTRFS_QGROUP_LIMIT_RSV_RFER")
  + sizeof("BTRFS_QGROUP_LIMIT_RSV_EXCL")
  + sizeof("BTRFS_QGROUP_LIMIT_RFER_CMPR")
  + sizeof("BTRFS_QGROUP_LIMIT_EXCL_CMPR")
  ,
} };


static const struct xlat_data btrfs_qgroup_status_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_QGROUP_STATUS_FLAG_ON" },
 { (uint64_t)((1ULL << 1)), "BTRFS_QGROUP_STATUS_FLAG_RESCAN" },
};
const struct xlat btrfs_qgroup_status_flags[1] = { {
 .data = btrfs_qgroup_status_flags_xdata,
 .size = (sizeof(btrfs_qgroup_status_flags_xdata) / sizeof((btrfs_qgroup_status_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_qgroup_status_flags_xdata)), __typeof__(&(btrfs_qgroup_status_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_QGROUP_STATUS_FLAG_ON")
  + sizeof("BTRFS_QGROUP_STATUS_FLAG_RESCAN")
  ,
} };


static const struct xlat_data btrfs_scrub_flags_xdata[] = {
 { (uint64_t)(1), "BTRFS_SCRUB_READONLY" },
};
const struct xlat btrfs_scrub_flags[1] = { {
 .data = btrfs_scrub_flags_xdata,
 .size = (sizeof(btrfs_scrub_flags_xdata) / sizeof((btrfs_scrub_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_scrub_flags_xdata)), __typeof__(&(btrfs_scrub_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (1))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_SCRUB_READONLY")
  ,
} };


static const struct xlat_data btrfs_send_flags_xdata[] = {
 { (unsigned)(0x1), "BTRFS_SEND_FLAG_NO_FILE_DATA" },
 { (unsigned)(0x2), "BTRFS_SEND_FLAG_OMIT_STREAM_HEADER" },
 { (unsigned)(0x4), "BTRFS_SEND_FLAG_OMIT_END_CMD" },
 { (unsigned)(0x8), "BTRFS_SEND_FLAG_VERSION" },
 { (unsigned)(0x10), "BTRFS_SEND_FLAG_COMPRESSED" },
};
const struct xlat btrfs_send_flags[1] = { {
 .data = btrfs_send_flags_xdata,
 .size = (sizeof(btrfs_send_flags_xdata) / sizeof((btrfs_send_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_send_flags_xdata)), __typeof__(&(btrfs_send_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x1))
  | ((unsigned) (0x2))
  | ((unsigned) (0x4))
  | ((unsigned) (0x8))
  | ((unsigned) (0x10))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_SEND_FLAG_NO_FILE_DATA")
  + sizeof("BTRFS_SEND_FLAG_OMIT_STREAM_HEADER")
  + sizeof("BTRFS_SEND_FLAG_OMIT_END_CMD")
  + sizeof("BTRFS_SEND_FLAG_VERSION")
  + sizeof("BTRFS_SEND_FLAG_COMPRESSED")
  ,
} };


static const struct xlat_data btrfs_snap_flags_v2_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_SUBVOL_CREATE_ASYNC" },
 { (uint64_t)((1ULL << 1)), "BTRFS_SUBVOL_RDONLY" },
 { (uint64_t)((1ULL << 2)), "BTRFS_SUBVOL_QGROUP_INHERIT" },
};
const struct xlat btrfs_snap_flags_v2[1] = { {
 .data = btrfs_snap_flags_v2_xdata,
 .size = (sizeof(btrfs_snap_flags_v2_xdata) / sizeof((btrfs_snap_flags_v2_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_snap_flags_v2_xdata)), __typeof__(&(btrfs_snap_flags_v2_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_SUBVOL_CREATE_ASYNC")
  + sizeof("BTRFS_SUBVOL_RDONLY")
  + sizeof("BTRFS_SUBVOL_QGROUP_INHERIT")
  ,
} };


static const struct xlat_data btrfs_space_info_flags_xdata[] = {
 { (uint64_t)((1ULL << 0)), "BTRFS_BLOCK_GROUP_DATA" },
 { (uint64_t)((1ULL << 1)), "BTRFS_BLOCK_GROUP_SYSTEM" },
 { (uint64_t)((1ULL << 2)), "BTRFS_BLOCK_GROUP_METADATA" },
 { (uint64_t)((1ULL << 3)), "BTRFS_BLOCK_GROUP_RAID0" },
 { (uint64_t)((1ULL << 4)), "BTRFS_BLOCK_GROUP_RAID1" },
 { (uint64_t)((1ULL << 5)), "BTRFS_BLOCK_GROUP_DUP" },
 { (uint64_t)((1ULL << 6)), "BTRFS_BLOCK_GROUP_RAID10" },
 { (uint64_t)((1ULL << 7)), "BTRFS_BLOCK_GROUP_RAID5" },
 { (uint64_t)((1ULL << 8)), "BTRFS_BLOCK_GROUP_RAID6" },
 { (uint64_t)((1ULL << 48)), "BTRFS_AVAIL_ALLOC_BIT_SINGLE" },
 { (uint64_t)((1ULL << 49)), "BTRFS_SPACE_INFO_GLOBAL_RSV" },
};
const struct xlat btrfs_space_info_flags[1] = { {
 .data = btrfs_space_info_flags_xdata,
 .size = (sizeof(btrfs_space_info_flags_xdata) / sizeof((btrfs_space_info_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_space_info_flags_xdata)), __typeof__(&(btrfs_space_info_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) ((1ULL << 0)))
  | ((uint64_t) ((1ULL << 1)))
  | ((uint64_t) ((1ULL << 2)))
  | ((uint64_t) ((1ULL << 3)))
  | ((uint64_t) ((1ULL << 4)))
  | ((uint64_t) ((1ULL << 5)))
  | ((uint64_t) ((1ULL << 6)))
  | ((uint64_t) ((1ULL << 7)))
  | ((uint64_t) ((1ULL << 8)))
  | ((uint64_t) ((1ULL << 48)))
  | ((uint64_t) ((1ULL << 49)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_BLOCK_GROUP_DATA")
  + sizeof("BTRFS_BLOCK_GROUP_SYSTEM")
  + sizeof("BTRFS_BLOCK_GROUP_METADATA")
  + sizeof("BTRFS_BLOCK_GROUP_RAID0")
  + sizeof("BTRFS_BLOCK_GROUP_RAID1")
  + sizeof("BTRFS_BLOCK_GROUP_DUP")
  + sizeof("BTRFS_BLOCK_GROUP_RAID10")
  + sizeof("BTRFS_BLOCK_GROUP_RAID5")
  + sizeof("BTRFS_BLOCK_GROUP_RAID6")
  + sizeof("BTRFS_AVAIL_ALLOC_BIT_SINGLE")
  + sizeof("BTRFS_SPACE_INFO_GLOBAL_RSV")
  ,
} };


static const struct xlat_data btrfs_tree_objectids_xdata[] = {
 { (uint64_t)(1ULL), "BTRFS_ROOT_TREE_OBJECTID" },
 { (uint64_t)(2ULL), "BTRFS_EXTENT_TREE_OBJECTID" },
 { (uint64_t)(3ULL), "BTRFS_CHUNK_TREE_OBJECTID" },
 { (uint64_t)(4ULL), "BTRFS_DEV_TREE_OBJECTID" },
 { (uint64_t)(5ULL), "BTRFS_FS_TREE_OBJECTID" },
 { (uint64_t)(6ULL), "BTRFS_ROOT_TREE_DIR_OBJECTID" },
 { (uint64_t)(7ULL), "BTRFS_CSUM_TREE_OBJECTID" },
 { (uint64_t)(8ULL), "BTRFS_QUOTA_TREE_OBJECTID" },
 { (uint64_t)(9ULL), "BTRFS_UUID_TREE_OBJECTID" },
 { (uint64_t)(10ULL), "BTRFS_FREE_SPACE_TREE_OBJECTID" },
 { (uint64_t)(11ULL), "BTRFS_BLOCK_GROUP_TREE_OBJECTID" },
 { (uint64_t)(256ULL), "BTRFS_FIRST_FREE_OBJECTID" },
 { (uint64_t)(-256ULL), "BTRFS_LAST_FREE_OBJECTID" },
 { (uint64_t)((18446744073709551615UL)), "UINT64_MAX" },
};
const struct xlat btrfs_tree_objectids[1] = { {
 .data = btrfs_tree_objectids_xdata,
 .size = (sizeof(btrfs_tree_objectids_xdata) / sizeof((btrfs_tree_objectids_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((btrfs_tree_objectids_xdata)), __typeof__(&(btrfs_tree_objectids_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((uint64_t) (1ULL))
  | ((uint64_t) (2ULL))
  | ((uint64_t) (3ULL))
  | ((uint64_t) (4ULL))
  | ((uint64_t) (5ULL))
  | ((uint64_t) (6ULL))
  | ((uint64_t) (7ULL))
  | ((uint64_t) (8ULL))
  | ((uint64_t) (9ULL))
  | ((uint64_t) (10ULL))
  | ((uint64_t) (11ULL))
  | ((uint64_t) (256ULL))
  | ((uint64_t) (-256ULL))
  | ((uint64_t) ((18446744073709551615UL)))
  ,
 .flags_strsz = 0
  + sizeof("BTRFS_ROOT_TREE_OBJECTID")
  + sizeof("BTRFS_EXTENT_TREE_OBJECTID")
  + sizeof("BTRFS_CHUNK_TREE_OBJECTID")
  + sizeof("BTRFS_DEV_TREE_OBJECTID")
  + sizeof("BTRFS_FS_TREE_OBJECTID")
  + sizeof("BTRFS_ROOT_TREE_DIR_OBJECTID")
  + sizeof("BTRFS_CSUM_TREE_OBJECTID")
  + sizeof("BTRFS_QUOTA_TREE_OBJECTID")
  + sizeof("BTRFS_UUID_TREE_OBJECTID")
  + sizeof("BTRFS_FREE_SPACE_TREE_OBJECTID")
  + sizeof("BTRFS_BLOCK_GROUP_TREE_OBJECTID")
  + sizeof("BTRFS_FIRST_FREE_OBJECTID")
  + sizeof("BTRFS_LAST_FREE_OBJECTID")
  + sizeof("UINT64_MAX")
  ,
} };

static void
btrfs_print_balance_args(const struct btrfs_balance_args *const bba)
{
 tprint_struct_begin();
 do { tprints_field_name("profiles"); printflags64((btrfs_space_info_flags), (sizeof((*bba).profiles) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).profiles) : sizeof((*bba).profiles) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).profiles) : sizeof((*bba).profiles) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).profiles) : sizeof((*bba).profiles) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).profiles) : (unsigned long long) ((*bba).profiles)), ("BTRFS_BLOCK_GROUP_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("usage"); if ((sizeof((*bba).usage) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).usage) : sizeof((*bba).usage) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).usage) : sizeof((*bba).usage) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).usage) : sizeof((*bba).usage) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).usage) : (unsigned long long) ((*bba).usage)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).usage) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).usage) : sizeof((*bba).usage) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).usage) : sizeof((*bba).usage) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).usage) : sizeof((*bba).usage) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).usage) : (unsigned long long) ((*bba).usage))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("devid"); print_dev_t((*bba).devid); } while (0);
 tprint_struct_next();
 do { tprints_field_name("pstart"); if ((sizeof((*bba).pstart) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).pstart) : (unsigned long long) ((*bba).pstart)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).pstart) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).pstart) : sizeof((*bba).pstart) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).pstart) : (unsigned long long) ((*bba).pstart))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("pend"); if ((sizeof((*bba).pend) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).pend) : sizeof((*bba).pend) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).pend) : sizeof((*bba).pend) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).pend) : sizeof((*bba).pend) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).pend) : (unsigned long long) ((*bba).pend)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).pend) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).pend) : sizeof((*bba).pend) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).pend) : sizeof((*bba).pend) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).pend) : sizeof((*bba).pend) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).pend) : (unsigned long long) ((*bba).pend))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("vstart"); if ((sizeof((*bba).vstart) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).vstart) : (unsigned long long) ((*bba).vstart)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).vstart) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).vstart) : sizeof((*bba).vstart) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).vstart) : (unsigned long long) ((*bba).vstart))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("vend"); if ((sizeof((*bba).vend) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).vend) : sizeof((*bba).vend) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).vend) : sizeof((*bba).vend) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).vend) : sizeof((*bba).vend) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).vend) : (unsigned long long) ((*bba).vend)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).vend) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).vend) : sizeof((*bba).vend) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).vend) : sizeof((*bba).vend) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).vend) : sizeof((*bba).vend) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).vend) : (unsigned long long) ((*bba).vend))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("target"); if ((sizeof((*bba).target) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).target) : sizeof((*bba).target) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).target) : sizeof((*bba).target) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).target) : sizeof((*bba).target) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).target) : (unsigned long long) ((*bba).target)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*bba).target) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).target) : sizeof((*bba).target) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).target) : sizeof((*bba).target) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).target) : sizeof((*bba).target) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).target) : (unsigned long long) ((*bba).target))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("flags"); printflags64((btrfs_balance_args), (sizeof((*bba).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*bba).flags) : sizeof((*bba).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*bba).flags) : sizeof((*bba).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*bba).flags) : sizeof((*bba).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*bba).flags) : (unsigned long long) ((*bba).flags)), ("BTRFS_BALANCE_ARGS_???")); } while (0);
 tprint_struct_end();
}
static void
btrfs_print_balance(struct tcb *const tcp, const kernel_ulong_t arg, _Bool out)
{
 struct btrfs_ioctl_balance_args balance_args;
 if (umoven_or_printaddr((tcp), (arg), sizeof(*(&balance_args)), (void *) (&balance_args)))
  return;
 tprint_struct_begin();
 do { tprints_field_name("flags"); printflags64((btrfs_balance_flags), (sizeof((balance_args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((balance_args).flags) : sizeof((balance_args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((balance_args).flags) : sizeof((balance_args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((balance_args).flags) : sizeof((balance_args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((balance_args).flags) : (unsigned long long) ((balance_args).flags)), ("BTRFS_BALANCE_???")); } while (0);
 if (out) {
  tprint_struct_next();
  do { tprints_field_name("state"); printflags64((btrfs_balance_state), (sizeof((balance_args).state) == sizeof(char) ? (unsigned long long) (unsigned char) ((balance_args).state) : sizeof((balance_args).state) == sizeof(short) ? (unsigned long long) (unsigned short) ((balance_args).state) : sizeof((balance_args).state) == sizeof(int) ? (unsigned long long) (unsigned int) ((balance_args).state) : sizeof((balance_args).state) == sizeof(long) ? (unsigned long long) (unsigned long) ((balance_args).state) : (unsigned long long) ((balance_args).state)), ("BTRFS_BALANCE_STATE_???")); } while (0);
 }
 if (balance_args.flags & (1ULL << 0)) {
  tprint_struct_next();
  do { tprints_field_name("data"); (btrfs_print_balance_args)(&((balance_args).data)); } while (0);
 }
 if (balance_args.flags & (1ULL << 2)) {
  tprint_struct_next();
  do { tprints_field_name("meta"); (btrfs_print_balance_args)(&((balance_args).meta)); } while (0);
 }
 if (balance_args.flags & (1ULL << 1)) {
  tprint_struct_next();
  do { tprints_field_name("sys"); (btrfs_print_balance_args)(&((balance_args).sys)); } while (0);
 }
 tprint_struct_end();
}
static void
btrfs_print_features(const struct btrfs_ioctl_feature_flags *flags)
{
 tprint_struct_begin();
 do { tprints_field_name("compat_flags"); printflags64((btrfs_features_compat), (sizeof((*flags).compat_flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*flags).compat_flags) : sizeof((*flags).compat_flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*flags).compat_flags) : sizeof((*flags).compat_flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*flags).compat_flags) : sizeof((*flags).compat_flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*flags).compat_flags) : (unsigned long long) ((*flags).compat_flags)), ("BTRFS_FEATURE_COMPAT_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("compat_ro_flags"); printflags64((btrfs_features_compat_ro), (sizeof((*flags).compat_ro_flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*flags).compat_ro_flags) : sizeof((*flags).compat_ro_flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*flags).compat_ro_flags) : sizeof((*flags).compat_ro_flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*flags).compat_ro_flags) : sizeof((*flags).compat_ro_flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*flags).compat_ro_flags) : (unsigned long long) ((*flags).compat_ro_flags)), ("BTRFS_FEATURE_COMPAT_RO_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("incompat_flags"); printflags64((btrfs_features_incompat), (sizeof((*flags).incompat_flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*flags).incompat_flags) : sizeof((*flags).incompat_flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*flags).incompat_flags) : sizeof((*flags).incompat_flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*flags).incompat_flags) : sizeof((*flags).incompat_flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*flags).incompat_flags) : (unsigned long long) ((*flags).incompat_flags)), ("BTRFS_FEATURE_INCOMPAT_???")); } while (0);
 tprint_struct_end();
}
static void
btrfs_print_qgroup_limit(const struct btrfs_qgroup_limit *lim)
{
 tprint_struct_begin();
 do { tprints_field_name("flags"); printflags64((btrfs_qgroup_limit_flags), (sizeof((*lim).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*lim).flags) : sizeof((*lim).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*lim).flags) : sizeof((*lim).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*lim).flags) : sizeof((*lim).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*lim).flags) : (unsigned long long) ((*lim).flags)), ("BTRFS_QGROUP_LIMIT_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("max_rfer"); tprintf_string("%llu", (sizeof((*lim).max_rfer) == sizeof(char) ? (unsigned long long) (unsigned char) ((*lim).max_rfer) : sizeof((*lim).max_rfer) == sizeof(short) ? (unsigned long long) (unsigned short) ((*lim).max_rfer) : sizeof((*lim).max_rfer) == sizeof(int) ? (unsigned long long) (unsigned int) ((*lim).max_rfer) : sizeof((*lim).max_rfer) == sizeof(long) ? (unsigned long long) (unsigned long) ((*lim).max_rfer) : (unsigned long long) ((*lim).max_rfer))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("max_excl"); tprintf_string("%llu", (sizeof((*lim).max_excl) == sizeof(char) ? (unsigned long long) (unsigned char) ((*lim).max_excl) : sizeof((*lim).max_excl) == sizeof(short) ? (unsigned long long) (unsigned short) ((*lim).max_excl) : sizeof((*lim).max_excl) == sizeof(int) ? (unsigned long long) (unsigned int) ((*lim).max_excl) : sizeof((*lim).max_excl) == sizeof(long) ? (unsigned long long) (unsigned long) ((*lim).max_excl) : (unsigned long long) ((*lim).max_excl))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("rsv_rfer"); tprintf_string("%llu", (sizeof((*lim).rsv_rfer) == sizeof(char) ? (unsigned long long) (unsigned char) ((*lim).rsv_rfer) : sizeof((*lim).rsv_rfer) == sizeof(short) ? (unsigned long long) (unsigned short) ((*lim).rsv_rfer) : sizeof((*lim).rsv_rfer) == sizeof(int) ? (unsigned long long) (unsigned int) ((*lim).rsv_rfer) : sizeof((*lim).rsv_rfer) == sizeof(long) ? (unsigned long long) (unsigned long) ((*lim).rsv_rfer) : (unsigned long long) ((*lim).rsv_rfer))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("rsv_excl"); tprintf_string("%llu", (sizeof((*lim).rsv_excl) == sizeof(char) ? (unsigned long long) (unsigned char) ((*lim).rsv_excl) : sizeof((*lim).rsv_excl) == sizeof(short) ? (unsigned long long) (unsigned short) ((*lim).rsv_excl) : sizeof((*lim).rsv_excl) == sizeof(int) ? (unsigned long long) (unsigned int) ((*lim).rsv_excl) : sizeof((*lim).rsv_excl) == sizeof(long) ? (unsigned long long) (unsigned long) ((*lim).rsv_excl) : (unsigned long long) ((*lim).rsv_excl))); } while (0);
 tprint_struct_end();
}
static void
btrfs_print_data_container_header(const struct btrfs_data_container *container)
{
 tprint_struct_begin();
 do { tprints_field_name("bytes_left"); tprintf_string("%llu", (sizeof((*container).bytes_left) == sizeof(char) ? (unsigned long long) (unsigned char) ((*container).bytes_left) : sizeof((*container).bytes_left) == sizeof(short) ? (unsigned long long) (unsigned short) ((*container).bytes_left) : sizeof((*container).bytes_left) == sizeof(int) ? (unsigned long long) (unsigned int) ((*container).bytes_left) : sizeof((*container).bytes_left) == sizeof(long) ? (unsigned long long) (unsigned long) ((*container).bytes_left) : (unsigned long long) ((*container).bytes_left))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("bytes_missing"); tprintf_string("%llu", (sizeof((*container).bytes_missing) == sizeof(char) ? (unsigned long long) (unsigned char) ((*container).bytes_missing) : sizeof((*container).bytes_missing) == sizeof(short) ? (unsigned long long) (unsigned short) ((*container).bytes_missing) : sizeof((*container).bytes_missing) == sizeof(int) ? (unsigned long long) (unsigned int) ((*container).bytes_missing) : sizeof((*container).bytes_missing) == sizeof(long) ? (unsigned long long) (unsigned long) ((*container).bytes_missing) : (unsigned long long) ((*container).bytes_missing))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("elem_cnt"); tprintf_string("%llu", (sizeof((*container).elem_cnt) == sizeof(char) ? (unsigned long long) (unsigned char) ((*container).elem_cnt) : sizeof((*container).elem_cnt) == sizeof(short) ? (unsigned long long) (unsigned short) ((*container).elem_cnt) : sizeof((*container).elem_cnt) == sizeof(int) ? (unsigned long long) (unsigned int) ((*container).elem_cnt) : sizeof((*container).elem_cnt) == sizeof(long) ? (unsigned long long) (unsigned long) ((*container).elem_cnt) : (unsigned long long) ((*container).elem_cnt))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("elem_missed"); tprintf_string("%llu", (sizeof((*container).elem_missed) == sizeof(char) ? (unsigned long long) (unsigned char) ((*container).elem_missed) : sizeof((*container).elem_missed) == sizeof(short) ? (unsigned long long) (unsigned short) ((*container).elem_missed) : sizeof((*container).elem_missed) == sizeof(int) ? (unsigned long long) (unsigned int) ((*container).elem_missed) : sizeof((*container).elem_missed) == sizeof(long) ? (unsigned long long) (unsigned long) ((*container).elem_missed) : (unsigned long long) ((*container).elem_missed))); } while (0);
}
static void
btrfs_print_data_container_footer(void)
{
 tprint_struct_end();
}
static _Bool
print_btrfs_data_container_logical_ino(struct tcb *tcp, void *elem_buf,
           size_t elem_size, void *data)
{
 const struct {
  uint64_t inum;
  uint64_t offset;
  uint64_t root;
 } *const record = elem_buf;
 tprint_struct_begin();
 do { tprints_field_name("inum"); tprintf_string("%llu", (sizeof((*record).inum) == sizeof(char) ? (unsigned long long) (unsigned char) ((*record).inum) : sizeof((*record).inum) == sizeof(short) ? (unsigned long long) (unsigned short) ((*record).inum) : sizeof((*record).inum) == sizeof(int) ? (unsigned long long) (unsigned int) ((*record).inum) : sizeof((*record).inum) == sizeof(long) ? (unsigned long long) (unsigned long) ((*record).inum) : (unsigned long long) ((*record).inum))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("offset"); tprintf_string("%llu", (sizeof((*record).offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*record).offset) : sizeof((*record).offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*record).offset) : sizeof((*record).offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*record).offset) : sizeof((*record).offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*record).offset) : (unsigned long long) ((*record).offset))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("root"); tprintf_string("%llu", (sizeof((*record).root) == sizeof(char) ? (unsigned long long) (unsigned char) ((*record).root) : sizeof((*record).root) == sizeof(short) ? (unsigned long long) (unsigned short) ((*record).root) : sizeof((*record).root) == sizeof(int) ? (unsigned long long) (unsigned int) ((*record).root) : sizeof((*record).root) == sizeof(long) ? (unsigned long long) (unsigned long) ((*record).root) : (unsigned long long) ((*record).root))); } while (0);
 tprint_struct_end();
 return 1;
}
static void
btrfs_print_logical_ino_container(struct tcb *tcp,
      const uint64_t inodes_addr)
{
 struct btrfs_data_container container;
 if (umoven_or_printaddr((tcp), (inodes_addr), sizeof(*(&container)), (void *) (&container)))
  return;
 btrfs_print_data_container_header(&container);
 if (((tcp)->qual_flg & 0x002)) {
  tprint_struct_next();
  tprint_more_data_follows();
 } else {
  const uint64_t val_addr =
   inodes_addr + __builtin_offsetof (typeof(container), val);
  uint64_t record[3];
  tprint_struct_next();
  tprints_field_name("val");
  print_array(tcp, val_addr, container.elem_cnt / 3,
       record, sizeof(record),
       tfetch_mem,
       print_btrfs_data_container_logical_ino, 0);
 }
 btrfs_print_data_container_footer();
}
static _Bool
print_btrfs_data_container_ino_path(struct tcb *tcp, void *elem_buf,
           size_t elem_size, void *data)
{
 const uint64_t *const offset = elem_buf;
 const uint64_t *const val_addr = data;
 printpath(tcp, *val_addr + *offset);
 return 1;
}
static void
btrfs_print_ino_path_container(struct tcb *tcp,
          const uint64_t fspath_addr)
{
 struct btrfs_data_container container;
 if (umoven_or_printaddr((tcp), (fspath_addr), sizeof(*(&container)), (void *) (&container)))
  return;
 btrfs_print_data_container_header(&container);
 if (((tcp)->qual_flg & 0x002)) {
  tprint_struct_next();
  tprint_more_data_follows();
 } else {
  uint64_t val_addr =
   fspath_addr + __builtin_offsetof (typeof(container), val);
  uint64_t offset;
  tprint_struct_next();
  tprints_field_name("val");
  print_array(tcp, val_addr, container.elem_cnt,
       &offset, sizeof(offset),
       tfetch_mem,
       print_btrfs_data_container_ino_path, &val_addr);
 }
 btrfs_print_data_container_footer();
}
static void
btrfs_print_qgroup_inherit(struct tcb *const tcp, const kernel_ulong_t qgi_addr)
{
 struct btrfs_qgroup_inherit inherit;
 if (umoven_or_printaddr((tcp), (qgi_addr), sizeof(*(&inherit)), (void *) (&inherit)))
  return;
 tprint_struct_begin();
 do { tprints_field_name("flags"); printflags64((btrfs_qgroup_inherit_flags), (sizeof((inherit).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((inherit).flags) : sizeof((inherit).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((inherit).flags) : sizeof((inherit).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((inherit).flags) : sizeof((inherit).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((inherit).flags) : (unsigned long long) ((inherit).flags)), ("BTRFS_QGROUP_INHERIT_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("num_qgroups"); tprintf_string("%llu", (sizeof((inherit).num_qgroups) == sizeof(char) ? (unsigned long long) (unsigned char) ((inherit).num_qgroups) : sizeof((inherit).num_qgroups) == sizeof(short) ? (unsigned long long) (unsigned short) ((inherit).num_qgroups) : sizeof((inherit).num_qgroups) == sizeof(int) ? (unsigned long long) (unsigned int) ((inherit).num_qgroups) : sizeof((inherit).num_qgroups) == sizeof(long) ? (unsigned long long) (unsigned long) ((inherit).num_qgroups) : (unsigned long long) ((inherit).num_qgroups))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("num_ref_copies"); tprintf_string("%llu", (sizeof((inherit).num_ref_copies) == sizeof(char) ? (unsigned long long) (unsigned char) ((inherit).num_ref_copies) : sizeof((inherit).num_ref_copies) == sizeof(short) ? (unsigned long long) (unsigned short) ((inherit).num_ref_copies) : sizeof((inherit).num_ref_copies) == sizeof(int) ? (unsigned long long) (unsigned int) ((inherit).num_ref_copies) : sizeof((inherit).num_ref_copies) == sizeof(long) ? (unsigned long long) (unsigned long) ((inherit).num_ref_copies) : (unsigned long long) ((inherit).num_ref_copies))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("num_excl_copies"); tprintf_string("%llu", (sizeof((inherit).num_excl_copies) == sizeof(char) ? (unsigned long long) (unsigned char) ((inherit).num_excl_copies) : sizeof((inherit).num_excl_copies) == sizeof(short) ? (unsigned long long) (unsigned short) ((inherit).num_excl_copies) : sizeof((inherit).num_excl_copies) == sizeof(int) ? (unsigned long long) (unsigned int) ((inherit).num_excl_copies) : sizeof((inherit).num_excl_copies) == sizeof(long) ? (unsigned long long) (unsigned long) ((inherit).num_excl_copies) : (unsigned long long) ((inherit).num_excl_copies))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("lim"); (btrfs_print_qgroup_limit)(&((inherit).lim)); } while (0);
 if (((tcp)->qual_flg & 0x002)) {
  tprint_struct_next();
  tprint_more_data_follows();
 } else {
  uint64_t record;
  tprint_struct_next();
  tprints_field_name("qgroups");
  print_array(tcp, qgi_addr + __builtin_offsetof (typeof(inherit), qgroups),
       inherit.num_qgroups, &record, sizeof(record),
       tfetch_mem, print_uint_array_member, 0);
 }
 tprint_struct_end();
}
static void
print_btrfs_ioctl_search_key(const struct btrfs_ioctl_search_key *const key,
        const _Bool is_entering, const _Bool is_not_abbrev)
{
 tprint_struct_begin();
 if (is_entering) {
  do { tprints_field_name("tree_id"); printxval64_u((btrfs_tree_objectids), (sizeof(((*key)).tree_id) == sizeof(char) ? (unsigned long long) (unsigned char) (((*key)).tree_id) : sizeof(((*key)).tree_id) == sizeof(short) ? (unsigned long long) (unsigned short) (((*key)).tree_id) : sizeof(((*key)).tree_id) == sizeof(int) ? (unsigned long long) (unsigned int) (((*key)).tree_id) : sizeof(((*key)).tree_id) == sizeof(long) ? (unsigned long long) (unsigned long) (((*key)).tree_id) : (unsigned long long) (((*key)).tree_id)), (((void *)0))); } while (0);
  if (key->min_objectid != 256ULL ||
      is_not_abbrev) {
   tprint_struct_next();
   do { tprints_field_name("min_objectid"); printxval64_u((btrfs_tree_objectids), (sizeof(((*key)).min_objectid) == sizeof(char) ? (unsigned long long) (unsigned char) (((*key)).min_objectid) : sizeof(((*key)).min_objectid) == sizeof(short) ? (unsigned long long) (unsigned short) (((*key)).min_objectid) : sizeof(((*key)).min_objectid) == sizeof(int) ? (unsigned long long) (unsigned int) (((*key)).min_objectid) : sizeof(((*key)).min_objectid) == sizeof(long) ? (unsigned long long) (unsigned long) (((*key)).min_objectid) : (unsigned long long) (((*key)).min_objectid)), (((void *)0))); } while (0);
  }
  if (key->max_objectid != -256ULL ||
      is_not_abbrev) {
   tprint_struct_next();
   do { tprints_field_name("max_objectid"); printxval64_u((btrfs_tree_objectids), (sizeof(((*key)).max_objectid) == sizeof(char) ? (unsigned long long) (unsigned char) (((*key)).max_objectid) : sizeof(((*key)).max_objectid) == sizeof(short) ? (unsigned long long) (unsigned short) (((*key)).max_objectid) : sizeof(((*key)).max_objectid) == sizeof(int) ? (unsigned long long) (unsigned int) (((*key)).max_objectid) : sizeof(((*key)).max_objectid) == sizeof(long) ? (unsigned long long) (unsigned long) (((*key)).max_objectid) : (unsigned long long) (((*key)).max_objectid)), (((void *)0))); } while (0);
  }
  tprint_struct_next();
  do { tprints_field_name("min_offset"); if ((sizeof((*key).min_offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).min_offset) : (unsigned long long) ((*key).min_offset)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*key).min_offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).min_offset) : sizeof((*key).min_offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).min_offset) : (unsigned long long) ((*key).min_offset))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("max_offset"); if ((sizeof((*key).max_offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).max_offset) : (unsigned long long) ((*key).max_offset)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*key).max_offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).max_offset) : sizeof((*key).max_offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).max_offset) : (unsigned long long) ((*key).max_offset))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("min_transid"); if ((sizeof((*key).min_transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).min_transid) : (unsigned long long) ((*key).min_transid)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*key).min_transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).min_transid) : sizeof((*key).min_transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).min_transid) : (unsigned long long) ((*key).min_transid))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("max_transid"); if ((sizeof((*key).max_transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).max_transid) : (unsigned long long) ((*key).max_transid)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((*key).max_transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).max_transid) : sizeof((*key).max_transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).max_transid) : (unsigned long long) ((*key).max_transid))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("min_type"); printxval64_u((btrfs_key_types), (sizeof(((*key)).min_type) == sizeof(char) ? (unsigned long long) (unsigned char) (((*key)).min_type) : sizeof(((*key)).min_type) == sizeof(short) ? (unsigned long long) (unsigned short) (((*key)).min_type) : sizeof(((*key)).min_type) == sizeof(int) ? (unsigned long long) (unsigned int) (((*key)).min_type) : sizeof(((*key)).min_type) == sizeof(long) ? (unsigned long long) (unsigned long) (((*key)).min_type) : (unsigned long long) (((*key)).min_type)), (((void *)0))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("max_type"); printxval64_u((btrfs_key_types), (sizeof(((*key)).max_type) == sizeof(char) ? (unsigned long long) (unsigned char) (((*key)).max_type) : sizeof(((*key)).max_type) == sizeof(short) ? (unsigned long long) (unsigned short) (((*key)).max_type) : sizeof(((*key)).max_type) == sizeof(int) ? (unsigned long long) (unsigned int) (((*key)).max_type) : sizeof(((*key)).max_type) == sizeof(long) ? (unsigned long long) (unsigned long) (((*key)).max_type) : (unsigned long long) (((*key)).max_type)), (((void *)0))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("nr_items"); tprintf_string("%llu", (sizeof((*key).nr_items) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).nr_items) : (unsigned long long) ((*key).nr_items))); } while (0);
 } else {
  do { tprints_field_name("nr_items"); tprintf_string("%llu", (sizeof((*key).nr_items) == sizeof(char) ? (unsigned long long) (unsigned char) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(short) ? (unsigned long long) (unsigned short) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(int) ? (unsigned long long) (unsigned int) ((*key).nr_items) : sizeof((*key).nr_items) == sizeof(long) ? (unsigned long long) (unsigned long) ((*key).nr_items) : (unsigned long long) ((*key).nr_items))); } while (0);
 }
 tprint_struct_end();
}
static void
print_btrfs_ioctl_search_header(const struct btrfs_ioctl_search_header *p)
{
 tprint_struct_begin();
 do { tprints_field_name("transid"); tprintf_string("%llu", (sizeof((*p).transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).transid) : sizeof((*p).transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).transid) : sizeof((*p).transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).transid) : sizeof((*p).transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).transid) : (unsigned long long) ((*p).transid))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("objectid"); printxval64_u((btrfs_tree_objectids), (sizeof(((*p)).objectid) == sizeof(char) ? (unsigned long long) (unsigned char) (((*p)).objectid) : sizeof(((*p)).objectid) == sizeof(short) ? (unsigned long long) (unsigned short) (((*p)).objectid) : sizeof(((*p)).objectid) == sizeof(int) ? (unsigned long long) (unsigned int) (((*p)).objectid) : sizeof(((*p)).objectid) == sizeof(long) ? (unsigned long long) (unsigned long) (((*p)).objectid) : (unsigned long long) (((*p)).objectid)), (((void *)0))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("offset"); tprintf_string("%llu", (sizeof((*p).offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).offset) : sizeof((*p).offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).offset) : sizeof((*p).offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).offset) : sizeof((*p).offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).offset) : (unsigned long long) ((*p).offset))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("type"); printxval64_u((btrfs_key_types), (sizeof(((*p)).type) == sizeof(char) ? (unsigned long long) (unsigned char) (((*p)).type) : sizeof(((*p)).type) == sizeof(short) ? (unsigned long long) (unsigned short) (((*p)).type) : sizeof(((*p)).type) == sizeof(int) ? (unsigned long long) (unsigned int) (((*p)).type) : sizeof(((*p)).type) == sizeof(long) ? (unsigned long long) (unsigned long) (((*p)).type) : (unsigned long long) (((*p)).type)), (((void *)0))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("len"); tprintf_string("%llu", (sizeof((*p).len) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).len) : sizeof((*p).len) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).len) : sizeof((*p).len) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).len) : sizeof((*p).len) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).len) : (unsigned long long) ((*p).len))); } while (0);
 tprint_struct_end();
}
static void
decode_search_arg_buf(struct tcb *tcp, kernel_ulong_t buf_addr, uint64_t buf_size,
        unsigned int nr_items)
{
 if ((!((tcp)->flags & 0x04)))
  return;
 tprint_struct_next();
 if (((tcp)->qual_flg & 0x002)) {
  tprint_more_data_follows();
 } else {
  tprints_field_name("buf");
  tprint_array_begin();
  uint64_t off = 0;
  for (unsigned int i = 0; i < nr_items; ++i) {
   if (i)
    tprint_array_next();
   struct btrfs_ioctl_search_header sh;
   uint64_t addr = buf_addr + off;
   if (addr < buf_addr || off + sizeof(sh) > buf_size ||
       i > max_strlen) {
    tprint_more_data_follows();
    break;
   }
   if (!tfetch_mem(tcp, addr, sizeof(sh), &sh)) {
    tprint_more_data_follows();
    printaddr_comment(addr);
    break;
   }
   print_btrfs_ioctl_search_header(&sh);
   off += sizeof(sh) + sh.len;
  }
  tprint_array_end();
 }
}
static _Bool
print_objectid_callback(struct tcb *tcp, void *elem_buf,
   size_t elem_size, void *data)
{
 printxvals_ex(*(uint64_t *) elem_buf, ((void *)0), XLAT_STYLE_FMT_U,
        btrfs_tree_objectids, ((void *)0));
 return 1;
}
static _Bool
print_btrfs_ioctl_space_info(struct tcb *tcp, void *elem_buf,
        size_t elem_size, void *data)
{
 const struct btrfs_ioctl_space_info *info = elem_buf;
 tprint_struct_begin();
 do { tprints_field_name("flags"); printflags64((btrfs_space_info_flags), (sizeof((*info).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*info).flags) : sizeof((*info).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*info).flags) : sizeof((*info).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*info).flags) : sizeof((*info).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*info).flags) : (unsigned long long) ((*info).flags)), ("BTRFS_SPACE_INFO_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("total_bytes"); tprintf_string("%llu", (sizeof((*info).total_bytes) == sizeof(char) ? (unsigned long long) (unsigned char) ((*info).total_bytes) : sizeof((*info).total_bytes) == sizeof(short) ? (unsigned long long) (unsigned short) ((*info).total_bytes) : sizeof((*info).total_bytes) == sizeof(int) ? (unsigned long long) (unsigned int) ((*info).total_bytes) : sizeof((*info).total_bytes) == sizeof(long) ? (unsigned long long) (unsigned long) ((*info).total_bytes) : (unsigned long long) ((*info).total_bytes))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("used_bytes"); tprintf_string("%llu", (sizeof((*info).used_bytes) == sizeof(char) ? (unsigned long long) (unsigned char) ((*info).used_bytes) : sizeof((*info).used_bytes) == sizeof(short) ? (unsigned long long) (unsigned short) ((*info).used_bytes) : sizeof((*info).used_bytes) == sizeof(int) ? (unsigned long long) (unsigned int) ((*info).used_bytes) : sizeof((*info).used_bytes) == sizeof(long) ? (unsigned long long) (unsigned long) ((*info).used_bytes) : (unsigned long long) ((*info).used_bytes))); } while (0);
 tprint_struct_end();
 return 1;
}
static void
print_btrfs_timespec(const struct_btrfs_ioctl_timespec * const arg)
{
 const struct_btrfs_ioctl_timespec *const p = arg;
 tprint_struct_begin();
 do { tprints_field_name("sec"); tprintf_string("%llu", (sizeof((*p).sec) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).sec) : sizeof((*p).sec) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).sec) : sizeof((*p).sec) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).sec) : sizeof((*p).sec) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).sec) : (unsigned long long) ((*p).sec))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("nsec"); tprintf_string("%llu", (sizeof((*p).nsec) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).nsec) : sizeof((*p).nsec) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).nsec) : sizeof((*p).nsec) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).nsec) : sizeof((*p).nsec) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).nsec) : (unsigned long long) ((*p).nsec))); } while (0);
 tprint_struct_end();
 tprints_comment(sprinttime_nsec(p->sec, p->nsec));
}
static void
print_btrfs_scrub_progress(const struct btrfs_scrub_progress *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("data_extents_scrubbed"); tprintf_string("%llu", (sizeof((*p).data_extents_scrubbed) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).data_extents_scrubbed) : sizeof((*p).data_extents_scrubbed) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).data_extents_scrubbed) : sizeof((*p).data_extents_scrubbed) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).data_extents_scrubbed) : sizeof((*p).data_extents_scrubbed) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).data_extents_scrubbed) : (unsigned long long) ((*p).data_extents_scrubbed))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("tree_extents_scrubbed"); tprintf_string("%llu", (sizeof((*p).tree_extents_scrubbed) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).tree_extents_scrubbed) : sizeof((*p).tree_extents_scrubbed) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).tree_extents_scrubbed) : sizeof((*p).tree_extents_scrubbed) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).tree_extents_scrubbed) : sizeof((*p).tree_extents_scrubbed) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).tree_extents_scrubbed) : (unsigned long long) ((*p).tree_extents_scrubbed))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("data_bytes_scrubbed"); tprintf_string("%llu", (sizeof((*p).data_bytes_scrubbed) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).data_bytes_scrubbed) : sizeof((*p).data_bytes_scrubbed) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).data_bytes_scrubbed) : sizeof((*p).data_bytes_scrubbed) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).data_bytes_scrubbed) : sizeof((*p).data_bytes_scrubbed) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).data_bytes_scrubbed) : (unsigned long long) ((*p).data_bytes_scrubbed))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("tree_bytes_scrubbed"); tprintf_string("%llu", (sizeof((*p).tree_bytes_scrubbed) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).tree_bytes_scrubbed) : sizeof((*p).tree_bytes_scrubbed) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).tree_bytes_scrubbed) : sizeof((*p).tree_bytes_scrubbed) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).tree_bytes_scrubbed) : sizeof((*p).tree_bytes_scrubbed) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).tree_bytes_scrubbed) : (unsigned long long) ((*p).tree_bytes_scrubbed))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("read_errors"); tprintf_string("%llu", (sizeof((*p).read_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).read_errors) : sizeof((*p).read_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).read_errors) : sizeof((*p).read_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).read_errors) : sizeof((*p).read_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).read_errors) : (unsigned long long) ((*p).read_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("csum_errors"); tprintf_string("%llu", (sizeof((*p).csum_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).csum_errors) : sizeof((*p).csum_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).csum_errors) : sizeof((*p).csum_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).csum_errors) : sizeof((*p).csum_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).csum_errors) : (unsigned long long) ((*p).csum_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("verify_errors"); tprintf_string("%llu", (sizeof((*p).verify_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).verify_errors) : sizeof((*p).verify_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).verify_errors) : sizeof((*p).verify_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).verify_errors) : sizeof((*p).verify_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).verify_errors) : (unsigned long long) ((*p).verify_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("no_csum"); tprintf_string("%llu", (sizeof((*p).no_csum) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).no_csum) : sizeof((*p).no_csum) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).no_csum) : sizeof((*p).no_csum) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).no_csum) : sizeof((*p).no_csum) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).no_csum) : (unsigned long long) ((*p).no_csum))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("csum_discards"); tprintf_string("%llu", (sizeof((*p).csum_discards) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).csum_discards) : sizeof((*p).csum_discards) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).csum_discards) : sizeof((*p).csum_discards) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).csum_discards) : sizeof((*p).csum_discards) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).csum_discards) : (unsigned long long) ((*p).csum_discards))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("super_errors"); tprintf_string("%llu", (sizeof((*p).super_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).super_errors) : sizeof((*p).super_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).super_errors) : sizeof((*p).super_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).super_errors) : sizeof((*p).super_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).super_errors) : (unsigned long long) ((*p).super_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("malloc_errors"); tprintf_string("%llu", (sizeof((*p).malloc_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).malloc_errors) : sizeof((*p).malloc_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).malloc_errors) : sizeof((*p).malloc_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).malloc_errors) : sizeof((*p).malloc_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).malloc_errors) : (unsigned long long) ((*p).malloc_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("uncorrectable_errors"); tprintf_string("%llu", (sizeof((*p).uncorrectable_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).uncorrectable_errors) : sizeof((*p).uncorrectable_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).uncorrectable_errors) : sizeof((*p).uncorrectable_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).uncorrectable_errors) : sizeof((*p).uncorrectable_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).uncorrectable_errors) : (unsigned long long) ((*p).uncorrectable_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("corrected_errors"); tprintf_string("%llu", (sizeof((*p).corrected_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).corrected_errors) : sizeof((*p).corrected_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).corrected_errors) : sizeof((*p).corrected_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).corrected_errors) : sizeof((*p).corrected_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).corrected_errors) : (unsigned long long) ((*p).corrected_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("last_physical"); tprintf_string("%llu", (sizeof((*p).last_physical) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).last_physical) : sizeof((*p).last_physical) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).last_physical) : sizeof((*p).last_physical) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).last_physical) : sizeof((*p).last_physical) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).last_physical) : (unsigned long long) ((*p).last_physical))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("unverified_errors"); tprintf_string("%llu", (sizeof((*p).unverified_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).unverified_errors) : sizeof((*p).unverified_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).unverified_errors) : sizeof((*p).unverified_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).unverified_errors) : sizeof((*p).unverified_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).unverified_errors) : (unsigned long long) ((*p).unverified_errors))); } while (0);
 tprint_struct_end();
}
static void
print_btrfs_replace_start_params(const typeof(((struct_btrfs_ioctl_dev_replace_args *)0)->start) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("srcdevid"); print_dev_t((*p).srcdevid); } while (0);
 tprint_struct_next();
 do { tprints_field_name("cont_reading_from_srcdev_mode"); printxval64((btrfs_cont_reading_from_srcdev_mode), (sizeof((*p).cont_reading_from_srcdev_mode) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).cont_reading_from_srcdev_mode) : sizeof((*p).cont_reading_from_srcdev_mode) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).cont_reading_from_srcdev_mode) : sizeof((*p).cont_reading_from_srcdev_mode) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).cont_reading_from_srcdev_mode) : sizeof((*p).cont_reading_from_srcdev_mode) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).cont_reading_from_srcdev_mode) : (unsigned long long) ((*p).cont_reading_from_srcdev_mode)), ("BTRFS_IOCTL_DEV_REPLACE_CONT_READING" "_FROM_SRCDEV_MODE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("srcdev_name"); print_quoted_cstring((const char *) (*p).srcdev_name, sizeof((*p).srcdev_name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((*p).srcdev_name)), __typeof__(&((*p).srcdev_name)[0])))]) * 0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("tgtdev_name"); print_quoted_cstring((const char *) (*p).tgtdev_name, sizeof((*p).tgtdev_name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((*p).tgtdev_name)), __typeof__(&((*p).tgtdev_name)[0])))]) * 0)); } while (0);
 tprint_struct_end();
}
static void
print_btrfs_replace_status_params(const typeof(((struct_btrfs_ioctl_dev_replace_args *)0)->status) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("replace_state"); printxval64((btrfs_dev_replace_state), (sizeof((*p).replace_state) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).replace_state) : sizeof((*p).replace_state) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).replace_state) : sizeof((*p).replace_state) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).replace_state) : sizeof((*p).replace_state) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).replace_state) : (unsigned long long) ((*p).replace_state)), ("BTRFS_IOCTL_DEV_REPLACE_STATE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("progress_1000"); tprintf_string("%llu", (sizeof((*p).progress_1000) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).progress_1000) : sizeof((*p).progress_1000) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).progress_1000) : sizeof((*p).progress_1000) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).progress_1000) : sizeof((*p).progress_1000) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).progress_1000) : (unsigned long long) ((*p).progress_1000))); } while (0);
 if (p->progress_1000 <= 1000)
  tprintf_comment("%u.%u%%",
   (unsigned) p->progress_1000 / 10,
   (unsigned) p->progress_1000 % 10);
 tprint_struct_next();
 do { tprints_field_name("time_started"); tprintf_string("%llu", (sizeof((*p).time_started) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).time_started) : sizeof((*p).time_started) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).time_started) : sizeof((*p).time_started) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).time_started) : sizeof((*p).time_started) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).time_started) : (unsigned long long) ((*p).time_started))); } while (0);
 tprints_comment(sprinttime(p->time_started));
 tprint_struct_next();
 do { tprints_field_name("time_stopped"); tprintf_string("%llu", (sizeof((*p).time_stopped) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).time_stopped) : sizeof((*p).time_stopped) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).time_stopped) : sizeof((*p).time_stopped) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).time_stopped) : sizeof((*p).time_stopped) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).time_stopped) : (unsigned long long) ((*p).time_stopped))); } while (0);
 tprints_comment(sprinttime(p->time_stopped));
 tprint_struct_next();
 do { tprints_field_name("num_write_errors"); tprintf_string("%llu", (sizeof((*p).num_write_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).num_write_errors) : sizeof((*p).num_write_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).num_write_errors) : sizeof((*p).num_write_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).num_write_errors) : sizeof((*p).num_write_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).num_write_errors) : (unsigned long long) ((*p).num_write_errors))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("num_uncorrectable_read_errors"); tprintf_string("%llu", (sizeof((*p).num_uncorrectable_read_errors) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).num_uncorrectable_read_errors) : sizeof((*p).num_uncorrectable_read_errors) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).num_uncorrectable_read_errors) : sizeof((*p).num_uncorrectable_read_errors) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).num_uncorrectable_read_errors) : sizeof((*p).num_uncorrectable_read_errors) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).num_uncorrectable_read_errors) : (unsigned long long) ((*p).num_uncorrectable_read_errors))); } while (0);
 tprint_struct_end();
}
MPERS_PRINTER_DECL(int, btrfs_ioctl, struct tcb *const tcp, const unsigned int code, const kernel_ulong_t arg)
{
 switch (code) {
 case (((0U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((6)) << 0) | ((0) << ((0 +8)+8))):
 case (((0U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((7)) << 0) | ((0) << ((0 +8)+8))):
 case (((0U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((8)) << 0) | ((0) << ((0 +8)+8))):
 case (((0U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((28)) << 0) | ((0) << ((0 +8)+8))):
 case (((0U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((46)) << 0) | ((0) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((2)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((12)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
  break;
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((33)) << 0) | ((((sizeof(int)))) << ((0 +8)+8))):
  tprint_arg_next();
  printxval(btrfs_balance_ctl_cmds, arg, "BTRFS_BALANCE_CTL_???");
  break;
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((24)) << 0) | ((((sizeof(__u64)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04)))
   return 0;
 __attribute__((__fallthrough__));
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((19)) << 0) | ((((sizeof(__u64)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((22)) << 0) | ((((sizeof(__u64)))) << ((0 +8)+8))):
  tprint_arg_next();
  printnum_int64(tcp, arg, "%" "l" "u");
  break;
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((25)) << 0) | ((((sizeof(__u64)))) << ((0 +8)+8))): {
  uint64_t flags;
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&flags)), (void *) (&flags)))
   break;
  printflags64(btrfs_snap_flags_v2, flags, "BTRFS_SUBVOL_???");
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((26)) << 0) | ((((sizeof(__u64)))) << ((0 +8)+8))): {
  uint64_t flags;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&flags)), (void *) (&flags)))
   break;
  printflags64(btrfs_snap_flags_v2, flags, "BTRFS_SUBVOL_???");
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((32)) << 0) | ((((sizeof(struct btrfs_ioctl_balance_args)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04))) {
   tprint_arg_next();
   btrfs_print_balance(tcp, arg, 0);
   return 0;
  }
  if (((tcp)->u_error != 0))
   break;
  tprint_value_changed();
  btrfs_print_balance(tcp, arg, 1);
  break;
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((34)) << 0) | ((((sizeof(struct btrfs_ioctl_balance_args)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  btrfs_print_balance(tcp, arg, 1);
  break;
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((16)) << 0) | ((((sizeof(struct btrfs_ioctl_defrag_range_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_defrag_range_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("start"); tprintf_string("%llu", (sizeof((args).start) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).start) : sizeof((args).start) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).start) : sizeof((args).start) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).start) : sizeof((args).start) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).start) : (unsigned long long) ((args).start))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("len"); if ((sizeof((args).len) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).len) : sizeof((args).len) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).len) : sizeof((args).len) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).len) : sizeof((args).len) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).len) : (unsigned long long) ((args).len)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((args).len) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).len) : sizeof((args).len) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).len) : sizeof((args).len) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).len) : sizeof((args).len) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).len) : (unsigned long long) ((args).len))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((btrfs_defrag_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_DEFRAG_RANGE_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("extent_thresh"); tprintf_string("%llu", (sizeof((args).extent_thresh) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).extent_thresh) : sizeof((args).extent_thresh) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).extent_thresh) : sizeof((args).extent_thresh) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).extent_thresh) : sizeof((args).extent_thresh) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).extent_thresh) : (unsigned long long) ((args).extent_thresh))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("compress_type"); printxval64((btrfs_compress_types), (sizeof((args).compress_type) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).compress_type) : sizeof((args).compress_type) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).compress_type) : sizeof((args).compress_type) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).compress_type) : sizeof((args).compress_type) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).compress_type) : (unsigned long long) ((args).compress_type)), ("BTRFS_COMPRESS_???")); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((30)) << 0) | ((((sizeof(struct btrfs_ioctl_dev_info_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_dev_info_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("devid"); print_dev_t((args).devid); } while (0);
   if (!is_filled((const char *) (args.uuid), 0, sizeof(args.uuid) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((args.uuid)), __typeof__(&(args.uuid)[0])))]) * 0))) {
    tprint_struct_next();
    do { tprints_field_name("uuid"); print_uuid((const unsigned char *) ((args).uuid)); } while (0);
   }
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  if (!is_filled((const char *) (args.uuid), 0, sizeof(args.uuid) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((args.uuid)), __typeof__(&(args.uuid)[0])))]) * 0))) {
   do { tprints_field_name("uuid"); print_uuid((const unsigned char *) ((args).uuid)); } while (0);
   tprint_struct_next();
  }
  do { tprints_field_name("bytes_used"); tprintf_string("%llu", (sizeof((args).bytes_used) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).bytes_used) : sizeof((args).bytes_used) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).bytes_used) : sizeof((args).bytes_used) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).bytes_used) : sizeof((args).bytes_used) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).bytes_used) : (unsigned long long) ((args).bytes_used))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("total_bytes"); tprintf_string("%llu", (sizeof((args).total_bytes) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).total_bytes) : sizeof((args).total_bytes) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).total_bytes) : sizeof((args).total_bytes) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).total_bytes) : sizeof((args).total_bytes) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).total_bytes) : (unsigned long long) ((args).total_bytes))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("path"); print_quoted_cstring((const char *) (args).path, sizeof((args).path) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((args).path)), __typeof__(&((args).path)[0])))]) * 0)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((53)) << 0) | ((((sizeof(struct btrfs_ioctl_dev_replace_args)))) << ((0 +8)+8))): {
  struct_btrfs_ioctl_dev_replace_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("cmd"); printxval64((btrfs_dev_replace_cmds), (sizeof((args).cmd) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).cmd) : sizeof((args).cmd) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).cmd) : sizeof((args).cmd) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).cmd) : sizeof((args).cmd) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).cmd) : (unsigned long long) ((args).cmd)), ("BTRFS_IOCTL_DEV_REPLACE_CMD_???")); } while (0);
   if (args.cmd == 0) {
    tprint_struct_next();
    do { tprints_field_name("start"); (print_btrfs_replace_start_params)(&((args).start)); } while (0);
   }
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("result"); printxval64((btrfs_dev_replace_results), (sizeof((args).result) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).result) : sizeof((args).result) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).result) : sizeof((args).result) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).result) : sizeof((args).result) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).result) : (unsigned long long) ((args).result)), ("BTRFS_IOCTL_DEV_REPLACE_RESULT_???")); } while (0);
  if (args.cmd == 1) {
   tprint_struct_next();
   do { tprints_field_name("status"); (print_btrfs_replace_status_params)(&((args).status)); } while (0);
  }
  tprint_struct_end();
  break;
 }
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((57)) << 0) | ((((sizeof(struct btrfs_ioctl_feature_flags)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_feature_flags flags;
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&flags)), (void *) (&flags)))
   break;
  btrfs_print_features(&flags);
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((57)) << 0) | ((((sizeof(struct btrfs_ioctl_feature_flags[2])))) << ((0 +8)+8))): {
  struct btrfs_ioctl_feature_flags flarg[2];
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&flarg)), (void *) (&flarg)))
   break;
  tprint_array_begin();
  btrfs_print_features(&flarg[0]);
  tprint_array_next();
  btrfs_print_features(&flarg[1]);
  tprint_array_end();
  break;
 }
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((57)) << 0) | ((((sizeof(struct btrfs_ioctl_feature_flags[3])))) << ((0 +8)+8))): {
  struct btrfs_ioctl_feature_flags flarg[3];
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&flarg)), (void *) (&flarg)))
   break;
  tprint_array_begin();
  btrfs_print_features(&flarg[0]);
  tprints_comment("supported");
  tprint_array_next();
  btrfs_print_features(&flarg[1]);
  tprints_comment("safe to set");
  tprint_array_next();
  btrfs_print_features(&flarg[2]);
  tprints_comment("safe to clear");
  tprint_array_end();
  break;
 }
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((31)) << 0) | ((((sizeof(struct btrfs_ioctl_fs_info_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_fs_info_args args;
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("max_id"); tprintf_string("%llu", (sizeof((args).max_id) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).max_id) : sizeof((args).max_id) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).max_id) : sizeof((args).max_id) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).max_id) : sizeof((args).max_id) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).max_id) : (unsigned long long) ((args).max_id))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("num_devices"); tprintf_string("%llu", (sizeof((args).num_devices) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).num_devices) : sizeof((args).num_devices) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).num_devices) : sizeof((args).num_devices) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).num_devices) : sizeof((args).num_devices) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).num_devices) : (unsigned long long) ((args).num_devices))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("fsid"); print_uuid((const unsigned char *) ((args).fsid)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("nodesize"); tprintf_string("%llu", (sizeof((args).nodesize) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).nodesize) : sizeof((args).nodesize) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).nodesize) : sizeof((args).nodesize) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).nodesize) : sizeof((args).nodesize) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).nodesize) : (unsigned long long) ((args).nodesize))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("sectorsize"); tprintf_string("%llu", (sizeof((args).sectorsize) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).sectorsize) : sizeof((args).sectorsize) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).sectorsize) : sizeof((args).sectorsize) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).sectorsize) : sizeof((args).sectorsize) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).sectorsize) : (unsigned long long) ((args).sectorsize))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("clone_alignment"); tprintf_string("%llu", (sizeof((args).clone_alignment) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).clone_alignment) : sizeof((args).clone_alignment) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).clone_alignment) : sizeof((args).clone_alignment) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).clone_alignment) : sizeof((args).clone_alignment) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).clone_alignment) : (unsigned long long) ((args).clone_alignment))); } while (0);
  if (args.flags & (1 << 0)) {
   tprint_struct_next();
   do { tprints_field_name("csum_type"); printxval64((btrfs_csum_types), (sizeof((args).csum_type) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).csum_type) : sizeof((args).csum_type) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).csum_type) : sizeof((args).csum_type) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).csum_type) : sizeof((args).csum_type) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).csum_type) : (unsigned long long) ((args).csum_type)), ("BTRFS_CSUM_TYPE_???")); } while (0);
   tprint_struct_next();
   do { tprints_field_name("csum_size"); tprintf_string("%llu", (sizeof((args).csum_size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).csum_size) : sizeof((args).csum_size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).csum_size) : sizeof((args).csum_size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).csum_size) : sizeof((args).csum_size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).csum_size) : (unsigned long long) ((args).csum_size))); } while (0);
  }
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((btrfs_fs_info_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_FS_INFO_FLAG_???")); } while (0);
  if (args.flags & (1 << 1)) {
   tprint_struct_next();
   do { tprints_field_name("generation"); tprintf_string("%llu", (sizeof((args).generation) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).generation) : sizeof((args).generation) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).generation) : sizeof((args).generation) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).generation) : sizeof((args).generation) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).generation) : (unsigned long long) ((args).generation))); } while (0);
  }
  if (args.flags & (1 << 2)) {
   tprint_struct_next();
   do { tprints_field_name("metadata_uuid"); print_uuid((const unsigned char *) ((args).metadata_uuid)); } while (0);
  }
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((52)) << 0) | ((((sizeof(struct btrfs_ioctl_get_dev_stats)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_get_dev_stats args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  if ((!((tcp)->flags & 0x04))) {
   do { tprints_field_name("devid"); print_dev_t((args).devid); } while (0);
   tprint_struct_next();
  }
  do { tprints_field_name("nr_items"); tprintf_string("%llu", (sizeof((args).nr_items) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).nr_items) : sizeof((args).nr_items) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).nr_items) : sizeof((args).nr_items) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).nr_items) : sizeof((args).nr_items) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).nr_items) : (unsigned long long) ((args).nr_items))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((btrfs_dev_stats_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_DEV_STATS_???")); } while (0);
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_end();
   return 0;
  }
  tprint_struct_next();
  tprint_array_begin();
  for (uint64_t i = 0; i < args.nr_items; ++i) {
   if (i)
    tprint_array_next();
   if (i >= (sizeof(args.values) / sizeof((args.values)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((args.values)), __typeof__(&(args.values)[0])))]) * 0))) {
    tprint_more_data_follows();
    break;
   }
   tprint_array_index_begin();
   printxval_u(btrfs_dev_stats_values, i, ((void *)0));
   tprint_array_index_equal();
   tprintf_string("%llu", (sizeof(args.values[i]) == sizeof(char) ? (unsigned long long) (unsigned char) (args.values[i]) : sizeof(args.values[i]) == sizeof(short) ? (unsigned long long) (unsigned short) (args.values[i]) : sizeof(args.values[i]) == sizeof(int) ? (unsigned long long) (unsigned int) (args.values[i]) : sizeof(args.values[i]) == sizeof(long) ? (unsigned long long) (unsigned long) (args.values[i]) : (unsigned long long) (args.values[i])));
   tprint_array_index_end();
  }
  tprint_array_end();
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((18)) << 0) | ((((sizeof(struct btrfs_ioctl_ino_lookup_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_ino_lookup_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   if (args.treeid == 0)
    set_tcb_priv_ulong(tcp, 1);
   tprint_struct_begin();
   do { tprints_field_name("treeid"); printxval64_u((btrfs_tree_objectids), (sizeof(((args)).treeid) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).treeid) : (unsigned long long) (((args)).treeid)), (((void *)0))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("objectid"); printxval64_u((btrfs_tree_objectids), (sizeof(((args)).objectid) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).objectid) : sizeof(((args)).objectid) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).objectid) : sizeof(((args)).objectid) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).objectid) : sizeof(((args)).objectid) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).objectid) : (unsigned long long) (((args)).objectid)), (((void *)0))); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  if (get_tcb_priv_ulong(tcp)) {
   do { tprints_field_name("treeid"); printxval64_u((btrfs_tree_objectids), (sizeof(((args)).treeid) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).treeid) : sizeof(((args)).treeid) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).treeid) : (unsigned long long) (((args)).treeid)), (((void *)0))); } while (0);
   tprint_struct_next();
  }
  do { tprints_field_name("name"); print_quoted_cstring((const char *) (args).name, sizeof((args).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((args).name)), __typeof__(&((args).name)[0])))]) * 0)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((35)) << 0) | ((((sizeof(struct btrfs_ioctl_ino_path_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_ino_path_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("inum"); tprintf_string("%llu", (sizeof((args).inum) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).inum) : sizeof((args).inum) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).inum) : sizeof((args).inum) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).inum) : sizeof((args).inum) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).inum) : (unsigned long long) ((args).inum))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("size"); tprintf_string("%llu", (sizeof((args).size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).size) : sizeof((args).size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).size) : sizeof((args).size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).size) : sizeof((args).size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).size) : (unsigned long long) ((args).size))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("fspath"); printaddr64((args).fspath); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("fspath"); (btrfs_print_ino_path_container)((tcp), (args).fspath); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((36)) << 0) | ((((sizeof(struct btrfs_ioctl_logical_ino_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_logical_ino_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("logical"); tprintf_string("%llu", (sizeof((args).logical) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).logical) : sizeof((args).logical) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).logical) : sizeof((args).logical) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).logical) : sizeof((args).logical) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).logical) : (unsigned long long) ((args).logical))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("size"); tprintf_string("%llu", (sizeof((args).size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).size) : sizeof((args).size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).size) : sizeof((args).size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).size) : sizeof((args).size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).size) : (unsigned long long) ((args).size))); } while (0);
   if (!is_filled((const char *) (args.reserved), 0, sizeof(args.reserved) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((args.reserved)), __typeof__(&(args.reserved)[0])))]) * 0))) {
    tprint_struct_next();
    do { tprints_field_name("reserved"); for (size_t i_ = 0; i_ < (sizeof(((args)).reserved) / sizeof((((args)).reserved)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((((args)).reserved)), __typeof__(&(((args)).reserved)[0])))]) * 0)); ++i_) { if (i_) tprint_array_next(); else tprint_array_begin(); tprintf_string("%#llx", (sizeof(((args)).reserved[i_]) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).reserved[i_]) : sizeof(((args)).reserved[i_]) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).reserved[i_]) : sizeof(((args)).reserved[i_]) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).reserved[i_]) : sizeof(((args)).reserved[i_]) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).reserved[i_]) : (unsigned long long) (((args)).reserved[i_]))); } tprint_array_end(); } while (0);
   }
   tprint_struct_next();
   do { tprints_field_name("flags"); printflags64((btrfs_logical_ino_args_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_LOGICAL_INO_ARGS_???")); } while (0);
   tprint_struct_next();
   do { tprints_field_name("inodes"); printaddr64((args).inodes); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("inodes"); (btrfs_print_logical_ino_container)((tcp), (args).inodes); } while (0);
  tprint_struct_end();
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((41)) << 0) | ((((sizeof(struct btrfs_ioctl_qgroup_assign_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_qgroup_assign_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("assign"); tprintf_string("%llu", (sizeof((args).assign) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).assign) : sizeof((args).assign) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).assign) : sizeof((args).assign) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).assign) : sizeof((args).assign) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).assign) : (unsigned long long) ((args).assign))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("src"); tprintf_string("%llu", (sizeof((args).src) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).src) : sizeof((args).src) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).src) : sizeof((args).src) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).src) : sizeof((args).src) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).src) : (unsigned long long) ((args).src))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("dst"); tprintf_string("%llu", (sizeof((args).dst) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).dst) : sizeof((args).dst) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).dst) : sizeof((args).dst) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).dst) : sizeof((args).dst) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).dst) : (unsigned long long) ((args).dst))); } while (0);
  tprint_struct_end();
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((42)) << 0) | ((((sizeof(struct btrfs_ioctl_qgroup_create_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_qgroup_create_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("create"); tprintf_string("%llu", (sizeof((args).create) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).create) : sizeof((args).create) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).create) : sizeof((args).create) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).create) : sizeof((args).create) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).create) : (unsigned long long) ((args).create))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("qgroupid"); tprintf_string("%llu", (sizeof((args).qgroupid) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).qgroupid) : (unsigned long long) ((args).qgroupid))); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((43)) << 0) | ((((sizeof(struct btrfs_ioctl_qgroup_limit_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_qgroup_limit_args args;
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("qgroupid"); tprintf_string("%llu", (sizeof((args).qgroupid) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).qgroupid) : sizeof((args).qgroupid) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).qgroupid) : (unsigned long long) ((args).qgroupid))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("lim"); (btrfs_print_qgroup_limit)(&((args).lim)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((40)) << 0) | ((((sizeof(struct btrfs_ioctl_quota_ctl_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_quota_ctl_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("cmd"); printxval64((btrfs_qgroup_ctl_cmds), (sizeof((args).cmd) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).cmd) : sizeof((args).cmd) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).cmd) : sizeof((args).cmd) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).cmd) : sizeof((args).cmd) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).cmd) : (unsigned long long) ((args).cmd)), ("BTRFS_QUOTA_CTL_???")); } while (0);
  tprint_struct_end();
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((44)) << 0) | ((((sizeof(struct btrfs_ioctl_quota_rescan_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_quota_rescan_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("flags"); tprintf_string("%llu", (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags))); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((45)) << 0) | ((((sizeof(struct btrfs_ioctl_quota_rescan_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_quota_rescan_args args;
  if ((!((tcp)->flags & 0x04)))
   return 0;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("flags"); tprintf_string("%llu", (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("progress"); printxval64_u((btrfs_tree_objectids), (sizeof(((args)).progress) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).progress) : sizeof(((args)).progress) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).progress) : sizeof(((args)).progress) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).progress) : sizeof(((args)).progress) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).progress) : (unsigned long long) (((args)).progress)), (((void *)0))); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((37)) << 0) | ((((sizeof(struct btrfs_ioctl_received_subvol_args)))) << ((0 +8)+8))): {
  struct_btrfs_ioctl_received_subvol_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("uuid"); print_uuid((const unsigned char *) ((args).uuid)); } while (0);
   tprint_struct_next();
   do { tprints_field_name("stransid"); tprintf_string("%llu", (sizeof((args).stransid) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).stransid) : sizeof((args).stransid) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).stransid) : sizeof((args).stransid) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).stransid) : sizeof((args).stransid) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).stransid) : (unsigned long long) ((args).stransid))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("stime"); (print_btrfs_timespec)(&((args).stime)); } while (0);
   tprint_struct_next();
   do { tprints_field_name("flags"); tprintf_string("%llu", (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags))); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("rtransid"); tprintf_string("%llu", (sizeof((args).rtransid) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).rtransid) : sizeof((args).rtransid) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).rtransid) : sizeof((args).rtransid) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).rtransid) : sizeof((args).rtransid) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).rtransid) : (unsigned long long) ((args).rtransid))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("rtime"); (print_btrfs_timespec)(&((args).rtime)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((27)) << 0) | ((((sizeof(struct btrfs_ioctl_scrub_args)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((29)) << 0) | ((((sizeof(struct btrfs_ioctl_scrub_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_scrub_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("devid"); print_dev_t((args).devid); } while (0);
   if (code == (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((27)) << 0) | ((((sizeof(struct btrfs_ioctl_scrub_args)))) << ((0 +8)+8)))) {
    tprint_struct_next();
    do { tprints_field_name("start"); tprintf_string("%llu", (sizeof((args).start) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).start) : sizeof((args).start) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).start) : sizeof((args).start) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).start) : sizeof((args).start) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).start) : (unsigned long long) ((args).start))); } while (0);
    tprint_struct_next();
    do { tprints_field_name("end"); if ((sizeof((args).end) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).end) : sizeof((args).end) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).end) : sizeof((args).end) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).end) : sizeof((args).end) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).end) : (unsigned long long) ((args).end)) == (18446744073709551615UL)) print_xlat_ex(((18446744073709551615UL)), "UINT64_MAX", XLAT_STYLE_FMT_U); else tprintf_string("%llu", (sizeof((args).end) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).end) : sizeof((args).end) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).end) : sizeof((args).end) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).end) : sizeof((args).end) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).end) : (unsigned long long) ((args).end))); } while (0);
    tprint_struct_next();
    do { tprints_field_name("flags"); printflags64((btrfs_scrub_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_SCRUB_???")); } while (0);
   }
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("progress"); (print_btrfs_scrub_progress)(&((args).progress)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((17)) << 0) | ((((sizeof(struct btrfs_ioctl_search_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_search_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args.key)), (void *) (&args.key)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("key"); (print_btrfs_ioctl_search_key)(&((args).key), (!((tcp)->flags & 0x04)), !((tcp)->qual_flg & 0x002)); } while (0);
  decode_search_arg_buf(tcp, arg + __builtin_offsetof (typeof(args), buf),
          sizeof(args.buf), args.key.nr_items);
  tprint_struct_end();
  if ((!((tcp)->flags & 0x04)))
   return 0;
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((17)) << 0) | ((((sizeof(struct btrfs_ioctl_search_args_v2)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_search_args_v2 args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0)) {
   if (tcp->u_error == 75) {
    tprint_value_changed();
    if (!umoven_or_printaddr_ignore_syserror((tcp), (arg), sizeof(*(&args)), (void *) (&args))) {
     tprint_struct_begin();
     do { tprints_field_name("buf_size"); tprintf_string("%llu", (sizeof((args).buf_size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).buf_size) : sizeof((args).buf_size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).buf_size) : sizeof((args).buf_size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).buf_size) : sizeof((args).buf_size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).buf_size) : (unsigned long long) ((args).buf_size))); } while (0);
     tprint_struct_end();
    }
   }
   break;
  } else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("key"); (print_btrfs_ioctl_search_key)(&((args).key), (!((tcp)->flags & 0x04)), !((tcp)->qual_flg & 0x002)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("buf_size"); tprintf_string("%llu", (sizeof((args).buf_size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).buf_size) : sizeof((args).buf_size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).buf_size) : sizeof((args).buf_size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).buf_size) : sizeof((args).buf_size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).buf_size) : (unsigned long long) ((args).buf_size))); } while (0);
  decode_search_arg_buf(tcp, arg + __builtin_offsetof (typeof(args), buf),
          args.buf_size, args.key.nr_items);
  tprint_struct_end();
  if ((!((tcp)->flags & 0x04)))
   return 0;
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((38)) << 0) | ((((sizeof(struct btrfs_ioctl_send_args)))) << ((0 +8)+8))): {
  struct_btrfs_ioctl_send_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("send_fd"); printfd((tcp), (args).send_fd); } while (0);
  tprint_struct_next();
  do { tprints_field_name("clone_sources_count"); tprintf_string("%llu", (sizeof((args).clone_sources_count) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).clone_sources_count) : sizeof((args).clone_sources_count) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).clone_sources_count) : sizeof((args).clone_sources_count) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).clone_sources_count) : sizeof((args).clone_sources_count) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).clone_sources_count) : (unsigned long long) ((args).clone_sources_count))); } while (0);
  if (((tcp)->qual_flg & 0x002)) {
   tprint_struct_next();
   do { tprints_field_name("clone_sources"); printaddr((mpers_ptr_t) (args).clone_sources); } while (0);
  } else {
   tprint_struct_next();
   tprints_field_name("clone_sources");
   uint64_t record;
   print_array(tcp, ((kernel_ulong_t) (unsigned long) (args.clone_sources)),
        args.clone_sources_count,
        &record, sizeof(record),
        tfetch_mem,
        print_objectid_callback, 0);
  }
  tprint_struct_next();
  do { tprints_field_name("parent_root"); printxval64_u((btrfs_tree_objectids), (sizeof(((args)).parent_root) == sizeof(char) ? (unsigned long long) (unsigned char) (((args)).parent_root) : sizeof(((args)).parent_root) == sizeof(short) ? (unsigned long long) (unsigned short) (((args)).parent_root) : sizeof(((args)).parent_root) == sizeof(int) ? (unsigned long long) (unsigned int) (((args)).parent_root) : sizeof(((args)).parent_root) == sizeof(long) ? (unsigned long long) (unsigned long) (((args)).parent_root) : (unsigned long long) (((args)).parent_root)), (((void *)0))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((btrfs_send_flags), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_SEND_FLAGS_???")); } while (0);
  tprint_struct_end();
  break;
 }
 case (((2U|1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((20)) << 0) | ((((sizeof(struct btrfs_ioctl_space_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_space_args args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("space_slots"); tprintf_string("%llu", (sizeof((args).space_slots) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).space_slots) : sizeof((args).space_slots) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).space_slots) : sizeof((args).space_slots) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).space_slots) : sizeof((args).space_slots) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).space_slots) : (unsigned long long) ((args).space_slots))); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("total_spaces"); tprintf_string("%llu", (sizeof((args).total_spaces) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).total_spaces) : sizeof((args).total_spaces) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).total_spaces) : sizeof((args).total_spaces) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).total_spaces) : sizeof((args).total_spaces) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).total_spaces) : (unsigned long long) ((args).total_spaces))); } while (0);
  if (args.space_slots == 0 && args.total_spaces) {
   tprint_struct_end();
   break;
  }
  if (((tcp)->qual_flg & 0x002)) {
   tprint_struct_next();
   tprint_more_data_follows();
  } else {
   struct btrfs_ioctl_space_info info;
   tprint_struct_next();
   tprints_field_name("spaces");
   print_array(tcp, arg + __builtin_offsetof (typeof(args), spaces),
        args.total_spaces,
        &info, sizeof(info), tfetch_mem,
        print_btrfs_ioctl_space_info, 0);
  }
  tprint_struct_end();
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((1)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((3)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((4)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((5)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((10)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((11)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((14)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((15)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))):
 case (((2U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((39)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args)))) << ((0 +8)+8))): {
  struct btrfs_ioctl_vol_args args;
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  tprint_struct_begin();
  do { tprints_field_name("fd"); printfd((tcp), (args).fd); } while (0);
  tprint_struct_next();
  do { tprints_field_name("name"); print_quoted_cstring((const char *) (args).name, sizeof((args).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((args).name)), __typeof__(&((args).name)[0])))]) * 0)); } while (0);
  tprint_struct_end();
  break;
 }
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((23)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args_v2)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | (((0x94)) << (0 +8)) | (((24)) << 0) | ((((sizeof(struct btrfs_ioctl_vol_args_v2)))) << ((0 +8)+8))): {
  struct_btrfs_ioctl_vol_args_v2 args;
  if ((!((tcp)->flags & 0x04)))
   tprint_arg_next();
  else if (((tcp)->u_error != 0))
   break;
  else
   tprint_value_changed();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&args)), (void *) (&args)))
   break;
  if ((!((tcp)->flags & 0x04))) {
   tprint_struct_begin();
   do { tprints_field_name("fd"); printfd((tcp), (args).fd); } while (0);
   tprint_struct_next();
   do { tprints_field_name("flags"); printflags64((btrfs_snap_flags_v2), (sizeof((args).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).flags) : sizeof((args).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).flags) : sizeof((args).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).flags) : sizeof((args).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).flags) : (unsigned long long) ((args).flags)), ("BTRFS_SUBVOL_???")); } while (0);
   if (args.flags & (1ULL << 2)) {
    tprint_struct_next();
    do { tprints_field_name("size"); tprintf_string("%llu", (sizeof((args).size) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).size) : sizeof((args).size) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).size) : sizeof((args).size) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).size) : sizeof((args).size) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).size) : (unsigned long long) ((args).size))); } while (0);
    tprint_struct_next();
    tprints_field_name("qgroup_inherit");
    btrfs_print_qgroup_inherit(tcp,
     ((kernel_ulong_t) (unsigned long) (args.qgroup_inherit)));
   }
   tprint_struct_next();
   do { tprints_field_name("name"); print_quoted_cstring((const char *) (args).name, sizeof((args).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((args).name)), __typeof__(&((args).name)[0])))]) * 0)); } while (0);
   tprint_struct_end();
   return 0;
  }
  tprint_struct_begin();
  do { tprints_field_name("transid"); tprintf_string("%llu", (sizeof((args).transid) == sizeof(char) ? (unsigned long long) (unsigned char) ((args).transid) : sizeof((args).transid) == sizeof(short) ? (unsigned long long) (unsigned short) ((args).transid) : sizeof((args).transid) == sizeof(int) ? (unsigned long long) (unsigned int) ((args).transid) : sizeof((args).transid) == sizeof(long) ? (unsigned long long) (unsigned long) ((args).transid) : (unsigned long long) ((args).transid))); } while (0);
  tprint_struct_end();
  break;
 }
 default:
  return 0100;
 };
 return 0200;
}

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

typedef __sig_atomic_t sig_atomic_t;
union sigval
{
  int sival_int;
  void *sival_ptr;
};
typedef union sigval __sigval_t;
typedef struct
  {
    int si_signo;
    int si_errno;
    int si_code;
    int __pad0;
    union
      {
 int _pad[((128 / sizeof (int)) - 4)];
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
   } _kill;
 struct
   {
     int si_tid;
     int si_overrun;
     __sigval_t si_sigval;
   } _timer;
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
     __sigval_t si_sigval;
   } _rt;
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
     int si_status;
     __clock_t si_utime;
     __clock_t si_stime;
   } _sigchld;
 struct
   {
     void *si_addr;
    
     short int si_addr_lsb;
     union
       {
  struct
    {
      void *_lower;
      void *_upper;
    } _addr_bnd;
  __uint32_t _pkey;
       } _bounds;
   } _sigfault;
 struct
   {
     long int si_band;
     int si_fd;
   } _sigpoll;
 struct
   {
     void *_call_addr;
     int _syscall;
     unsigned int _arch;
   } _sigsys;
      } _sifields;
  } siginfo_t ;
enum
{
  SI_ASYNCNL = -60,
  SI_DETHREAD = -7,
  SI_TKILL,
  SI_SIGIO,
  SI_ASYNCIO,
  SI_MESGQ,
  SI_TIMER,
  SI_QUEUE,
  SI_USER,
  SI_KERNEL = 0x80
};
enum
{
  ILL_ILLOPC = 1,
  ILL_ILLOPN,
  ILL_ILLADR,
  ILL_ILLTRP,
  ILL_PRVOPC,
  ILL_PRVREG,
  ILL_COPROC,
  ILL_BADSTK,
  ILL_BADIADDR
};
enum
{
  FPE_INTDIV = 1,
  FPE_INTOVF,
  FPE_FLTDIV,
  FPE_FLTOVF,
  FPE_FLTUND,
  FPE_FLTRES,
  FPE_FLTINV,
  FPE_FLTSUB,
  FPE_FLTUNK = 14,
  FPE_CONDTRAP
};
enum
{
  SEGV_MAPERR = 1,
  SEGV_ACCERR,
  SEGV_BNDERR,
  SEGV_PKUERR,
  SEGV_ACCADI,
  SEGV_ADIDERR,
  SEGV_ADIPERR
};
enum
{
  BUS_ADRALN = 1,
  BUS_ADRERR,
  BUS_OBJERR,
  BUS_MCEERR_AR,
  BUS_MCEERR_AO
};
enum
{
  TRAP_BRKPT = 1,
  TRAP_TRACE,
  TRAP_BRANCH,
  TRAP_HWBKPT,
  TRAP_UNK
};
enum
{
  CLD_EXITED = 1,
  CLD_KILLED,
  CLD_DUMPED,
  CLD_TRAPPED,
  CLD_STOPPED,
  CLD_CONTINUED
};
enum
{
  POLL_IN = 1,
  POLL_OUT,
  POLL_MSG,
  POLL_ERR,
  POLL_PRI,
  POLL_HUP
};
typedef __sigval_t sigval_t;
typedef struct sigevent
  {
    __sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;
    union
      {
 int _pad[((64 / sizeof (int)) - 4)];
 __pid_t _tid;
 struct
   {
     void (*_function) (__sigval_t);
     pthread_attr_t *_attribute;
   } _sigev_thread;
      } _sigev_un;
  } sigevent_t;
enum
{
  SIGEV_SIGNAL = 0,
  SIGEV_NONE,
  SIGEV_THREAD,
  SIGEV_THREAD_ID = 4
};
typedef void (*__sighandler_t) (int);
extern __sighandler_t __sysv_signal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));
extern __sighandler_t sysv_signal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));
extern __sighandler_t signal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));
extern int kill (__pid_t __pid, int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern int killpg (__pid_t __pgrp, int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern int raise (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern __sighandler_t ssignal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));
extern int gsignal (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern void psignal (int __sig, const char *__s);
extern void psiginfo (const siginfo_t *__pinfo, const char *__s);
extern int sigpause (int __sig) __asm__ ("__xpg_sigpause");
extern int sigblock (int __mask) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int sigsetmask (int __mask) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int siggetmask (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
typedef __sighandler_t sighandler_t;
typedef __sighandler_t sig_t;
extern int sigemptyset (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigfillset (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigaddset (sigset_t *__set, int __signo) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigdelset (sigset_t *__set, int __signo) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigismember (const sigset_t *__set, int __signo)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigisemptyset (const sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigandset (sigset_t *__set, const sigset_t *__left,
        const sigset_t *__right) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2, 3)));
extern int sigorset (sigset_t *__set, const sigset_t *__left,
       const sigset_t *__right) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2, 3)));
struct sigaction
  {
    union
      {
 __sighandler_t sa_handler;
 void (*sa_sigaction) (int, siginfo_t *, void *);
      }
    __sigaction_handler;
    __sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer) (void);
  };
extern int sigprocmask (int __how, const sigset_t *__restrict __set,
   sigset_t *__restrict __oset) __attribute__ ((__nothrow__ , __leaf__));
extern int sigsuspend (const sigset_t *__set) __attribute__ ((__nonnull__ (1)));
extern int sigaction (int __sig, const struct sigaction *__restrict __act,
        struct sigaction *__restrict __oact) __attribute__ ((__nothrow__ , __leaf__));
extern int sigpending (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigwait (const sigset_t *__restrict __set, int *__restrict __sig)
     __attribute__ ((__nonnull__ (1, 2)));
extern int sigwaitinfo (const sigset_t *__restrict __set,
   siginfo_t *__restrict __info) __attribute__ ((__nonnull__ (1)));
extern int sigtimedwait (const sigset_t *__restrict __set,
    siginfo_t *__restrict __info,
    const struct timespec *__restrict __timeout)
     __attribute__ ((__nonnull__ (1)));
extern int sigqueue (__pid_t __pid, int __sig, const union sigval __val)
     __attribute__ ((__nothrow__ , __leaf__));
extern const char *const _sys_siglist[(64 + 1)];
extern const char *const sys_siglist[(64 + 1)];
struct _fpx_sw_bytes
{
  __uint32_t magic1;
  __uint32_t extended_size;
  __uint64_t xstate_bv;
  __uint32_t xstate_size;
  __uint32_t __glibc_reserved1[7];
};
struct _fpreg
{
  unsigned short significand[4];
  unsigned short exponent;
};
struct _fpxreg
{
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short __glibc_reserved1[3];
};
struct _xmmreg
{
  __uint32_t element[4];
};
struct _fpstate
{
  __uint16_t cwd;
  __uint16_t swd;
  __uint16_t ftw;
  __uint16_t fop;
  __uint64_t rip;
  __uint64_t rdp;
  __uint32_t mxcsr;
  __uint32_t mxcr_mask;
  struct _fpxreg _st[8];
  struct _xmmreg _xmm[16];
  __uint32_t __glibc_reserved1[24];
};
struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
struct _xsave_hdr
{
  __uint64_t xstate_bv;
  __uint64_t __glibc_reserved1[2];
  __uint64_t __glibc_reserved2[5];
};
struct _ymmh_state
{
  __uint32_t ymmh_space[64];
};
struct _xstate
{
  struct _fpstate fpstate;
  struct _xsave_hdr xstate_hdr;
  struct _ymmh_state ymmh;
};
extern int sigreturn (struct sigcontext *__scp) __attribute__ ((__nothrow__ , __leaf__));
typedef struct
  {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
  } stack_t;
__extension__ typedef long long int greg_t;
typedef greg_t gregset_t[23];
enum
{
  REG_R8 = 0,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
  REG_RDI,
  REG_RSI,
  REG_RBP,
  REG_RBX,
  REG_RDX,
  REG_RAX,
  REG_RCX,
  REG_RSP,
  REG_RIP,
  REG_EFL,
  REG_CSGSFS,
  REG_ERR,
  REG_TRAPNO,
  REG_OLDMASK,
  REG_CR2
};
struct _libc_fpxreg
{
  unsigned short int significand[4];
  unsigned short int exponent;
  unsigned short int __glibc_reserved1[3];
};
struct _libc_xmmreg
{
  __uint32_t element[4];
};
struct _libc_fpstate
{
  __uint16_t cwd;
  __uint16_t swd;
  __uint16_t ftw;
  __uint16_t fop;
  __uint64_t rip;
  __uint64_t rdp;
  __uint32_t mxcsr;
  __uint32_t mxcr_mask;
  struct _libc_fpxreg _st[8];
  struct _libc_xmmreg _xmm[16];
  __uint32_t __glibc_reserved1[24];
};
typedef struct _libc_fpstate *fpregset_t;
typedef struct
  {
    gregset_t gregs;
    fpregset_t fpregs;
    __extension__ unsigned long long __reserved1 [8];
} mcontext_t;
typedef struct ucontext_t
  {
    unsigned long int uc_flags;
    struct ucontext_t *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
    __extension__ unsigned long long int __ssp[4];
  } ucontext_t;
extern int siginterrupt (int __sig, int __interrupt) __attribute__ ((__nothrow__ , __leaf__));
enum
{
  SS_ONSTACK = 1,
  SS_DISABLE
};
extern int sigaltstack (const stack_t *__restrict __ss,
   stack_t *__restrict __oss) __attribute__ ((__nothrow__ , __leaf__));
struct sigstack
  {
    void *ss_sp;
    int ss_onstack;
  };
extern int sigstack (struct sigstack *__ss, struct sigstack *__oss)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int sighold (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern int sigrelse (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern int sigignore (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern __sighandler_t sigset (int __sig, __sighandler_t __disp) __attribute__ ((__nothrow__ , __leaf__));
extern int pthread_sigmask (int __how,
       const __sigset_t *__restrict __newmask,
       __sigset_t *__restrict __oldmask)__attribute__ ((__nothrow__ , __leaf__));
extern int pthread_kill (pthread_t __threadid, int __signo) __attribute__ ((__nothrow__ , __leaf__));
extern int pthread_sigqueue (pthread_t __threadid, int __signo,
        const union sigval __value) __attribute__ ((__nothrow__ , __leaf__));
extern int __libc_current_sigrtmin (void) __attribute__ ((__nothrow__ , __leaf__));
extern int __libc_current_sigrtmax (void) __attribute__ ((__nothrow__ , __leaf__));
extern int tgkill (__pid_t __tgid, __pid_t __tid, int __signal);

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
enum {
 Audit_equal,
 Audit_not_equal,
 Audit_bitmask,
 Audit_bittest,
 Audit_lt,
 Audit_gt,
 Audit_le,
 Audit_ge,
 Audit_bad
};
enum audit_nlgrps {
 AUDIT_NLGRP_NONE,
 AUDIT_NLGRP_READLOG,
 __AUDIT_NLGRP_MAX
};
struct audit_status {
 __u32 mask;
 __u32 enabled;
 __u32 failure;
 __u32 pid;
 __u32 rate_limit;
 __u32 backlog_limit;
 __u32 lost;
 __u32 backlog;
 union {
  __u32 version;
  __u32 feature_bitmap;
 };
 __u32 backlog_wait_time;
};
struct audit_features {
 __u32 vers;
 __u32 mask;
 __u32 features;
 __u32 lock;
};
struct audit_tty_status {
 __u32 enabled;
 __u32 log_passwd;
};
struct audit_rule_data {
 __u32 flags;
 __u32 action;
 __u32 field_count;
 __u32 mask[64];
 __u32 fields[64];
 __u32 values[64];
 __u32 fieldflags[64];
 __u32 buflen;
 char buf[0];
};
extern void printsiginfo(struct tcb *, const siginfo_t *);

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0) == (0), "EM_NONE != 0");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((1) == (1), "EM_M32 != 1");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (1)
      > (unsigned long long) ((0)),
      "Incorrect order in #sorted xlat: EM_M32"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((2) == (2), "EM_SPARC != 2");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (2)
      > (unsigned long long) ((1)),
      "Incorrect order in #sorted xlat: EM_SPARC"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((3) == (3), "EM_386 != 3");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (3)
      > (unsigned long long) ((2)),
      "Incorrect order in #sorted xlat: EM_386"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((4) == (4), "EM_68K != 4");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (4)
      > (unsigned long long) ((3)),
      "Incorrect order in #sorted xlat: EM_68K"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((5) == (5), "EM_88K != 5");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (5)
      > (unsigned long long) ((4)),
      "Incorrect order in #sorted xlat: EM_88K"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((6) == (6), "EM_486 != 6");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (6)
      > (unsigned long long) ((5)),
      "Incorrect order in #sorted xlat: EM_486"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((7) == (7), "EM_860 != 7");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (7)
      > (unsigned long long) ((6)),
      "Incorrect order in #sorted xlat: EM_860"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((8) == (8), "EM_MIPS != 8");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (8)
      > (unsigned long long) ((7)),
      "Incorrect order in #sorted xlat: EM_MIPS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (9)
      > (unsigned long long) ((8)),
      "Incorrect order in #sorted xlat: EM_S370"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((10) == (10), "EM_MIPS_RS3_LE != 10");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (10)
      > (unsigned long long) ((9)),
      "Incorrect order in #sorted xlat: EM_MIPS_RS3_LE"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((15) == (15), "EM_PARISC != 15");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (15)
      > (unsigned long long) ((10)),
      "Incorrect order in #sorted xlat: EM_PARISC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (17)
      > (unsigned long long) ((15)),
      "Incorrect order in #sorted xlat: EM_VPP500"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((18) == (18), "EM_SPARC32PLUS != 18");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (18)
      > (unsigned long long) ((17)),
      "Incorrect order in #sorted xlat: EM_SPARC32PLUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (19)
      > (unsigned long long) ((18)),
      "Incorrect order in #sorted xlat: EM_960"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((20) == (20), "EM_PPC != 20");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (20)
      > (unsigned long long) ((19)),
      "Incorrect order in #sorted xlat: EM_PPC"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((21) == (21), "EM_PPC64 != 21");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (21)
      > (unsigned long long) ((20)),
      "Incorrect order in #sorted xlat: EM_PPC64"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((22) == (22), "EM_S390 != 22");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (22)
      > (unsigned long long) ((21)),
      "Incorrect order in #sorted xlat: EM_S390"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((23) == (23), "EM_SPU != 23");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (23)
      > (unsigned long long) ((22)),
      "Incorrect order in #sorted xlat: EM_SPU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (36)
      > (unsigned long long) ((23)),
      "Incorrect order in #sorted xlat: EM_V800"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (37)
      > (unsigned long long) ((36)),
      "Incorrect order in #sorted xlat: EM_FR20"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (38)
      > (unsigned long long) ((37)),
      "Incorrect order in #sorted xlat: EM_RH32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (39)
      > (unsigned long long) ((38)),
      "Incorrect order in #sorted xlat: EM_RCE"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((40) == (40), "EM_ARM != 40");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (40)
      > (unsigned long long) ((39)),
      "Incorrect order in #sorted xlat: EM_ARM"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((42) == (42), "EM_SH != 42");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (42)
      > (unsigned long long) ((40)),
      "Incorrect order in #sorted xlat: EM_SH"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((43) == (43), "EM_SPARCV9 != 43");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (43)
      > (unsigned long long) ((42)),
      "Incorrect order in #sorted xlat: EM_SPARCV9"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (44)
      > (unsigned long long) ((43)),
      "Incorrect order in #sorted xlat: EM_TRICORE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (45)
      > (unsigned long long) ((44)),
      "Incorrect order in #sorted xlat: EM_ARC"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((46) == (46), "EM_H8_300 != 46");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (46)
      > (unsigned long long) ((45)),
      "Incorrect order in #sorted xlat: EM_H8_300"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (47)
      > (unsigned long long) ((46)),
      "Incorrect order in #sorted xlat: EM_H8_300H"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (48)
      > (unsigned long long) ((47)),
      "Incorrect order in #sorted xlat: EM_H8S"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (49)
      > (unsigned long long) ((48)),
      "Incorrect order in #sorted xlat: EM_H8_500"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((50) == (50), "EM_IA_64 != 50");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (50)
      > (unsigned long long) ((49)),
      "Incorrect order in #sorted xlat: EM_IA_64"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (51)
      > (unsigned long long) ((50)),
      "Incorrect order in #sorted xlat: EM_MIPS_X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (52)
      > (unsigned long long) ((51)),
      "Incorrect order in #sorted xlat: EM_COLDFIRE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (53)
      > (unsigned long long) ((52)),
      "Incorrect order in #sorted xlat: EM_68HC12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (54)
      > (unsigned long long) ((53)),
      "Incorrect order in #sorted xlat: EM_MMA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (55)
      > (unsigned long long) ((54)),
      "Incorrect order in #sorted xlat: EM_PCP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (56)
      > (unsigned long long) ((55)),
      "Incorrect order in #sorted xlat: EM_NCPU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (57)
      > (unsigned long long) ((56)),
      "Incorrect order in #sorted xlat: EM_NDR1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (58)
      > (unsigned long long) ((57)),
      "Incorrect order in #sorted xlat: EM_STARCORE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (59)
      > (unsigned long long) ((58)),
      "Incorrect order in #sorted xlat: EM_ME16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (60)
      > (unsigned long long) ((59)),
      "Incorrect order in #sorted xlat: EM_ST100"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (61)
      > (unsigned long long) ((60)),
      "Incorrect order in #sorted xlat: EM_TINYJ"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((62) == (62), "EM_X86_64 != 62");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (62)
      > (unsigned long long) ((61)),
      "Incorrect order in #sorted xlat: EM_X86_64"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (63)
      > (unsigned long long) ((62)),
      "Incorrect order in #sorted xlat: EM_PDSP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (64)
      > (unsigned long long) ((63)),
      "Incorrect order in #sorted xlat: EM_PDP10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (65)
      > (unsigned long long) ((64)),
      "Incorrect order in #sorted xlat: EM_PDP11"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (66)
      > (unsigned long long) ((65)),
      "Incorrect order in #sorted xlat: EM_FX66"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (67)
      > (unsigned long long) ((66)),
      "Incorrect order in #sorted xlat: EM_ST9PLUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (68)
      > (unsigned long long) ((67)),
      "Incorrect order in #sorted xlat: EM_ST7"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (69)
      > (unsigned long long) ((68)),
      "Incorrect order in #sorted xlat: EM_68HC16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (70)
      > (unsigned long long) ((69)),
      "Incorrect order in #sorted xlat: EM_68HC11"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (71)
      > (unsigned long long) ((70)),
      "Incorrect order in #sorted xlat: EM_68HC08"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (72)
      > (unsigned long long) ((71)),
      "Incorrect order in #sorted xlat: EM_68HC05"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (73)
      > (unsigned long long) ((72)),
      "Incorrect order in #sorted xlat: EM_SVX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (74)
      > (unsigned long long) ((73)),
      "Incorrect order in #sorted xlat: EM_ST19"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (75)
      > (unsigned long long) ((74)),
      "Incorrect order in #sorted xlat: EM_VAX"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((76) == (76), "EM_CRIS != 76");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (76)
      > (unsigned long long) ((75)),
      "Incorrect order in #sorted xlat: EM_CRIS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (77)
      > (unsigned long long) ((76)),
      "Incorrect order in #sorted xlat: EM_JAVELIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (78)
      > (unsigned long long) ((77)),
      "Incorrect order in #sorted xlat: EM_FIREPATH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (79)
      > (unsigned long long) ((78)),
      "Incorrect order in #sorted xlat: EM_ZSP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (80)
      > (unsigned long long) ((79)),
      "Incorrect order in #sorted xlat: EM_MMIX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (81)
      > (unsigned long long) ((80)),
      "Incorrect order in #sorted xlat: EM_HUANY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (82)
      > (unsigned long long) ((81)),
      "Incorrect order in #sorted xlat: EM_PRISM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (83)
      > (unsigned long long) ((82)),
      "Incorrect order in #sorted xlat: EM_AVR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (84)
      > (unsigned long long) ((83)),
      "Incorrect order in #sorted xlat: EM_FR30"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (85)
      > (unsigned long long) ((84)),
      "Incorrect order in #sorted xlat: EM_D10V"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (86)
      > (unsigned long long) ((85)),
      "Incorrect order in #sorted xlat: EM_D30V"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (87)
      > (unsigned long long) ((86)),
      "Incorrect order in #sorted xlat: EM_V850"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((88) == (88), "EM_M32R != 88");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (88)
      > (unsigned long long) ((87)),
      "Incorrect order in #sorted xlat: EM_M32R"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((89) == (89), "EM_MN10300 != 89");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (89)
      > (unsigned long long) ((88)),
      "Incorrect order in #sorted xlat: EM_MN10300"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (90)
      > (unsigned long long) ((89)),
      "Incorrect order in #sorted xlat: EM_MN10200"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (91)
      > (unsigned long long) ((90)),
      "Incorrect order in #sorted xlat: EM_PJ"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((92) == (92), "EM_OPENRISC != 92");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (92)
      > (unsigned long long) ((91)),
      "Incorrect order in #sorted xlat: EM_OPENRISC"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((93) == (93), "EM_ARCOMPACT != 93");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (93)
      > (unsigned long long) ((92)),
      "Incorrect order in #sorted xlat: EM_ARCOMPACT"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((94) == (94), "EM_XTENSA != 94");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (94)
      > (unsigned long long) ((93)),
      "Incorrect order in #sorted xlat: EM_XTENSA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (95)
      > (unsigned long long) ((94)),
      "Incorrect order in #sorted xlat: EM_VIDEOCORE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (96)
      > (unsigned long long) ((95)),
      "Incorrect order in #sorted xlat: EM_TMM_GPP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (97)
      > (unsigned long long) ((96)),
      "Incorrect order in #sorted xlat: EM_NS32K"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (98)
      > (unsigned long long) ((97)),
      "Incorrect order in #sorted xlat: EM_TPC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (99)
      > (unsigned long long) ((98)),
      "Incorrect order in #sorted xlat: EM_SNP1K"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (100)
      > (unsigned long long) ((99)),
      "Incorrect order in #sorted xlat: EM_ST200"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (101)
      > (unsigned long long) ((100)),
      "Incorrect order in #sorted xlat: EM_IP2K"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (102)
      > (unsigned long long) ((101)),
      "Incorrect order in #sorted xlat: EM_MAX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (103)
      > (unsigned long long) ((102)),
      "Incorrect order in #sorted xlat: EM_CR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (104)
      > (unsigned long long) ((103)),
      "Incorrect order in #sorted xlat: EM_F2MC16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (105)
      > (unsigned long long) ((104)),
      "Incorrect order in #sorted xlat: EM_MSP430"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((106) == (106), "EM_BLACKFIN != 106");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (106)
      > (unsigned long long) ((105)),
      "Incorrect order in #sorted xlat: EM_BLACKFIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (107)
      > (unsigned long long) ((106)),
      "Incorrect order in #sorted xlat: EM_SE_C33"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (108)
      > (unsigned long long) ((107)),
      "Incorrect order in #sorted xlat: EM_SEP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (109)
      > (unsigned long long) ((108)),
      "Incorrect order in #sorted xlat: EM_ARCA"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((110) == (110), "EM_UNICORE != 110");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (110)
      > (unsigned long long) ((109)),
      "Incorrect order in #sorted xlat: EM_UNICORE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (111)
      > (unsigned long long) ((110)),
      "Incorrect order in #sorted xlat: EM_EXCESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (112)
      > (unsigned long long) ((111)),
      "Incorrect order in #sorted xlat: EM_DXP"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((113) == (113), "EM_ALTERA_NIOS2 != 113");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (113)
      > (unsigned long long) ((112)),
      "Incorrect order in #sorted xlat: EM_ALTERA_NIOS2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (114)
      > (unsigned long long) ((113)),
      "Incorrect order in #sorted xlat: EM_CRX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (115)
      > (unsigned long long) ((114)),
      "Incorrect order in #sorted xlat: EM_XGATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (116)
      > (unsigned long long) ((115)),
      "Incorrect order in #sorted xlat: EM_C166"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (117)
      > (unsigned long long) ((116)),
      "Incorrect order in #sorted xlat: EM_M16C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (118)
      > (unsigned long long) ((117)),
      "Incorrect order in #sorted xlat: EM_DSPIC30F"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (119)
      > (unsigned long long) ((118)),
      "Incorrect order in #sorted xlat: EM_CE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (120)
      > (unsigned long long) ((119)),
      "Incorrect order in #sorted xlat: EM_M32C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (131)
      > (unsigned long long) ((120)),
      "Incorrect order in #sorted xlat: EM_TSK3000"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (132)
      > (unsigned long long) ((131)),
      "Incorrect order in #sorted xlat: EM_RS08"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (133)
      > (unsigned long long) ((132)),
      "Incorrect order in #sorted xlat: EM_SHARC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (134)
      > (unsigned long long) ((133)),
      "Incorrect order in #sorted xlat: EM_ECOG2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (135)
      > (unsigned long long) ((134)),
      "Incorrect order in #sorted xlat: EM_SCORE7"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (136)
      > (unsigned long long) ((135)),
      "Incorrect order in #sorted xlat: EM_DSP24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (137)
      > (unsigned long long) ((136)),
      "Incorrect order in #sorted xlat: EM_VIDEOCORE3"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (138)
      > (unsigned long long) ((137)),
      "Incorrect order in #sorted xlat: EM_LATTICEMICO32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (139)
      > (unsigned long long) ((138)),
      "Incorrect order in #sorted xlat: EM_SE_C17"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((140) == (140), "EM_TI_C6000 != 140");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (140)
      > (unsigned long long) ((139)),
      "Incorrect order in #sorted xlat: EM_TI_C6000"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (141)
      > (unsigned long long) ((140)),
      "Incorrect order in #sorted xlat: EM_TI_C2000"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (142)
      > (unsigned long long) ((141)),
      "Incorrect order in #sorted xlat: EM_TI_C5500"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (143)
      > (unsigned long long) ((142)),
      "Incorrect order in #sorted xlat: EM_TI_ARP32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (144)
      > (unsigned long long) ((143)),
      "Incorrect order in #sorted xlat: EM_TI_PRU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (160)
      > (unsigned long long) ((144)),
      "Incorrect order in #sorted xlat: EM_MMDSP_PLUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (161)
      > (unsigned long long) ((160)),
      "Incorrect order in #sorted xlat: EM_CYPRESS_M8C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (162)
      > (unsigned long long) ((161)),
      "Incorrect order in #sorted xlat: EM_R32C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (163)
      > (unsigned long long) ((162)),
      "Incorrect order in #sorted xlat: EM_TRIMEDIA"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((164) == (164), "EM_HEXAGON != 164");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (164)
      > (unsigned long long) ((163)),
      "Incorrect order in #sorted xlat: EM_HEXAGON"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (165)
      > (unsigned long long) ((164)),
      "Incorrect order in #sorted xlat: EM_8051"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (166)
      > (unsigned long long) ((165)),
      "Incorrect order in #sorted xlat: EM_STXP7X"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((167) == (167), "EM_NDS32 != 167");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (167)
      > (unsigned long long) ((166)),
      "Incorrect order in #sorted xlat: EM_NDS32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (168)
      > (unsigned long long) ((167)),
      "Incorrect order in #sorted xlat: EM_ECOG1X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (169)
      > (unsigned long long) ((168)),
      "Incorrect order in #sorted xlat: EM_MAXQ30"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (170)
      > (unsigned long long) ((169)),
      "Incorrect order in #sorted xlat: EM_XIMO16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (171)
      > (unsigned long long) ((170)),
      "Incorrect order in #sorted xlat: EM_MANIK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (172)
      > (unsigned long long) ((171)),
      "Incorrect order in #sorted xlat: EM_CRAYNV2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (173)
      > (unsigned long long) ((172)),
      "Incorrect order in #sorted xlat: EM_RX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (174)
      > (unsigned long long) ((173)),
      "Incorrect order in #sorted xlat: EM_METAG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (175)
      > (unsigned long long) ((174)),
      "Incorrect order in #sorted xlat: EM_MCST_ELBRUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (176)
      > (unsigned long long) ((175)),
      "Incorrect order in #sorted xlat: EM_ECOG16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (177)
      > (unsigned long long) ((176)),
      "Incorrect order in #sorted xlat: EM_CR16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (178)
      > (unsigned long long) ((177)),
      "Incorrect order in #sorted xlat: EM_ETPU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (179)
      > (unsigned long long) ((178)),
      "Incorrect order in #sorted xlat: EM_SLE9X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (180)
      > (unsigned long long) ((179)),
      "Incorrect order in #sorted xlat: EM_L10M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (181)
      > (unsigned long long) ((180)),
      "Incorrect order in #sorted xlat: EM_K10M"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((183) == (183), "EM_AARCH64 != 183");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (183)
      > (unsigned long long) ((181)),
      "Incorrect order in #sorted xlat: EM_AARCH64"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (186)
      > (unsigned long long) ((183)),
      "Incorrect order in #sorted xlat: EM_STM8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (187)
      > (unsigned long long) ((186)),
      "Incorrect order in #sorted xlat: EM_TILE64"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((188) == (188), "EM_TILEPRO != 188");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (188)
      > (unsigned long long) ((187)),
      "Incorrect order in #sorted xlat: EM_TILEPRO"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((189) == (189), "EM_MICROBLAZE != 189");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (189)
      > (unsigned long long) ((188)),
      "Incorrect order in #sorted xlat: EM_MICROBLAZE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (190)
      > (unsigned long long) ((189)),
      "Incorrect order in #sorted xlat: EM_CUDA"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((191) == (191), "EM_TILEGX != 191");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (191)
      > (unsigned long long) ((190)),
      "Incorrect order in #sorted xlat: EM_TILEGX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (192)
      > (unsigned long long) ((191)),
      "Incorrect order in #sorted xlat: EM_CLOUDSHIELD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (193)
      > (unsigned long long) ((192)),
      "Incorrect order in #sorted xlat: EM_COREA_1ST"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (194)
      > (unsigned long long) ((193)),
      "Incorrect order in #sorted xlat: EM_COREA_2ND"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((195) == (195), "EM_ARCV2 != 195");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (195)
      > (unsigned long long) ((194)),
      "Incorrect order in #sorted xlat: EM_ARCV2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (196)
      > (unsigned long long) ((195)),
      "Incorrect order in #sorted xlat: EM_OPEN8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (197)
      > (unsigned long long) ((196)),
      "Incorrect order in #sorted xlat: EM_RL78"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (198)
      > (unsigned long long) ((197)),
      "Incorrect order in #sorted xlat: EM_VIDEOCORE5"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (199)
      > (unsigned long long) ((198)),
      "Incorrect order in #sorted xlat: EM_78KOR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (200)
      > (unsigned long long) ((199)),
      "Incorrect order in #sorted xlat: EM_56800EX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (201)
      > (unsigned long long) ((200)),
      "Incorrect order in #sorted xlat: EM_BA1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (202)
      > (unsigned long long) ((201)),
      "Incorrect order in #sorted xlat: EM_BA2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (203)
      > (unsigned long long) ((202)),
      "Incorrect order in #sorted xlat: EM_XCORE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (204)
      > (unsigned long long) ((203)),
      "Incorrect order in #sorted xlat: EM_MCHP_PIC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (210)
      > (unsigned long long) ((204)),
      "Incorrect order in #sorted xlat: EM_KM32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (211)
      > (unsigned long long) ((210)),
      "Incorrect order in #sorted xlat: EM_KMX32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (212)
      > (unsigned long long) ((211)),
      "Incorrect order in #sorted xlat: EM_KMX16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (213)
      > (unsigned long long) ((212)),
      "Incorrect order in #sorted xlat: EM_KMX8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (214)
      > (unsigned long long) ((213)),
      "Incorrect order in #sorted xlat: EM_KVARC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (215)
      > (unsigned long long) ((214)),
      "Incorrect order in #sorted xlat: EM_CDP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (216)
      > (unsigned long long) ((215)),
      "Incorrect order in #sorted xlat: EM_COGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (217)
      > (unsigned long long) ((216)),
      "Incorrect order in #sorted xlat: EM_COOL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (218)
      > (unsigned long long) ((217)),
      "Incorrect order in #sorted xlat: EM_NORC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (219)
      > (unsigned long long) ((218)),
      "Incorrect order in #sorted xlat: EM_CSR_KALIMBA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (220)
      > (unsigned long long) ((219)),
      "Incorrect order in #sorted xlat: EM_Z80"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (221)
      > (unsigned long long) ((220)),
      "Incorrect order in #sorted xlat: EM_VISIUM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (222)
      > (unsigned long long) ((221)),
      "Incorrect order in #sorted xlat: EM_FT32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (223)
      > (unsigned long long) ((222)),
      "Incorrect order in #sorted xlat: EM_MOXIE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (224)
      > (unsigned long long) ((223)),
      "Incorrect order in #sorted xlat: EM_AMDGPU"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((243) == (243), "EM_RISCV != 243");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (243)
      > (unsigned long long) ((224)),
      "Incorrect order in #sorted xlat: EM_RISCV"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((247) == (247), "EM_BPF != 247");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (247)
      > (unsigned long long) ((243)),
      "Incorrect order in #sorted xlat: EM_BPF"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((252) == (252), "EM_CSKY != 252");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (252)
      > (unsigned long long) ((247)),
      "Incorrect order in #sorted xlat: EM_CSKY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (258)
      > (unsigned long long) ((252)),
      "Incorrect order in #sorted xlat: EM_LOONGARCH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x18ad)
      > (unsigned long long) ((258)),
      "Incorrect order in #sorted xlat: EM_AVR32"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0x5441) == (0x5441), "EM_FRV != 0x5441");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (0x5441)
      > (unsigned long long) ((0x18ad)),
      "Incorrect order in #sorted xlat: EM_FRV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x8472)
      > (unsigned long long) ((0x5441)),
      "Incorrect order in #sorted xlat: EM_OR32"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0x9026) == (0x9026), "EM_ALPHA != 0x9026");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (0x9026)
      > (unsigned long long) ((0x8472)),
      "Incorrect order in #sorted xlat: EM_ALPHA"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0x9041) == (0x9041), "EM_CYGNUS_M32R != 0x9041");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (0x9041)
      > (unsigned long long) ((0x9026)),
      "Incorrect order in #sorted xlat: EM_CYGNUS_M32R"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x9080)
      > (unsigned long long) ((0x9041)),
      "Incorrect order in #sorted xlat: EM_CYGNUS_V850"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0xA390) == (0xa390), "EM_S390_OLD != 0xa390");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (0xA390)
      > (unsigned long long) ((0x9080)),
      "Incorrect order in #sorted xlat: EM_S390_OLD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0xabc7)
      > (unsigned long long) ((0xA390)),
      "Incorrect order in #sorted xlat: EM_XTENSA_OLD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0xbaab)
      > (unsigned long long) ((0xabc7)),
      "Incorrect order in #sorted xlat: EM_MICROBLAZE_OLD"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((0xbeef) == (0xbeef), "EM_CYGNUS_MN10300 != 0xbeef");

#pragma GCC diagnostic pop
;
_Static_assert((unsigned long long) (0xbeef)
      > (unsigned long long) ((0xbaab)),
      "Incorrect order in #sorted xlat: EM_CYGNUS_MN10300"
      " is not larger than the previous value");

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((183|0x80000000|0x40000000)) == ((183|0x80000000|0x40000000)), "AUDIT_ARCH_AARCH64 != (EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((0x9026|0x80000000|0x40000000)) == ((0x9026|0x80000000|0x40000000)), "AUDIT_ARCH_ALPHA != (EM_ALPHA|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((93|0x40000000)) == ((93|0x40000000)), "AUDIT_ARCH_ARCOMPACT != (EM_ARCOMPACT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((93)) == ((93)), "AUDIT_ARCH_ARCOMPACTBE != (EM_ARCOMPACT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((195|0x40000000)) == ((195|0x40000000)), "AUDIT_ARCH_ARCV2 != (EM_ARCV2|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((195)) == ((195)), "AUDIT_ARCH_ARCV2BE != (EM_ARCV2)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((40|0x40000000)) == ((40|0x40000000)), "AUDIT_ARCH_ARM != (EM_ARM|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((40)) == ((40)), "AUDIT_ARCH_ARMEB != (EM_ARM)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((140|0x40000000)) == ((140|0x40000000)), "AUDIT_ARCH_C6X != (EM_TI_C6000|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((140)) == ((140)), "AUDIT_ARCH_C6XBE != (EM_TI_C6000)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((76|0x40000000)) == ((76|0x40000000)), "AUDIT_ARCH_CRIS != (EM_CRIS|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((252|0x40000000)) == ((252|0x40000000)), "AUDIT_ARCH_CSKY != (EM_CSKY|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((0x5441)) == ((0x5441)), "AUDIT_ARCH_FRV != (EM_FRV)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((46)) == ((46)), "AUDIT_ARCH_H8300 != (EM_H8_300)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((164)) == ((164)), "AUDIT_ARCH_HEXAGON != (EM_HEXAGON)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((3|0x40000000)) == ((3|0x40000000)), "AUDIT_ARCH_I386 != (EM_386|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((50|0x80000000|0x40000000)) == ((50|0x80000000|0x40000000)), "AUDIT_ARCH_IA64 != (EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((88)) == ((88)), "AUDIT_ARCH_M32R != (EM_M32R)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((4)) == ((4)), "AUDIT_ARCH_M68K != (EM_68K)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((189)) == ((189)), "AUDIT_ARCH_MICROBLAZE != (EM_MICROBLAZE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8)) == ((8)), "AUDIT_ARCH_MIPS != (EM_MIPS)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8|0x80000000)) == ((8|0x80000000)), "AUDIT_ARCH_MIPS64 != (EM_MIPS|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8|0x80000000| 0x20000000)) == ((8|0x80000000|0x20000000)), "AUDIT_ARCH_MIPS64N32 != (EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_CONVENTION_MIPS64_N32)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8|0x40000000)) == ((8|0x40000000)), "AUDIT_ARCH_MIPSEL != (EM_MIPS|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8|0x80000000|0x40000000)) == ((8|0x80000000|0x40000000)), "AUDIT_ARCH_MIPSEL64 != (EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((8|0x80000000|0x40000000| 0x20000000)) == ((8|0x80000000|0x40000000|0x20000000)), "AUDIT_ARCH_MIPSEL64N32 != (EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE|__AUDIT_ARCH_CONVENTION_MIPS64_N32)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((167|0x40000000)) == ((167|0x40000000)), "AUDIT_ARCH_NDS32 != (EM_NDS32|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((167)) == ((167)), "AUDIT_ARCH_NDS32BE != (EM_NDS32)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((113|0x40000000)) == ((113|0x40000000)), "AUDIT_ARCH_NIOS2 != (EM_ALTERA_NIOS2|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((92)) == ((92)), "AUDIT_ARCH_OPENRISC != (EM_OPENRISC)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((15)) == ((15)), "AUDIT_ARCH_PARISC != (EM_PARISC)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((15|0x80000000)) == ((15|0x80000000)), "AUDIT_ARCH_PARISC64 != (EM_PARISC|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((20)) == ((20)), "AUDIT_ARCH_PPC != (EM_PPC)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((21|0x80000000)) == ((21|0x80000000)), "AUDIT_ARCH_PPC64 != (EM_PPC64|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((21|0x80000000|0x40000000)) == ((21|0x80000000|0x40000000)), "AUDIT_ARCH_PPC64LE != (EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((243|0x40000000)) == ((243|0x40000000)), "AUDIT_ARCH_RISCV32 != (EM_RISCV|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((243|0x80000000|0x40000000)) == ((243|0x80000000|0x40000000)), "AUDIT_ARCH_RISCV64 != (EM_RISCV|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((22)) == ((22)), "AUDIT_ARCH_S390 != (EM_S390)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((22|0x80000000)) == ((22|0x80000000)), "AUDIT_ARCH_S390X != (EM_S390|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((42)) == ((42)), "AUDIT_ARCH_SH != (EM_SH)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((42|0x80000000)) == ((42|0x80000000)), "AUDIT_ARCH_SH64 != (EM_SH|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((42|0x40000000)) == ((42|0x40000000)), "AUDIT_ARCH_SHEL != (EM_SH|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((42|0x80000000|0x40000000)) == ((42|0x80000000|0x40000000)), "AUDIT_ARCH_SHEL64 != (EM_SH|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((2)) == ((2)), "AUDIT_ARCH_SPARC != (EM_SPARC)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((43|0x80000000)) == ((43|0x80000000)), "AUDIT_ARCH_SPARC64 != (EM_SPARCV9|__AUDIT_ARCH_64BIT)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((191|0x80000000|0x40000000)) == ((191|0x80000000|0x40000000)), "AUDIT_ARCH_TILEGX != (EM_TILEGX|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((191|0x40000000)) == ((191|0x40000000)), "AUDIT_ARCH_TILEGX32 != (EM_TILEGX|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((188|0x40000000)) == ((188|0x40000000)), "AUDIT_ARCH_TILEPRO != (EM_TILEPRO|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((110|0x40000000)) == ((110|0x40000000)), "AUDIT_ARCH_UNICORE != (EM_UNICORE|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((62|0x80000000|0x40000000)) == ((62|0x80000000|0x40000000)), "AUDIT_ARCH_X86_64 != (EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert(((94)) == ((94)), "AUDIT_ARCH_XTENSA != (EM_XTENSA)");

#pragma GCC diagnostic pop
;

static const struct xlat_data audit_arch_xdata[] = {
 { (unsigned)((183|0x80000000|0x40000000)), "AUDIT_ARCH_AARCH64" },
 { (unsigned)((0x9026|0x80000000|0x40000000)), "AUDIT_ARCH_ALPHA" },
 { (unsigned)((93|0x40000000)), "AUDIT_ARCH_ARCOMPACT" },
 { (unsigned)((93)), "AUDIT_ARCH_ARCOMPACTBE" },
 { (unsigned)((195|0x40000000)), "AUDIT_ARCH_ARCV2" },
 { (unsigned)((195)), "AUDIT_ARCH_ARCV2BE" },
 { (unsigned)((40|0x40000000)), "AUDIT_ARCH_ARM" },
 { (unsigned)((40)), "AUDIT_ARCH_ARMEB" },
 { (unsigned)((140|0x40000000)), "AUDIT_ARCH_C6X" },
 { (unsigned)((140)), "AUDIT_ARCH_C6XBE" },
 { (unsigned)((76|0x40000000)), "AUDIT_ARCH_CRIS" },
 { (unsigned)((252|0x40000000)), "AUDIT_ARCH_CSKY" },
 { (unsigned)((0x5441)), "AUDIT_ARCH_FRV" },
 { (unsigned)((46)), "AUDIT_ARCH_H8300" },
 { (unsigned)((164)), "AUDIT_ARCH_HEXAGON" },
 { (unsigned)((3|0x40000000)), "AUDIT_ARCH_I386" },
 { (unsigned)((50|0x80000000|0x40000000)), "AUDIT_ARCH_IA64" },
 { (unsigned)((258|0x40000000)), "AUDIT_ARCH_LOONGARCH32" },
 { (unsigned)((258|0x80000000|0x40000000)), "AUDIT_ARCH_LOONGARCH64" },
 { (unsigned)((88)), "AUDIT_ARCH_M32R" },
 { (unsigned)((4)), "AUDIT_ARCH_M68K" },
 { (unsigned)((189)), "AUDIT_ARCH_MICROBLAZE" },
 { (unsigned)((8)), "AUDIT_ARCH_MIPS" },
 { (unsigned)((8|0x80000000)), "AUDIT_ARCH_MIPS64" },
 { (unsigned)((8|0x80000000| 0x20000000)), "AUDIT_ARCH_MIPS64N32" },
 { (unsigned)((8|0x40000000)), "AUDIT_ARCH_MIPSEL" },
 { (unsigned)((8|0x80000000|0x40000000)), "AUDIT_ARCH_MIPSEL64" },
 { (unsigned)((8|0x80000000|0x40000000| 0x20000000)), "AUDIT_ARCH_MIPSEL64N32" },
 { (unsigned)((167|0x40000000)), "AUDIT_ARCH_NDS32" },
 { (unsigned)((167)), "AUDIT_ARCH_NDS32BE" },
 { (unsigned)((113|0x40000000)), "AUDIT_ARCH_NIOS2" },
 { (unsigned)((92)), "AUDIT_ARCH_OPENRISC" },
 { (unsigned)((15)), "AUDIT_ARCH_PARISC" },
 { (unsigned)((15|0x80000000)), "AUDIT_ARCH_PARISC64" },
 { (unsigned)((20)), "AUDIT_ARCH_PPC" },
 { (unsigned)((21|0x80000000)), "AUDIT_ARCH_PPC64" },
 { (unsigned)((21|0x80000000|0x40000000)), "AUDIT_ARCH_PPC64LE" },
 { (unsigned)((243|0x40000000)), "AUDIT_ARCH_RISCV32" },
 { (unsigned)((243|0x80000000|0x40000000)), "AUDIT_ARCH_RISCV64" },
 { (unsigned)((22)), "AUDIT_ARCH_S390" },
 { (unsigned)((22|0x80000000)), "AUDIT_ARCH_S390X" },
 { (unsigned)((42)), "AUDIT_ARCH_SH" },
 { (unsigned)((42|0x80000000)), "AUDIT_ARCH_SH64" },
 { (unsigned)((42|0x40000000)), "AUDIT_ARCH_SHEL" },
 { (unsigned)((42|0x80000000|0x40000000)), "AUDIT_ARCH_SHEL64" },
 { (unsigned)((2)), "AUDIT_ARCH_SPARC" },
 { (unsigned)((43|0x80000000)), "AUDIT_ARCH_SPARC64" },
 { (unsigned)((191|0x80000000|0x40000000)), "AUDIT_ARCH_TILEGX" },
 { (unsigned)((191|0x40000000)), "AUDIT_ARCH_TILEGX32" },
 { (unsigned)((188|0x40000000)), "AUDIT_ARCH_TILEPRO" },
 { (unsigned)((110|0x40000000)), "AUDIT_ARCH_UNICORE" },
 { (unsigned)((87|0x40000000)), "AUDIT_ARCH_V850" },
 { (unsigned)((62|0x80000000|0x40000000)), "AUDIT_ARCH_X86_64" },
 { (unsigned)((94)), "AUDIT_ARCH_XTENSA" },
};
const struct xlat audit_arch[1] = { {
 .data = audit_arch_xdata,
 .size = (sizeof(audit_arch_xdata) / sizeof((audit_arch_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((audit_arch_xdata)), __typeof__(&(audit_arch_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((183|0x80000000|0x40000000)))
  | ((unsigned) ((0x9026|0x80000000|0x40000000)))
  | ((unsigned) ((93|0x40000000)))
  | ((unsigned) ((93)))
  | ((unsigned) ((195|0x40000000)))
  | ((unsigned) ((195)))
  | ((unsigned) ((40|0x40000000)))
  | ((unsigned) ((40)))
  | ((unsigned) ((140|0x40000000)))
  | ((unsigned) ((140)))
  | ((unsigned) ((76|0x40000000)))
  | ((unsigned) ((252|0x40000000)))
  | ((unsigned) ((0x5441)))
  | ((unsigned) ((46)))
  | ((unsigned) ((164)))
  | ((unsigned) ((3|0x40000000)))
  | ((unsigned) ((50|0x80000000|0x40000000)))
  | ((unsigned) ((258|0x40000000)))
  | ((unsigned) ((258|0x80000000|0x40000000)))
  | ((unsigned) ((88)))
  | ((unsigned) ((4)))
  | ((unsigned) ((189)))
  | ((unsigned) ((8)))
  | ((unsigned) ((8|0x80000000)))
  | ((unsigned) ((8|0x80000000| 0x20000000)))
  | ((unsigned) ((8|0x40000000)))
  | ((unsigned) ((8|0x80000000|0x40000000)))
  | ((unsigned) ((8|0x80000000|0x40000000| 0x20000000)))
  | ((unsigned) ((167|0x40000000)))
  | ((unsigned) ((167)))
  | ((unsigned) ((113|0x40000000)))
  | ((unsigned) ((92)))
  | ((unsigned) ((15)))
  | ((unsigned) ((15|0x80000000)))
  | ((unsigned) ((20)))
  | ((unsigned) ((21|0x80000000)))
  | ((unsigned) ((21|0x80000000|0x40000000)))
  | ((unsigned) ((243|0x40000000)))
  | ((unsigned) ((243|0x80000000|0x40000000)))
  | ((unsigned) ((22)))
  | ((unsigned) ((22|0x80000000)))
  | ((unsigned) ((42)))
  | ((unsigned) ((42|0x80000000)))
  | ((unsigned) ((42|0x40000000)))
  | ((unsigned) ((42|0x80000000|0x40000000)))
  | ((unsigned) ((2)))
  | ((unsigned) ((43|0x80000000)))
  | ((unsigned) ((191|0x80000000|0x40000000)))
  | ((unsigned) ((191|0x40000000)))
  | ((unsigned) ((188|0x40000000)))
  | ((unsigned) ((110|0x40000000)))
  | ((unsigned) ((87|0x40000000)))
  | ((unsigned) ((62|0x80000000|0x40000000)))
  | ((unsigned) ((94)))
  ,
 .flags_strsz = 0
  + sizeof("AUDIT_ARCH_AARCH64")
  + sizeof("AUDIT_ARCH_ALPHA")
  + sizeof("AUDIT_ARCH_ARCOMPACT")
  + sizeof("AUDIT_ARCH_ARCOMPACTBE")
  + sizeof("AUDIT_ARCH_ARCV2")
  + sizeof("AUDIT_ARCH_ARCV2BE")
  + sizeof("AUDIT_ARCH_ARM")
  + sizeof("AUDIT_ARCH_ARMEB")
  + sizeof("AUDIT_ARCH_C6X")
  + sizeof("AUDIT_ARCH_C6XBE")
  + sizeof("AUDIT_ARCH_CRIS")
  + sizeof("AUDIT_ARCH_CSKY")
  + sizeof("AUDIT_ARCH_FRV")
  + sizeof("AUDIT_ARCH_H8300")
  + sizeof("AUDIT_ARCH_HEXAGON")
  + sizeof("AUDIT_ARCH_I386")
  + sizeof("AUDIT_ARCH_IA64")
  + sizeof("AUDIT_ARCH_LOONGARCH32")
  + sizeof("AUDIT_ARCH_LOONGARCH64")
  + sizeof("AUDIT_ARCH_M32R")
  + sizeof("AUDIT_ARCH_M68K")
  + sizeof("AUDIT_ARCH_MICROBLAZE")
  + sizeof("AUDIT_ARCH_MIPS")
  + sizeof("AUDIT_ARCH_MIPS64")
  + sizeof("AUDIT_ARCH_MIPS64N32")
  + sizeof("AUDIT_ARCH_MIPSEL")
  + sizeof("AUDIT_ARCH_MIPSEL64")
  + sizeof("AUDIT_ARCH_MIPSEL64N32")
  + sizeof("AUDIT_ARCH_NDS32")
  + sizeof("AUDIT_ARCH_NDS32BE")
  + sizeof("AUDIT_ARCH_NIOS2")
  + sizeof("AUDIT_ARCH_OPENRISC")
  + sizeof("AUDIT_ARCH_PARISC")
  + sizeof("AUDIT_ARCH_PARISC64")
  + sizeof("AUDIT_ARCH_PPC")
  + sizeof("AUDIT_ARCH_PPC64")
  + sizeof("AUDIT_ARCH_PPC64LE")
  + sizeof("AUDIT_ARCH_RISCV32")
  + sizeof("AUDIT_ARCH_RISCV64")
  + sizeof("AUDIT_ARCH_S390")
  + sizeof("AUDIT_ARCH_S390X")
  + sizeof("AUDIT_ARCH_SH")
  + sizeof("AUDIT_ARCH_SH64")
  + sizeof("AUDIT_ARCH_SHEL")
  + sizeof("AUDIT_ARCH_SHEL64")
  + sizeof("AUDIT_ARCH_SPARC")
  + sizeof("AUDIT_ARCH_SPARC64")
  + sizeof("AUDIT_ARCH_TILEGX")
  + sizeof("AUDIT_ARCH_TILEGX32")
  + sizeof("AUDIT_ARCH_TILEPRO")
  + sizeof("AUDIT_ARCH_UNICORE")
  + sizeof("AUDIT_ARCH_V850")
  + sizeof("AUDIT_ARCH_X86_64")
  + sizeof("AUDIT_ARCH_XTENSA")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((BUS_ADRALN) == (1), "BUS_ADRALN != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((BUS_ADRERR) == (2), "BUS_ADRERR != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((BUS_OBJERR) == (3), "BUS_OBJERR != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((BUS_MCEERR_AR) == (4), "BUS_MCEERR_AR != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((BUS_MCEERR_AO) == (5), "BUS_MCEERR_AO != 5");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigbus_codes_xdata[] = {
 { (unsigned)(BUS_ADRALN), "BUS_ADRALN" },
 { (unsigned)(BUS_ADRERR), "BUS_ADRERR" },
 { (unsigned)(BUS_OBJERR), "BUS_OBJERR" },
 { (unsigned)(BUS_MCEERR_AR), "BUS_MCEERR_AR" },
 { (unsigned)(BUS_MCEERR_AO), "BUS_MCEERR_AO" },
};
const struct xlat sigbus_codes[1] = { {
 .data = sigbus_codes_xdata,
 .size = (sizeof(sigbus_codes_xdata) / sizeof((sigbus_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigbus_codes_xdata)), __typeof__(&(sigbus_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (BUS_ADRALN))
  | ((unsigned) (BUS_ADRERR))
  | ((unsigned) (BUS_OBJERR))
  | ((unsigned) (BUS_MCEERR_AR))
  | ((unsigned) (BUS_MCEERR_AO))
  ,
 .flags_strsz = 0
  + sizeof("BUS_ADRALN")
  + sizeof("BUS_ADRERR")
  + sizeof("BUS_OBJERR")
  + sizeof("BUS_MCEERR_AR")
  + sizeof("BUS_MCEERR_AO")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_EXITED) == (1), "CLD_EXITED != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_KILLED) == (2), "CLD_KILLED != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_DUMPED) == (3), "CLD_DUMPED != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_TRAPPED) == (4), "CLD_TRAPPED != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_STOPPED) == (5), "CLD_STOPPED != 5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((CLD_CONTINUED) == (6), "CLD_CONTINUED != 6");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigchld_codes_xdata[] = {
 [CLD_EXITED] = { (unsigned)(CLD_EXITED), "CLD_EXITED" },
 [CLD_KILLED] = { (unsigned)(CLD_KILLED), "CLD_KILLED" },
 [CLD_DUMPED] = { (unsigned)(CLD_DUMPED), "CLD_DUMPED" },
 [CLD_TRAPPED] = { (unsigned)(CLD_TRAPPED), "CLD_TRAPPED" },
 [CLD_STOPPED] = { (unsigned)(CLD_STOPPED), "CLD_STOPPED" },
 [CLD_CONTINUED] = { (unsigned)(CLD_CONTINUED), "CLD_CONTINUED" },
};
const struct xlat sigchld_codes[1] = { {
 .data = sigchld_codes_xdata,
 .size = (sizeof(sigchld_codes_xdata) / sizeof((sigchld_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigchld_codes_xdata)), __typeof__(&(sigchld_codes_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (CLD_EXITED))
  | ((unsigned) (CLD_KILLED))
  | ((unsigned) (CLD_DUMPED))
  | ((unsigned) (CLD_TRAPPED))
  | ((unsigned) (CLD_STOPPED))
  | ((unsigned) (CLD_CONTINUED))
  ,
 .flags_strsz = 0
  + sizeof("CLD_EXITED")
  + sizeof("CLD_KILLED")
  + sizeof("CLD_DUMPED")
  + sizeof("CLD_TRAPPED")
  + sizeof("CLD_STOPPED")
  + sizeof("CLD_CONTINUED")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_INTDIV) == (1), "FPE_INTDIV != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_INTOVF) == (2), "FPE_INTOVF != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTDIV) == (3), "FPE_FLTDIV != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTOVF) == (4), "FPE_FLTOVF != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTUND) == (5), "FPE_FLTUND != 5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTRES) == (6), "FPE_FLTRES != 6");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTINV) == (7), "FPE_FLTINV != 7");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTSUB) == (8), "FPE_FLTSUB != 8");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_FLTUNK) == (14), "FPE_FLTUNK != 14");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((FPE_CONDTRAP) == (15), "FPE_CONDTRAP != 15");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigfpe_codes_xdata[] = {
 { (unsigned)(FPE_INTDIV), "FPE_INTDIV" },
 { (unsigned)(FPE_INTOVF), "FPE_INTOVF" },
 { (unsigned)(FPE_FLTDIV), "FPE_FLTDIV" },
 { (unsigned)(FPE_FLTOVF), "FPE_FLTOVF" },
 { (unsigned)(FPE_FLTUND), "FPE_FLTUND" },
 { (unsigned)(FPE_FLTRES), "FPE_FLTRES" },
 { (unsigned)(FPE_FLTINV), "FPE_FLTINV" },
 { (unsigned)(FPE_FLTSUB), "FPE_FLTSUB" },
 { (unsigned)(FPE_FLTUNK), "FPE_FLTUNK" },
 { (unsigned)(FPE_CONDTRAP), "FPE_CONDTRAP" },
};
const struct xlat sigfpe_codes[1] = { {
 .data = sigfpe_codes_xdata,
 .size = (sizeof(sigfpe_codes_xdata) / sizeof((sigfpe_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigfpe_codes_xdata)), __typeof__(&(sigfpe_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (FPE_INTDIV))
  | ((unsigned) (FPE_INTOVF))
  | ((unsigned) (FPE_FLTDIV))
  | ((unsigned) (FPE_FLTOVF))
  | ((unsigned) (FPE_FLTUND))
  | ((unsigned) (FPE_FLTRES))
  | ((unsigned) (FPE_FLTINV))
  | ((unsigned) (FPE_FLTSUB))
  | ((unsigned) (FPE_FLTUNK))
  | ((unsigned) (FPE_CONDTRAP))
  ,
 .flags_strsz = 0
  + sizeof("FPE_INTDIV")
  + sizeof("FPE_INTOVF")
  + sizeof("FPE_FLTDIV")
  + sizeof("FPE_FLTOVF")
  + sizeof("FPE_FLTUND")
  + sizeof("FPE_FLTRES")
  + sizeof("FPE_FLTINV")
  + sizeof("FPE_FLTSUB")
  + sizeof("FPE_FLTUNK")
  + sizeof("FPE_CONDTRAP")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_ILLOPC) == (1), "ILL_ILLOPC != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_ILLOPN) == (2), "ILL_ILLOPN != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_ILLADR) == (3), "ILL_ILLADR != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_ILLTRP) == (4), "ILL_ILLTRP != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_PRVOPC) == (5), "ILL_PRVOPC != 5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_PRVREG) == (6), "ILL_PRVREG != 6");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_COPROC) == (7), "ILL_COPROC != 7");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((ILL_BADSTK) == (8), "ILL_BADSTK != 8");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigill_codes_xdata[] = {
 { (unsigned)(ILL_ILLOPC), "ILL_ILLOPC" },
 { (unsigned)(ILL_ILLOPN), "ILL_ILLOPN" },
 { (unsigned)(ILL_ILLADR), "ILL_ILLADR" },
 { (unsigned)(ILL_ILLTRP), "ILL_ILLTRP" },
 { (unsigned)(ILL_PRVOPC), "ILL_PRVOPC" },
 { (unsigned)(ILL_PRVREG), "ILL_PRVREG" },
 { (unsigned)(ILL_COPROC), "ILL_COPROC" },
 { (unsigned)(ILL_BADSTK), "ILL_BADSTK" },
  { (unsigned)(ILL_BADIADDR), "ILL_BADIADDR" },
};
const struct xlat sigill_codes[1] = { {
 .data = sigill_codes_xdata,
 .size = (sizeof(sigill_codes_xdata) / sizeof((sigill_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigill_codes_xdata)), __typeof__(&(sigill_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (ILL_ILLOPC))
  | ((unsigned) (ILL_ILLOPN))
  | ((unsigned) (ILL_ILLADR))
  | ((unsigned) (ILL_ILLTRP))
  | ((unsigned) (ILL_PRVOPC))
  | ((unsigned) (ILL_PRVREG))
  | ((unsigned) (ILL_COPROC))
  | ((unsigned) (ILL_BADSTK))
  | ((unsigned) (ILL_BADIADDR))
  ,
 .flags_strsz = 0
  + sizeof("ILL_ILLOPC")
  + sizeof("ILL_ILLOPN")
  + sizeof("ILL_ILLADR")
  + sizeof("ILL_ILLTRP")
  + sizeof("ILL_PRVOPC")
  + sizeof("ILL_PRVREG")
  + sizeof("ILL_COPROC")
  + sizeof("ILL_BADSTK")
  + sizeof("ILL_BADIADDR")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_USER) == (0), "SI_USER != 0");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_KERNEL) == (0x80), "SI_KERNEL != 0x80");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_QUEUE) == (-1), "SI_QUEUE != -1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_TIMER) == (-2), "SI_TIMER != -2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_MESGQ) == (-3), "SI_MESGQ != -3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_ASYNCIO) == (-4), "SI_ASYNCIO != -4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_SIGIO) == (-5), "SI_SIGIO != -5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_TKILL) == (-6), "SI_TKILL != -6");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_DETHREAD) == (-7), "SI_DETHREAD != -7");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SI_ASYNCNL) == (-60), "SI_ASYNCNL != -60");

#pragma GCC diagnostic pop
;

static const struct xlat_data siginfo_codes_xdata[] = {
 { (unsigned)(SI_USER), "SI_USER" },
 { (unsigned)(SI_KERNEL), "SI_KERNEL" },
 { (unsigned)(SI_QUEUE), "SI_QUEUE" },
 { (unsigned)(SI_TIMER), "SI_TIMER" },
 { (unsigned)(SI_MESGQ), "SI_MESGQ" },
 { (unsigned)(SI_ASYNCIO), "SI_ASYNCIO" },
 { (unsigned)(SI_SIGIO), "SI_SIGIO" },
 { (unsigned)(SI_TKILL), "SI_TKILL" },
 { (unsigned)(SI_DETHREAD), "SI_DETHREAD" },
 { (unsigned)(SI_ASYNCNL), "SI_ASYNCNL" },
};
const struct xlat siginfo_codes[1] = { {
 .data = siginfo_codes_xdata,
 .size = (sizeof(siginfo_codes_xdata) / sizeof((siginfo_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((siginfo_codes_xdata)), __typeof__(&(siginfo_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (SI_USER))
  | ((unsigned) (SI_KERNEL))
  | ((unsigned) (SI_QUEUE))
  | ((unsigned) (SI_TIMER))
  | ((unsigned) (SI_MESGQ))
  | ((unsigned) (SI_ASYNCIO))
  | ((unsigned) (SI_SIGIO))
  | ((unsigned) (SI_TKILL))
  | ((unsigned) (SI_DETHREAD))
  | ((unsigned) (SI_ASYNCNL))
  ,
 .flags_strsz = 0
  + sizeof("SI_USER")
  + sizeof("SI_KERNEL")
  + sizeof("SI_QUEUE")
  + sizeof("SI_TIMER")
  + sizeof("SI_MESGQ")
  + sizeof("SI_ASYNCIO")
  + sizeof("SI_SIGIO")
  + sizeof("SI_TKILL")
  + sizeof("SI_DETHREAD")
  + sizeof("SI_ASYNCNL")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_IN) == (1), "POLL_IN != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_OUT) == (2), "POLL_OUT != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_MSG) == (3), "POLL_MSG != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_ERR) == (4), "POLL_ERR != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_PRI) == (5), "POLL_PRI != 5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((POLL_HUP) == (6), "POLL_HUP != 6");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigpoll_codes_xdata[] = {
 [POLL_IN] = { (unsigned)(POLL_IN), "POLL_IN" },
 [POLL_OUT] = { (unsigned)(POLL_OUT), "POLL_OUT" },
 [POLL_MSG] = { (unsigned)(POLL_MSG), "POLL_MSG" },
 [POLL_ERR] = { (unsigned)(POLL_ERR), "POLL_ERR" },
 [POLL_PRI] = { (unsigned)(POLL_PRI), "POLL_PRI" },
 [POLL_HUP] = { (unsigned)(POLL_HUP), "POLL_HUP" },
};
const struct xlat sigpoll_codes[1] = { {
 .data = sigpoll_codes_xdata,
 .size = (sizeof(sigpoll_codes_xdata) / sizeof((sigpoll_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigpoll_codes_xdata)), __typeof__(&(sigpoll_codes_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (POLL_IN))
  | ((unsigned) (POLL_OUT))
  | ((unsigned) (POLL_MSG))
  | ((unsigned) (POLL_ERR))
  | ((unsigned) (POLL_PRI))
  | ((unsigned) (POLL_HUP))
  ,
 .flags_strsz = 0
  + sizeof("POLL_IN")
  + sizeof("POLL_OUT")
  + sizeof("POLL_MSG")
  + sizeof("POLL_ERR")
  + sizeof("POLL_PRI")
  + sizeof("POLL_HUP")
  ,
} };


static const struct xlat_data sigprof_codes_xdata[] = {
};
const struct xlat sigprof_codes[1] = { {
 .data = sigprof_codes_xdata,
 .size = (sizeof(sigprof_codes_xdata) / sizeof((sigprof_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigprof_codes_xdata)), __typeof__(&(sigprof_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  ,
 .flags_strsz = 0
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_MAPERR) == (1), "SEGV_MAPERR != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_ACCERR) == (2), "SEGV_ACCERR != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_BNDERR) == (3), "SEGV_BNDERR != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_PKUERR) == (4), "SEGV_PKUERR != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_ACCADI) == (5), "SEGV_ACCADI != 5");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_ADIDERR) == (6), "SEGV_ADIDERR != 6");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((SEGV_ADIPERR) == (7), "SEGV_ADIPERR != 7");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigsegv_codes_xdata[] = {
 { (unsigned)(SEGV_MAPERR), "SEGV_MAPERR" },
 { (unsigned)(SEGV_ACCERR), "SEGV_ACCERR" },
 { (unsigned)(SEGV_BNDERR), "SEGV_BNDERR" },
 { (unsigned)(SEGV_PKUERR), "SEGV_PKUERR" },
 { (unsigned)(SEGV_ACCADI), "SEGV_ACCADI" },
 { (unsigned)(SEGV_ADIDERR), "SEGV_ADIDERR" },
 { (unsigned)(SEGV_ADIPERR), "SEGV_ADIPERR" },
 { (unsigned)(8), "SEGV_MTEAERR" },
 { (unsigned)(9), "SEGV_MTESERR" },
};
const struct xlat sigsegv_codes[1] = { {
 .data = sigsegv_codes_xdata,
 .size = (sizeof(sigsegv_codes_xdata) / sizeof((sigsegv_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigsegv_codes_xdata)), __typeof__(&(sigsegv_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (SEGV_MAPERR))
  | ((unsigned) (SEGV_ACCERR))
  | ((unsigned) (SEGV_BNDERR))
  | ((unsigned) (SEGV_PKUERR))
  | ((unsigned) (SEGV_ACCADI))
  | ((unsigned) (SEGV_ADIDERR))
  | ((unsigned) (SEGV_ADIPERR))
  | ((unsigned) (8))
  | ((unsigned) (9))
  ,
 .flags_strsz = 0
  + sizeof("SEGV_MAPERR")
  + sizeof("SEGV_ACCERR")
  + sizeof("SEGV_BNDERR")
  + sizeof("SEGV_PKUERR")
  + sizeof("SEGV_ACCADI")
  + sizeof("SEGV_ADIDERR")
  + sizeof("SEGV_ADIPERR")
  + sizeof("SEGV_MTEAERR")
  + sizeof("SEGV_MTESERR")
  ,
} };


static const struct xlat_data sigsys_codes_xdata[] = {
 { (unsigned)(1), "SYS_SECCOMP" },
 { (unsigned)(2), "SYS_USER_DISPATCH" },
};
const struct xlat sigsys_codes[1] = { {
 .data = sigsys_codes_xdata,
 .size = (sizeof(sigsys_codes_xdata) / sizeof((sigsys_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigsys_codes_xdata)), __typeof__(&(sigsys_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (1))
  | ((unsigned) (2))
  ,
 .flags_strsz = 0
  + sizeof("SYS_SECCOMP")
  + sizeof("SYS_USER_DISPATCH")
  ,
} };


#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((TRAP_BRKPT) == (1), "TRAP_BRKPT != 1");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((TRAP_TRACE) == (2), "TRAP_TRACE != 2");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((TRAP_BRANCH) == (3), "TRAP_BRANCH != 3");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((TRAP_HWBKPT) == (4), "TRAP_HWBKPT != 4");

#pragma GCC diagnostic pop
;

#pragma GCC diagnostic push
;
#pragma GCC diagnostic ignored "-Wtautological-compare"
 ;
_Static_assert((TRAP_UNK) == (5), "TRAP_UNK != 5");

#pragma GCC diagnostic pop
;

static const struct xlat_data sigtrap_codes_xdata[] = {
 { (unsigned)(TRAP_BRKPT), "TRAP_BRKPT" },
 { (unsigned)(TRAP_TRACE), "TRAP_TRACE" },
 { (unsigned)(TRAP_BRANCH), "TRAP_BRANCH" },
 { (unsigned)(TRAP_HWBKPT), "TRAP_HWBKPT" },
 { (unsigned)(TRAP_UNK), "TRAP_UNK" },
 { (unsigned)(6), "TRAP_PERF" },
};
const struct xlat sigtrap_codes[1] = { {
 .data = sigtrap_codes_xdata,
 .size = (sizeof(sigtrap_codes_xdata) / sizeof((sigtrap_codes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((sigtrap_codes_xdata)), __typeof__(&(sigtrap_codes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (TRAP_BRKPT))
  | ((unsigned) (TRAP_TRACE))
  | ((unsigned) (TRAP_BRANCH))
  | ((unsigned) (TRAP_HWBKPT))
  | ((unsigned) (TRAP_UNK))
  | ((unsigned) (6))
  ,
 .flags_strsz = 0
  + sizeof("TRAP_BRKPT")
  + sizeof("TRAP_TRACE")
  + sizeof("TRAP_BRANCH")
  + sizeof("TRAP_HWBKPT")
  + sizeof("TRAP_UNK")
  + sizeof("TRAP_PERF")
  ,
} };

static void
printsigsource(struct tcb *tcp, const siginfo_t *sip)
{
 tprint_struct_next();
 do { tprints_field_name("si_pid"); printpid((tcp), (*sip)._sifields._kill.si_pid, PT_TGID); } while (0);
 tprint_struct_next();
 do { tprints_field_name("si_uid"); do { if ((sizeof((*sip)._sifields._kill.si_uid) == sizeof(char) ? (long long) (char) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(short) ? (long long) (short) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(int) ? (long long) (int) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(long) ? (long long) (long) ((*sip)._sifields._kill.si_uid) : (long long) ((*sip)._sifields._kill.si_uid)) == -1LL) tprintf_string("%lld", (sizeof(-1) == sizeof(char) ? (long long) (char) (-1) : sizeof(-1) == sizeof(short) ? (long long) (short) (-1) : sizeof(-1) == sizeof(int) ? (long long) (int) (-1) : sizeof(-1) == sizeof(long) ? (long long) (long) (-1) : (long long) (-1))); else tprintf_string("%llu", (sizeof((*sip)._sifields._kill.si_uid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._kill.si_uid) : sizeof((*sip)._sifields._kill.si_uid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._kill.si_uid) : (unsigned long long) ((*sip)._sifields._kill.si_uid))); } while (0); } while (0);
}
static void
printsigval(const siginfo_t *sip)
{
 tprint_struct_next();
 do { tprints_field_name("si_int"); tprintf_string("%lld", (sizeof((*sip)._sifields._rt.si_sigval.sival_int) == sizeof(char) ? (long long) (char) ((*sip)._sifields._rt.si_sigval.sival_int) : sizeof((*sip)._sifields._rt.si_sigval.sival_int) == sizeof(short) ? (long long) (short) ((*sip)._sifields._rt.si_sigval.sival_int) : sizeof((*sip)._sifields._rt.si_sigval.sival_int) == sizeof(int) ? (long long) (int) ((*sip)._sifields._rt.si_sigval.sival_int) : sizeof((*sip)._sifields._rt.si_sigval.sival_int) == sizeof(long) ? (long long) (long) ((*sip)._sifields._rt.si_sigval.sival_int) : (long long) ((*sip)._sifields._rt.si_sigval.sival_int))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("si_ptr"); printaddr((mpers_ptr_t) (*sip)._sifields._rt.si_sigval.sival_ptr); } while (0);
}
static void
print_si_code(const unsigned int si_code, const int si_signo)
{
 static const struct xlat * const si_codes[] = {
  [5] = sigtrap_codes,
  [17] = sigchld_codes,
  [29] = sigpoll_codes,
  [27] = sigprof_codes,
  [4] = sigill_codes,
  [8] = sigfpe_codes,
  [11] = sigsegv_codes,
  [7] = sigbus_codes,
  [31] = sigsys_codes,
 };
 const char *code = xlookup(siginfo_codes, si_code);
 if (!code && (unsigned int) si_signo < (sizeof(si_codes) / sizeof((si_codes)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((si_codes)), __typeof__(&(si_codes)[0])))]) * 0))
     && si_codes[si_signo])
  code = xlookup(si_codes[si_signo], si_code);
 print_xlat_ex(si_code, code, XLAT_STYLE_DEFAULT);
}
static void
print_si_info(struct tcb *tcp, const siginfo_t *sip)
{
 if (sip->si_errno) {
  tprint_struct_next();
  do { tprints_field_name("si_errno"); print_err((sizeof((*sip).si_errno) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip).si_errno) : sizeof((*sip).si_errno) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip).si_errno) : sizeof((*sip).si_errno) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip).si_errno) : sizeof((*sip).si_errno) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip).si_errno) : (unsigned long long) ((*sip).si_errno)), 0); } while (0);
 }
 if (((sip)->si_code <= 0)) {
  switch (sip->si_code) {
  case SI_USER:
   printsigsource(tcp, sip);
   break;
  case SI_TKILL:
   printsigsource(tcp, sip);
   break;
  case SI_TIMER:
   tprint_struct_next();
   do { tprints_field_name("si_timerid"); tprintf_string("%#llx", (sizeof((*sip)._sifields._timer.si_tid) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._timer.si_tid) : sizeof((*sip)._sifields._timer.si_tid) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._timer.si_tid) : sizeof((*sip)._sifields._timer.si_tid) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._timer.si_tid) : sizeof((*sip)._sifields._timer.si_tid) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._timer.si_tid) : (unsigned long long) ((*sip)._sifields._timer.si_tid))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("si_overrun"); tprintf_string("%lld", (sizeof((*sip)._sifields._timer.si_overrun) == sizeof(char) ? (long long) (char) ((*sip)._sifields._timer.si_overrun) : sizeof((*sip)._sifields._timer.si_overrun) == sizeof(short) ? (long long) (short) ((*sip)._sifields._timer.si_overrun) : sizeof((*sip)._sifields._timer.si_overrun) == sizeof(int) ? (long long) (int) ((*sip)._sifields._timer.si_overrun) : sizeof((*sip)._sifields._timer.si_overrun) == sizeof(long) ? (long long) (long) ((*sip)._sifields._timer.si_overrun) : (long long) ((*sip)._sifields._timer.si_overrun))); } while (0);
   printsigval(sip);
   break;
  case SI_SIGIO:
   tprint_struct_next();
   do { tprints_field_name("si_band"); tprintf_string("%lld", (sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(char) ? (long long) (char) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(short) ? (long long) (short) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(int) ? (long long) (int) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(long) ? (long long) (long) ((*sip)._sifields._sigpoll.si_band) : (long long) ((*sip)._sifields._sigpoll.si_band))); } while (0);
   tprint_struct_next();
   do { tprints_field_name("si_fd"); printfd((tcp), (*sip)._sifields._sigpoll.si_fd); } while (0);
   break;
  default:
   printsigsource(tcp, sip);
   if (sip->_sifields._rt.si_sigval.sival_ptr)
    printsigval(sip);
   break;
  }
 } else {
  switch (sip->si_signo) {
  case 17:
   printsigsource(tcp, sip);
   if (sip->si_code == CLD_EXITED) {
    tprint_struct_next();
    do { tprints_field_name("si_status"); tprintf_string("%lld", (sizeof((*sip)._sifields._sigchld.si_status) == sizeof(char) ? (long long) (char) ((*sip)._sifields._sigchld.si_status) : sizeof((*sip)._sifields._sigchld.si_status) == sizeof(short) ? (long long) (short) ((*sip)._sifields._sigchld.si_status) : sizeof((*sip)._sifields._sigchld.si_status) == sizeof(int) ? (long long) (int) ((*sip)._sifields._sigchld.si_status) : sizeof((*sip)._sifields._sigchld.si_status) == sizeof(long) ? (long long) (long) ((*sip)._sifields._sigchld.si_status) : (long long) ((*sip)._sifields._sigchld.si_status))); } while (0);
   } else {
    tprint_struct_next();
    do { tprints_field_name("si_status"); (printsignal)((*sip)._sifields._sigchld.si_status); } while (0);
   }
   tprint_struct_next();
   do { tprints_field_name("si_utime"); print_clock_t((*sip)._sifields._sigchld.si_utime); } while (0);
   tprint_struct_next();
   do { tprints_field_name("si_stime"); print_clock_t((*sip)._sifields._sigchld.si_stime); } while (0);
   break;
  case 4:
   tprint_struct_next();
   do { tprints_field_name("si_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault.si_addr); } while (0);
   break;
  case 8:
   tprint_struct_next();
   do { tprints_field_name("si_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault.si_addr); } while (0);
   break;
  case 7:
   tprint_struct_next();
   do { tprints_field_name("si_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault.si_addr); } while (0);
   switch (sip->si_code) {
   case BUS_MCEERR_AR:
   case BUS_MCEERR_AO:
    tprint_struct_next();
    do { tprints_field_name("si_addr_lsb"); tprintf_string("%#llx", (sizeof((*sip)._sifields._sigfault.si_addr_lsb) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._sigfault.si_addr_lsb) : sizeof((*sip)._sifields._sigfault.si_addr_lsb) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._sigfault.si_addr_lsb) : sizeof((*sip)._sifields._sigfault.si_addr_lsb) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._sigfault.si_addr_lsb) : sizeof((*sip)._sifields._sigfault.si_addr_lsb) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._sigfault.si_addr_lsb) : (unsigned long long) ((*sip)._sifields._sigfault.si_addr_lsb))); } while (0);
    break;
   }
   break;
  case 11:
   tprint_struct_next();
   do { tprints_field_name("si_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault.si_addr); } while (0);
   switch (sip->si_code) {
   case SEGV_BNDERR:
    tprint_struct_next();
    do { tprints_field_name("si_lower"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault._bounds._addr_bnd._lower); } while (0);
    tprint_struct_next();
    do { tprints_field_name("si_upper"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault._bounds._addr_bnd._upper); } while (0);
    break;
   case SEGV_PKUERR:
    tprint_struct_next();
    do { tprints_field_name("si_pkey"); tprintf_string("%llu", (sizeof((*sip)._sifields._sigfault._bounds._pkey) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._sigfault._bounds._pkey) : sizeof((*sip)._sifields._sigfault._bounds._pkey) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._sigfault._bounds._pkey) : sizeof((*sip)._sifields._sigfault._bounds._pkey) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._sigfault._bounds._pkey) : sizeof((*sip)._sifields._sigfault._bounds._pkey) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._sigfault._bounds._pkey) : (unsigned long long) ((*sip)._sifields._sigfault._bounds._pkey))); } while (0);
    break;
   }
   break;
  case 5:
   tprint_struct_next();
   do { tprints_field_name("si_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigfault.si_addr); } while (0);
   break;
  case 29:
   switch (sip->si_code) {
   case POLL_IN: case POLL_OUT: case POLL_MSG:
   case POLL_ERR: case POLL_PRI: case POLL_HUP:
    tprint_struct_next();
    do { tprints_field_name("si_band"); tprintf_string("%lld", (sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(char) ? (long long) (char) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(short) ? (long long) (short) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(int) ? (long long) (int) ((*sip)._sifields._sigpoll.si_band) : sizeof((*sip)._sifields._sigpoll.si_band) == sizeof(long) ? (long long) (long) ((*sip)._sifields._sigpoll.si_band) : (long long) ((*sip)._sifields._sigpoll.si_band))); } while (0);
    tprint_struct_next();
    do { tprints_field_name("si_fd"); printfd((tcp), (*sip)._sifields._sigpoll.si_fd); } while (0);
    break;
   }
   break;
  case 31:
   tprint_struct_next();
   do { tprints_field_name("si_call_addr"); printaddr((mpers_ptr_t) (*sip)._sifields._sigsys._call_addr); } while (0);
   tprint_struct_next();
   do { tprints_field_name("si_syscall"); const char *nr_prefix_ = ((void *)0); const char *name = syscall_name_arch((*sip)._sifields._sigsys._syscall, (sip->_sifields._sigsys._arch), &nr_prefix_); if (((xlat_verbosity) & ((1 << 2) - 1)) != XLAT_STYLE_ABBREV || !nr_prefix_) tprintf_string("%llu", (sizeof((*sip)._sifields._sigsys._syscall) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._sigsys._syscall) : sizeof((*sip)._sifields._sigsys._syscall) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._sigsys._syscall) : sizeof((*sip)._sifields._sigsys._syscall) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._sigsys._syscall) : sizeof((*sip)._sifields._sigsys._syscall) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._sigsys._syscall) : (unsigned long long) ((*sip)._sifields._sigsys._syscall))); if (((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_RAW || !name) break; if (!nr_prefix_ || ((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_VERBOSE) tprint_comment_begin(); if (nr_prefix_) tprints_string(nr_prefix_); tprints_string(name); if (!nr_prefix_ || ((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_VERBOSE) tprint_comment_end(); } while (0);
   tprint_struct_next();
   do { tprints_field_name("si_arch"); printxval64((audit_arch), (sizeof((*sip)._sifields._sigsys._arch) == sizeof(char) ? (unsigned long long) (unsigned char) ((*sip)._sifields._sigsys._arch) : sizeof((*sip)._sifields._sigsys._arch) == sizeof(short) ? (unsigned long long) (unsigned short) ((*sip)._sifields._sigsys._arch) : sizeof((*sip)._sifields._sigsys._arch) == sizeof(int) ? (unsigned long long) (unsigned int) ((*sip)._sifields._sigsys._arch) : sizeof((*sip)._sifields._sigsys._arch) == sizeof(long) ? (unsigned long long) (unsigned long) ((*sip)._sifields._sigsys._arch) : (unsigned long long) ((*sip)._sifields._sigsys._arch)), ("AUDIT_ARCH_???")); } while (0);
   break;
  default:
   if (sip->_sifields._kill.si_pid || sip->_sifields._kill.si_uid)
    printsigsource(tcp, sip);
   if (sip->_sifields._rt.si_sigval.sival_ptr)
    printsigval(sip);
  }
 }
}
void
printsiginfo(struct tcb *tcp, const siginfo_t *sip)
{
 tprint_struct_begin();
 if (sip->si_signo) {
  do { tprints_field_name("si_signo"); (printsignal)((*sip).si_signo); } while (0);
  tprint_struct_next();
  do { tprints_field_name("si_code"); (print_si_code)((*sip).si_code, sip->si_signo); } while (0);
   print_si_info(tcp, sip);
 }
 tprint_struct_end();
}
MPERS_PRINTER_DECL(void, printsiginfo_at, struct tcb *const tcp, const kernel_ulong_t addr)
{
 siginfo_t si;
 if (!umoven_or_printaddr((tcp), (addr), sizeof(*(&si)), (void *) (&si)))
  printsiginfo(tcp, &si);
}
static _Bool
print_siginfo_t(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
 printsiginfo(tcp, (const siginfo_t *) elem_buf);
 return 1;
}
MPERS_PRINTER_DECL(void, print_siginfo_array, struct tcb *const tcp, const kernel_ulong_t addr, const kernel_ulong_t len)
{
 siginfo_t si;
 print_array(tcp, addr, len, &si, sizeof(si),
      tfetch_mem, print_siginfo_t, 0);
}

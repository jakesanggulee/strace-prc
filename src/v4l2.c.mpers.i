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
 unsigned long start_prc;
 char pre_comm[16];
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
struct v4l2_edid {
 __u32 pad;
 __u32 start_block;
 __u32 blocks;
 __u32 reserved[5];
 __u8 *edid;
};
enum v4l2_power_line_frequency {
 V4L2_CID_POWER_LINE_FREQUENCY_DISABLED = 0,
 V4L2_CID_POWER_LINE_FREQUENCY_50HZ = 1,
 V4L2_CID_POWER_LINE_FREQUENCY_60HZ = 2,
 V4L2_CID_POWER_LINE_FREQUENCY_AUTO = 3,
};
enum v4l2_colorfx {
 V4L2_COLORFX_NONE = 0,
 V4L2_COLORFX_BW = 1,
 V4L2_COLORFX_SEPIA = 2,
 V4L2_COLORFX_NEGATIVE = 3,
 V4L2_COLORFX_EMBOSS = 4,
 V4L2_COLORFX_SKETCH = 5,
 V4L2_COLORFX_SKY_BLUE = 6,
 V4L2_COLORFX_GRASS_GREEN = 7,
 V4L2_COLORFX_SKIN_WHITEN = 8,
 V4L2_COLORFX_VIVID = 9,
 V4L2_COLORFX_AQUA = 10,
 V4L2_COLORFX_ART_FREEZE = 11,
 V4L2_COLORFX_SILHOUETTE = 12,
 V4L2_COLORFX_SOLARIZATION = 13,
 V4L2_COLORFX_ANTIQUE = 14,
 V4L2_COLORFX_SET_CBCR = 15,
 V4L2_COLORFX_SET_RGB = 16,
};
enum v4l2_mpeg_stream_type {
 V4L2_MPEG_STREAM_TYPE_MPEG2_PS = 0,
 V4L2_MPEG_STREAM_TYPE_MPEG2_TS = 1,
 V4L2_MPEG_STREAM_TYPE_MPEG1_SS = 2,
 V4L2_MPEG_STREAM_TYPE_MPEG2_DVD = 3,
 V4L2_MPEG_STREAM_TYPE_MPEG1_VCD = 4,
 V4L2_MPEG_STREAM_TYPE_MPEG2_SVCD = 5,
};
enum v4l2_mpeg_stream_vbi_fmt {
 V4L2_MPEG_STREAM_VBI_FMT_NONE = 0,
 V4L2_MPEG_STREAM_VBI_FMT_IVTV = 1,
};
enum v4l2_mpeg_audio_sampling_freq {
 V4L2_MPEG_AUDIO_SAMPLING_FREQ_44100 = 0,
 V4L2_MPEG_AUDIO_SAMPLING_FREQ_48000 = 1,
 V4L2_MPEG_AUDIO_SAMPLING_FREQ_32000 = 2,
};
enum v4l2_mpeg_audio_encoding {
 V4L2_MPEG_AUDIO_ENCODING_LAYER_1 = 0,
 V4L2_MPEG_AUDIO_ENCODING_LAYER_2 = 1,
 V4L2_MPEG_AUDIO_ENCODING_LAYER_3 = 2,
 V4L2_MPEG_AUDIO_ENCODING_AAC = 3,
 V4L2_MPEG_AUDIO_ENCODING_AC3 = 4,
};
enum v4l2_mpeg_audio_l1_bitrate {
 V4L2_MPEG_AUDIO_L1_BITRATE_32K = 0,
 V4L2_MPEG_AUDIO_L1_BITRATE_64K = 1,
 V4L2_MPEG_AUDIO_L1_BITRATE_96K = 2,
 V4L2_MPEG_AUDIO_L1_BITRATE_128K = 3,
 V4L2_MPEG_AUDIO_L1_BITRATE_160K = 4,
 V4L2_MPEG_AUDIO_L1_BITRATE_192K = 5,
 V4L2_MPEG_AUDIO_L1_BITRATE_224K = 6,
 V4L2_MPEG_AUDIO_L1_BITRATE_256K = 7,
 V4L2_MPEG_AUDIO_L1_BITRATE_288K = 8,
 V4L2_MPEG_AUDIO_L1_BITRATE_320K = 9,
 V4L2_MPEG_AUDIO_L1_BITRATE_352K = 10,
 V4L2_MPEG_AUDIO_L1_BITRATE_384K = 11,
 V4L2_MPEG_AUDIO_L1_BITRATE_416K = 12,
 V4L2_MPEG_AUDIO_L1_BITRATE_448K = 13,
};
enum v4l2_mpeg_audio_l2_bitrate {
 V4L2_MPEG_AUDIO_L2_BITRATE_32K = 0,
 V4L2_MPEG_AUDIO_L2_BITRATE_48K = 1,
 V4L2_MPEG_AUDIO_L2_BITRATE_56K = 2,
 V4L2_MPEG_AUDIO_L2_BITRATE_64K = 3,
 V4L2_MPEG_AUDIO_L2_BITRATE_80K = 4,
 V4L2_MPEG_AUDIO_L2_BITRATE_96K = 5,
 V4L2_MPEG_AUDIO_L2_BITRATE_112K = 6,
 V4L2_MPEG_AUDIO_L2_BITRATE_128K = 7,
 V4L2_MPEG_AUDIO_L2_BITRATE_160K = 8,
 V4L2_MPEG_AUDIO_L2_BITRATE_192K = 9,
 V4L2_MPEG_AUDIO_L2_BITRATE_224K = 10,
 V4L2_MPEG_AUDIO_L2_BITRATE_256K = 11,
 V4L2_MPEG_AUDIO_L2_BITRATE_320K = 12,
 V4L2_MPEG_AUDIO_L2_BITRATE_384K = 13,
};
enum v4l2_mpeg_audio_l3_bitrate {
 V4L2_MPEG_AUDIO_L3_BITRATE_32K = 0,
 V4L2_MPEG_AUDIO_L3_BITRATE_40K = 1,
 V4L2_MPEG_AUDIO_L3_BITRATE_48K = 2,
 V4L2_MPEG_AUDIO_L3_BITRATE_56K = 3,
 V4L2_MPEG_AUDIO_L3_BITRATE_64K = 4,
 V4L2_MPEG_AUDIO_L3_BITRATE_80K = 5,
 V4L2_MPEG_AUDIO_L3_BITRATE_96K = 6,
 V4L2_MPEG_AUDIO_L3_BITRATE_112K = 7,
 V4L2_MPEG_AUDIO_L3_BITRATE_128K = 8,
 V4L2_MPEG_AUDIO_L3_BITRATE_160K = 9,
 V4L2_MPEG_AUDIO_L3_BITRATE_192K = 10,
 V4L2_MPEG_AUDIO_L3_BITRATE_224K = 11,
 V4L2_MPEG_AUDIO_L3_BITRATE_256K = 12,
 V4L2_MPEG_AUDIO_L3_BITRATE_320K = 13,
};
enum v4l2_mpeg_audio_mode {
 V4L2_MPEG_AUDIO_MODE_STEREO = 0,
 V4L2_MPEG_AUDIO_MODE_JOINT_STEREO = 1,
 V4L2_MPEG_AUDIO_MODE_DUAL = 2,
 V4L2_MPEG_AUDIO_MODE_MONO = 3,
};
enum v4l2_mpeg_audio_mode_extension {
 V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_4 = 0,
 V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_8 = 1,
 V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_12 = 2,
 V4L2_MPEG_AUDIO_MODE_EXTENSION_BOUND_16 = 3,
};
enum v4l2_mpeg_audio_emphasis {
 V4L2_MPEG_AUDIO_EMPHASIS_NONE = 0,
 V4L2_MPEG_AUDIO_EMPHASIS_50_DIV_15_uS = 1,
 V4L2_MPEG_AUDIO_EMPHASIS_CCITT_J17 = 2,
};
enum v4l2_mpeg_audio_crc {
 V4L2_MPEG_AUDIO_CRC_NONE = 0,
 V4L2_MPEG_AUDIO_CRC_CRC16 = 1,
};
enum v4l2_mpeg_audio_ac3_bitrate {
 V4L2_MPEG_AUDIO_AC3_BITRATE_32K = 0,
 V4L2_MPEG_AUDIO_AC3_BITRATE_40K = 1,
 V4L2_MPEG_AUDIO_AC3_BITRATE_48K = 2,
 V4L2_MPEG_AUDIO_AC3_BITRATE_56K = 3,
 V4L2_MPEG_AUDIO_AC3_BITRATE_64K = 4,
 V4L2_MPEG_AUDIO_AC3_BITRATE_80K = 5,
 V4L2_MPEG_AUDIO_AC3_BITRATE_96K = 6,
 V4L2_MPEG_AUDIO_AC3_BITRATE_112K = 7,
 V4L2_MPEG_AUDIO_AC3_BITRATE_128K = 8,
 V4L2_MPEG_AUDIO_AC3_BITRATE_160K = 9,
 V4L2_MPEG_AUDIO_AC3_BITRATE_192K = 10,
 V4L2_MPEG_AUDIO_AC3_BITRATE_224K = 11,
 V4L2_MPEG_AUDIO_AC3_BITRATE_256K = 12,
 V4L2_MPEG_AUDIO_AC3_BITRATE_320K = 13,
 V4L2_MPEG_AUDIO_AC3_BITRATE_384K = 14,
 V4L2_MPEG_AUDIO_AC3_BITRATE_448K = 15,
 V4L2_MPEG_AUDIO_AC3_BITRATE_512K = 16,
 V4L2_MPEG_AUDIO_AC3_BITRATE_576K = 17,
 V4L2_MPEG_AUDIO_AC3_BITRATE_640K = 18,
};
enum v4l2_mpeg_audio_dec_playback {
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_AUTO = 0,
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_STEREO = 1,
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_LEFT = 2,
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_RIGHT = 3,
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_MONO = 4,
 V4L2_MPEG_AUDIO_DEC_PLAYBACK_SWAPPED_STEREO = 5,
};
enum v4l2_mpeg_video_encoding {
 V4L2_MPEG_VIDEO_ENCODING_MPEG_1 = 0,
 V4L2_MPEG_VIDEO_ENCODING_MPEG_2 = 1,
 V4L2_MPEG_VIDEO_ENCODING_MPEG_4_AVC = 2,
};
enum v4l2_mpeg_video_aspect {
 V4L2_MPEG_VIDEO_ASPECT_1x1 = 0,
 V4L2_MPEG_VIDEO_ASPECT_4x3 = 1,
 V4L2_MPEG_VIDEO_ASPECT_16x9 = 2,
 V4L2_MPEG_VIDEO_ASPECT_221x100 = 3,
};
enum v4l2_mpeg_video_bitrate_mode {
 V4L2_MPEG_VIDEO_BITRATE_MODE_VBR = 0,
 V4L2_MPEG_VIDEO_BITRATE_MODE_CBR = 1,
 V4L2_MPEG_VIDEO_BITRATE_MODE_CQ = 2,
};
enum v4l2_mpeg_video_header_mode {
 V4L2_MPEG_VIDEO_HEADER_MODE_SEPARATE = 0,
 V4L2_MPEG_VIDEO_HEADER_MODE_JOINED_WITH_1ST_FRAME = 1,
};
enum v4l2_mpeg_video_multi_slice_mode {
 V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_SINGLE = 0,
 V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_MB = 1,
 V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_BYTES = 2,
 V4L2_MPEG_VIDEO_MULTI_SICE_MODE_MAX_MB = 1,
 V4L2_MPEG_VIDEO_MULTI_SICE_MODE_MAX_BYTES = 2,
};
enum v4l2_mpeg_video_intra_refresh_period_type {
 V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE_RANDOM = 0,
 V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE_CYCLIC = 1,
};
enum v4l2_mpeg_video_mpeg2_level {
 V4L2_MPEG_VIDEO_MPEG2_LEVEL_LOW = 0,
 V4L2_MPEG_VIDEO_MPEG2_LEVEL_MAIN = 1,
 V4L2_MPEG_VIDEO_MPEG2_LEVEL_HIGH_1440 = 2,
 V4L2_MPEG_VIDEO_MPEG2_LEVEL_HIGH = 3,
};
enum v4l2_mpeg_video_mpeg2_profile {
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_SIMPLE = 0,
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_MAIN = 1,
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_SNR_SCALABLE = 2,
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_SPATIALLY_SCALABLE = 3,
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_HIGH = 4,
 V4L2_MPEG_VIDEO_MPEG2_PROFILE_MULTIVIEW = 5,
};
enum v4l2_mpeg_video_h264_entropy_mode {
 V4L2_MPEG_VIDEO_H264_ENTROPY_MODE_CAVLC = 0,
 V4L2_MPEG_VIDEO_H264_ENTROPY_MODE_CABAC = 1,
};
enum v4l2_mpeg_video_h264_level {
 V4L2_MPEG_VIDEO_H264_LEVEL_1_0 = 0,
 V4L2_MPEG_VIDEO_H264_LEVEL_1B = 1,
 V4L2_MPEG_VIDEO_H264_LEVEL_1_1 = 2,
 V4L2_MPEG_VIDEO_H264_LEVEL_1_2 = 3,
 V4L2_MPEG_VIDEO_H264_LEVEL_1_3 = 4,
 V4L2_MPEG_VIDEO_H264_LEVEL_2_0 = 5,
 V4L2_MPEG_VIDEO_H264_LEVEL_2_1 = 6,
 V4L2_MPEG_VIDEO_H264_LEVEL_2_2 = 7,
 V4L2_MPEG_VIDEO_H264_LEVEL_3_0 = 8,
 V4L2_MPEG_VIDEO_H264_LEVEL_3_1 = 9,
 V4L2_MPEG_VIDEO_H264_LEVEL_3_2 = 10,
 V4L2_MPEG_VIDEO_H264_LEVEL_4_0 = 11,
 V4L2_MPEG_VIDEO_H264_LEVEL_4_1 = 12,
 V4L2_MPEG_VIDEO_H264_LEVEL_4_2 = 13,
 V4L2_MPEG_VIDEO_H264_LEVEL_5_0 = 14,
 V4L2_MPEG_VIDEO_H264_LEVEL_5_1 = 15,
 V4L2_MPEG_VIDEO_H264_LEVEL_5_2 = 16,
 V4L2_MPEG_VIDEO_H264_LEVEL_6_0 = 17,
 V4L2_MPEG_VIDEO_H264_LEVEL_6_1 = 18,
 V4L2_MPEG_VIDEO_H264_LEVEL_6_2 = 19,
};
enum v4l2_mpeg_video_h264_loop_filter_mode {
 V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_ENABLED = 0,
 V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_DISABLED = 1,
 V4L2_MPEG_VIDEO_H264_LOOP_FILTER_MODE_DISABLED_AT_SLICE_BOUNDARY = 2,
};
enum v4l2_mpeg_video_h264_profile {
 V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE = 0,
 V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE = 1,
 V4L2_MPEG_VIDEO_H264_PROFILE_MAIN = 2,
 V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED = 3,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH = 4,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10 = 5,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422 = 6,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE = 7,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA = 8,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA = 9,
 V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA = 10,
 V4L2_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA = 11,
 V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE = 12,
 V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH = 13,
 V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA = 14,
 V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH = 15,
 V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH = 16,
 V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_HIGH = 17,
};
enum v4l2_mpeg_video_h264_vui_sar_idc {
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_UNSPECIFIED = 0,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_1x1 = 1,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_12x11 = 2,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_10x11 = 3,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_16x11 = 4,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_40x33 = 5,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_24x11 = 6,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_20x11 = 7,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_32x11 = 8,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_80x33 = 9,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_18x11 = 10,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_15x11 = 11,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_64x33 = 12,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_160x99 = 13,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_4x3 = 14,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_3x2 = 15,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_2x1 = 16,
 V4L2_MPEG_VIDEO_H264_VUI_SAR_IDC_EXTENDED = 17,
};
enum v4l2_mpeg_video_h264_sei_fp_arrangement_type {
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_CHECKERBOARD = 0,
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_COLUMN = 1,
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_ROW = 2,
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_SIDE_BY_SIDE = 3,
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_TOP_BOTTOM = 4,
 V4L2_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE_TEMPORAL = 5,
};
enum v4l2_mpeg_video_h264_fmo_map_type {
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_INTERLEAVED_SLICES = 0,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_SCATTERED_SLICES = 1,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_FOREGROUND_WITH_LEFT_OVER = 2,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_BOX_OUT = 3,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_RASTER_SCAN = 4,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_WIPE_SCAN = 5,
 V4L2_MPEG_VIDEO_H264_FMO_MAP_TYPE_EXPLICIT = 6,
};
enum v4l2_mpeg_video_h264_fmo_change_dir {
 V4L2_MPEG_VIDEO_H264_FMO_CHANGE_DIR_RIGHT = 0,
 V4L2_MPEG_VIDEO_H264_FMO_CHANGE_DIR_LEFT = 1,
};
enum v4l2_mpeg_video_h264_hierarchical_coding_type {
 V4L2_MPEG_VIDEO_H264_HIERARCHICAL_CODING_B = 0,
 V4L2_MPEG_VIDEO_H264_HIERARCHICAL_CODING_P = 1,
};
enum v4l2_mpeg_video_mpeg4_level {
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_0 = 0,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_0B = 1,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_1 = 2,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_2 = 3,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_3 = 4,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_3B = 5,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_4 = 6,
 V4L2_MPEG_VIDEO_MPEG4_LEVEL_5 = 7,
};
enum v4l2_mpeg_video_mpeg4_profile {
 V4L2_MPEG_VIDEO_MPEG4_PROFILE_SIMPLE = 0,
 V4L2_MPEG_VIDEO_MPEG4_PROFILE_ADVANCED_SIMPLE = 1,
 V4L2_MPEG_VIDEO_MPEG4_PROFILE_CORE = 2,
 V4L2_MPEG_VIDEO_MPEG4_PROFILE_SIMPLE_SCALABLE = 3,
 V4L2_MPEG_VIDEO_MPEG4_PROFILE_ADVANCED_CODING_EFFICIENCY = 4,
};
enum v4l2_vp8_num_partitions {
 V4L2_CID_MPEG_VIDEO_VPX_1_PARTITION = 0,
 V4L2_CID_MPEG_VIDEO_VPX_2_PARTITIONS = 1,
 V4L2_CID_MPEG_VIDEO_VPX_4_PARTITIONS = 2,
 V4L2_CID_MPEG_VIDEO_VPX_8_PARTITIONS = 3,
};
enum v4l2_vp8_num_ref_frames {
 V4L2_CID_MPEG_VIDEO_VPX_1_REF_FRAME = 0,
 V4L2_CID_MPEG_VIDEO_VPX_2_REF_FRAME = 1,
 V4L2_CID_MPEG_VIDEO_VPX_3_REF_FRAME = 2,
};
enum v4l2_vp8_golden_frame_sel {
 V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_USE_PREV = 0,
 V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_USE_REF_PERIOD = 1,
};
enum v4l2_mpeg_video_vp8_profile {
 V4L2_MPEG_VIDEO_VP8_PROFILE_0 = 0,
 V4L2_MPEG_VIDEO_VP8_PROFILE_1 = 1,
 V4L2_MPEG_VIDEO_VP8_PROFILE_2 = 2,
 V4L2_MPEG_VIDEO_VP8_PROFILE_3 = 3,
};
enum v4l2_mpeg_video_vp9_profile {
 V4L2_MPEG_VIDEO_VP9_PROFILE_0 = 0,
 V4L2_MPEG_VIDEO_VP9_PROFILE_1 = 1,
 V4L2_MPEG_VIDEO_VP9_PROFILE_2 = 2,
 V4L2_MPEG_VIDEO_VP9_PROFILE_3 = 3,
};
enum v4l2_mpeg_video_vp9_level {
 V4L2_MPEG_VIDEO_VP9_LEVEL_1_0 = 0,
 V4L2_MPEG_VIDEO_VP9_LEVEL_1_1 = 1,
 V4L2_MPEG_VIDEO_VP9_LEVEL_2_0 = 2,
 V4L2_MPEG_VIDEO_VP9_LEVEL_2_1 = 3,
 V4L2_MPEG_VIDEO_VP9_LEVEL_3_0 = 4,
 V4L2_MPEG_VIDEO_VP9_LEVEL_3_1 = 5,
 V4L2_MPEG_VIDEO_VP9_LEVEL_4_0 = 6,
 V4L2_MPEG_VIDEO_VP9_LEVEL_4_1 = 7,
 V4L2_MPEG_VIDEO_VP9_LEVEL_5_0 = 8,
 V4L2_MPEG_VIDEO_VP9_LEVEL_5_1 = 9,
 V4L2_MPEG_VIDEO_VP9_LEVEL_5_2 = 10,
 V4L2_MPEG_VIDEO_VP9_LEVEL_6_0 = 11,
 V4L2_MPEG_VIDEO_VP9_LEVEL_6_1 = 12,
 V4L2_MPEG_VIDEO_VP9_LEVEL_6_2 = 13,
};
enum v4l2_mpeg_video_hevc_hier_coding_type {
 V4L2_MPEG_VIDEO_HEVC_HIERARCHICAL_CODING_B = 0,
 V4L2_MPEG_VIDEO_HEVC_HIERARCHICAL_CODING_P = 1,
};
enum v4l2_mpeg_video_hevc_profile {
 V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN = 0,
 V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_STILL_PICTURE = 1,
 V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10 = 2,
};
enum v4l2_mpeg_video_hevc_level {
 V4L2_MPEG_VIDEO_HEVC_LEVEL_1 = 0,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_2 = 1,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_2_1 = 2,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_3 = 3,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_3_1 = 4,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_4 = 5,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_4_1 = 6,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_5 = 7,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_5_1 = 8,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_5_2 = 9,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_6 = 10,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_6_1 = 11,
 V4L2_MPEG_VIDEO_HEVC_LEVEL_6_2 = 12,
};
enum v4l2_mpeg_video_hevc_tier {
 V4L2_MPEG_VIDEO_HEVC_TIER_MAIN = 0,
 V4L2_MPEG_VIDEO_HEVC_TIER_HIGH = 1,
};
enum v4l2_cid_mpeg_video_hevc_loop_filter_mode {
 V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_DISABLED = 0,
 V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_ENABLED = 1,
 V4L2_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE_DISABLED_AT_SLICE_BOUNDARY = 2,
};
enum v4l2_cid_mpeg_video_hevc_refresh_type {
 V4L2_MPEG_VIDEO_HEVC_REFRESH_NONE = 0,
 V4L2_MPEG_VIDEO_HEVC_REFRESH_CRA = 1,
 V4L2_MPEG_VIDEO_HEVC_REFRESH_IDR = 2,
};
enum v4l2_cid_mpeg_video_hevc_size_of_length_field {
 V4L2_MPEG_VIDEO_HEVC_SIZE_0 = 0,
 V4L2_MPEG_VIDEO_HEVC_SIZE_1 = 1,
 V4L2_MPEG_VIDEO_HEVC_SIZE_2 = 2,
 V4L2_MPEG_VIDEO_HEVC_SIZE_4 = 3,
};
enum v4l2_mpeg_video_frame_skip_mode {
 V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_DISABLED = 0,
 V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_LEVEL_LIMIT = 1,
 V4L2_MPEG_VIDEO_FRAME_SKIP_MODE_BUF_LIMIT = 2,
};
enum v4l2_mpeg_cx2341x_video_spatial_filter_mode {
 V4L2_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE_MANUAL = 0,
 V4L2_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE_AUTO = 1,
};
enum v4l2_mpeg_cx2341x_video_luma_spatial_filter_type {
 V4L2_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE_OFF = 0,
 V4L2_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE_1D_HOR = 1,
 V4L2_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE_1D_VERT = 2,
 V4L2_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE_2D_HV_SEPARABLE = 3,
 V4L2_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE_2D_SYM_NON_SEPARABLE = 4,
};
enum v4l2_mpeg_cx2341x_video_chroma_spatial_filter_type {
 V4L2_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE_OFF = 0,
 V4L2_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE_1D_HOR = 1,
};
enum v4l2_mpeg_cx2341x_video_temporal_filter_mode {
 V4L2_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE_MANUAL = 0,
 V4L2_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE_AUTO = 1,
};
enum v4l2_mpeg_cx2341x_video_median_filter_type {
 V4L2_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE_OFF = 0,
 V4L2_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE_HOR = 1,
 V4L2_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE_VERT = 2,
 V4L2_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE_HOR_VERT = 3,
 V4L2_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE_DIAG = 4,
};
enum v4l2_mpeg_mfc51_video_frame_skip_mode {
 V4L2_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE_DISABLED = 0,
 V4L2_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE_LEVEL_LIMIT = 1,
 V4L2_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE_BUF_LIMIT = 2,
};
enum v4l2_mpeg_mfc51_video_force_frame_type {
 V4L2_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE_DISABLED = 0,
 V4L2_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE_I_FRAME = 1,
 V4L2_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE_NOT_CODED = 2,
};
enum v4l2_exposure_auto_type {
 V4L2_EXPOSURE_AUTO = 0,
 V4L2_EXPOSURE_MANUAL = 1,
 V4L2_EXPOSURE_SHUTTER_PRIORITY = 2,
 V4L2_EXPOSURE_APERTURE_PRIORITY = 3
};
enum v4l2_auto_n_preset_white_balance {
 V4L2_WHITE_BALANCE_MANUAL = 0,
 V4L2_WHITE_BALANCE_AUTO = 1,
 V4L2_WHITE_BALANCE_INCANDESCENT = 2,
 V4L2_WHITE_BALANCE_FLUORESCENT = 3,
 V4L2_WHITE_BALANCE_FLUORESCENT_H = 4,
 V4L2_WHITE_BALANCE_HORIZON = 5,
 V4L2_WHITE_BALANCE_DAYLIGHT = 6,
 V4L2_WHITE_BALANCE_FLASH = 7,
 V4L2_WHITE_BALANCE_CLOUDY = 8,
 V4L2_WHITE_BALANCE_SHADE = 9,
};
enum v4l2_iso_sensitivity_auto_type {
 V4L2_ISO_SENSITIVITY_MANUAL = 0,
 V4L2_ISO_SENSITIVITY_AUTO = 1,
};
enum v4l2_exposure_metering {
 V4L2_EXPOSURE_METERING_AVERAGE = 0,
 V4L2_EXPOSURE_METERING_CENTER_WEIGHTED = 1,
 V4L2_EXPOSURE_METERING_SPOT = 2,
 V4L2_EXPOSURE_METERING_MATRIX = 3,
};
enum v4l2_scene_mode {
 V4L2_SCENE_MODE_NONE = 0,
 V4L2_SCENE_MODE_BACKLIGHT = 1,
 V4L2_SCENE_MODE_BEACH_SNOW = 2,
 V4L2_SCENE_MODE_CANDLE_LIGHT = 3,
 V4L2_SCENE_MODE_DAWN_DUSK = 4,
 V4L2_SCENE_MODE_FALL_COLORS = 5,
 V4L2_SCENE_MODE_FIREWORKS = 6,
 V4L2_SCENE_MODE_LANDSCAPE = 7,
 V4L2_SCENE_MODE_NIGHT = 8,
 V4L2_SCENE_MODE_PARTY_INDOOR = 9,
 V4L2_SCENE_MODE_PORTRAIT = 10,
 V4L2_SCENE_MODE_SPORTS = 11,
 V4L2_SCENE_MODE_SUNSET = 12,
 V4L2_SCENE_MODE_TEXT = 13,
};
enum v4l2_auto_focus_range {
 V4L2_AUTO_FOCUS_RANGE_AUTO = 0,
 V4L2_AUTO_FOCUS_RANGE_NORMAL = 1,
 V4L2_AUTO_FOCUS_RANGE_MACRO = 2,
 V4L2_AUTO_FOCUS_RANGE_INFINITY = 3,
};
enum v4l2_preemphasis {
 V4L2_PREEMPHASIS_DISABLED = 0,
 V4L2_PREEMPHASIS_50_uS = 1,
 V4L2_PREEMPHASIS_75_uS = 2,
};
enum v4l2_flash_led_mode {
 V4L2_FLASH_LED_MODE_NONE,
 V4L2_FLASH_LED_MODE_FLASH,
 V4L2_FLASH_LED_MODE_TORCH,
};
enum v4l2_flash_strobe_source {
 V4L2_FLASH_STROBE_SOURCE_SOFTWARE,
 V4L2_FLASH_STROBE_SOURCE_EXTERNAL,
};
enum v4l2_jpeg_chroma_subsampling {
 V4L2_JPEG_CHROMA_SUBSAMPLING_444 = 0,
 V4L2_JPEG_CHROMA_SUBSAMPLING_422 = 1,
 V4L2_JPEG_CHROMA_SUBSAMPLING_420 = 2,
 V4L2_JPEG_CHROMA_SUBSAMPLING_411 = 3,
 V4L2_JPEG_CHROMA_SUBSAMPLING_410 = 4,
 V4L2_JPEG_CHROMA_SUBSAMPLING_GRAY = 5,
};
enum v4l2_dv_tx_mode {
 V4L2_DV_TX_MODE_DVI_D = 0,
 V4L2_DV_TX_MODE_HDMI = 1,
};
enum v4l2_dv_rgb_range {
 V4L2_DV_RGB_RANGE_AUTO = 0,
 V4L2_DV_RGB_RANGE_LIMITED = 1,
 V4L2_DV_RGB_RANGE_FULL = 2,
};
enum v4l2_dv_it_content_type {
 V4L2_DV_IT_CONTENT_TYPE_GRAPHICS = 0,
 V4L2_DV_IT_CONTENT_TYPE_PHOTO = 1,
 V4L2_DV_IT_CONTENT_TYPE_CINEMA = 2,
 V4L2_DV_IT_CONTENT_TYPE_GAME = 3,
 V4L2_DV_IT_CONTENT_TYPE_NO_ITC = 4,
};
enum v4l2_deemphasis {
 V4L2_DEEMPHASIS_DISABLED = V4L2_PREEMPHASIS_DISABLED,
 V4L2_DEEMPHASIS_50_uS = V4L2_PREEMPHASIS_50_uS,
 V4L2_DEEMPHASIS_75_uS = V4L2_PREEMPHASIS_75_uS,
};
enum v4l2_detect_md_mode {
 V4L2_DETECT_MD_MODE_DISABLED = 0,
 V4L2_DETECT_MD_MODE_GLOBAL = 1,
 V4L2_DETECT_MD_MODE_THRESHOLD_GRID = 2,
 V4L2_DETECT_MD_MODE_REGION_GRID = 3,
};
enum v4l2_stateless_h264_decode_mode {
 V4L2_STATELESS_H264_DECODE_MODE_SLICE_BASED,
 V4L2_STATELESS_H264_DECODE_MODE_FRAME_BASED,
};
enum v4l2_stateless_h264_start_code {
 V4L2_STATELESS_H264_START_CODE_NONE,
 V4L2_STATELESS_H264_START_CODE_ANNEX_B,
};
struct v4l2_ctrl_h264_sps {
 __u8 profile_idc;
 __u8 constraint_set_flags;
 __u8 level_idc;
 __u8 seq_parameter_set_id;
 __u8 chroma_format_idc;
 __u8 bit_depth_luma_minus8;
 __u8 bit_depth_chroma_minus8;
 __u8 log2_max_frame_num_minus4;
 __u8 pic_order_cnt_type;
 __u8 log2_max_pic_order_cnt_lsb_minus4;
 __u8 max_num_ref_frames;
 __u8 num_ref_frames_in_pic_order_cnt_cycle;
 __s32 offset_for_ref_frame[255];
 __s32 offset_for_non_ref_pic;
 __s32 offset_for_top_to_bottom_field;
 __u16 pic_width_in_mbs_minus1;
 __u16 pic_height_in_map_units_minus1;
 __u32 flags;
};
struct v4l2_ctrl_h264_pps {
 __u8 pic_parameter_set_id;
 __u8 seq_parameter_set_id;
 __u8 num_slice_groups_minus1;
 __u8 num_ref_idx_l0_default_active_minus1;
 __u8 num_ref_idx_l1_default_active_minus1;
 __u8 weighted_bipred_idc;
 __s8 pic_init_qp_minus26;
 __s8 pic_init_qs_minus26;
 __s8 chroma_qp_index_offset;
 __s8 second_chroma_qp_index_offset;
 __u16 flags;
};
struct v4l2_ctrl_h264_scaling_matrix {
 __u8 scaling_list_4x4[6][16];
 __u8 scaling_list_8x8[6][64];
};
struct v4l2_h264_weight_factors {
 __s16 luma_weight[32];
 __s16 luma_offset[32];
 __s16 chroma_weight[32][2];
 __s16 chroma_offset[32][2];
};
struct v4l2_ctrl_h264_pred_weights {
 __u16 luma_log2_weight_denom;
 __u16 chroma_log2_weight_denom;
 struct v4l2_h264_weight_factors weight_factors[2];
};
struct v4l2_h264_reference {
 __u8 fields;
 __u8 index;
};
struct v4l2_ctrl_h264_slice_params {
 __u32 header_bit_size;
 __u32 first_mb_in_slice;
 __u8 slice_type;
 __u8 colour_plane_id;
 __u8 redundant_pic_cnt;
 __u8 cabac_init_idc;
 __s8 slice_qp_delta;
 __s8 slice_qs_delta;
 __u8 disable_deblocking_filter_idc;
 __s8 slice_alpha_c0_offset_div2;
 __s8 slice_beta_offset_div2;
 __u8 num_ref_idx_l0_active_minus1;
 __u8 num_ref_idx_l1_active_minus1;
 __u8 reserved;
 struct v4l2_h264_reference ref_pic_list0[(2 * 16)];
 struct v4l2_h264_reference ref_pic_list1[(2 * 16)];
 __u32 flags;
};
struct v4l2_h264_dpb_entry {
 __u64 reference_ts;
 __u32 pic_num;
 __u16 frame_num;
 __u8 fields;
 __u8 reserved[5];
 __s32 top_field_order_cnt;
 __s32 bottom_field_order_cnt;
 __u32 flags;
};
struct v4l2_ctrl_h264_decode_params {
 struct v4l2_h264_dpb_entry dpb[16];
 __u16 nal_ref_idc;
 __u16 frame_num;
 __s32 top_field_order_cnt;
 __s32 bottom_field_order_cnt;
 __u16 idr_pic_id;
 __u16 pic_order_cnt_lsb;
 __s32 delta_pic_order_cnt_bottom;
 __s32 delta_pic_order_cnt0;
 __s32 delta_pic_order_cnt1;
 __u32 dec_ref_pic_marking_bit_size;
 __u32 pic_order_cnt_bit_size;
 __u32 slice_group_change_cycle;
 __u32 reserved;
 __u32 flags;
};
struct v4l2_ctrl_fwht_params {
 __u64 backward_ref_ts;
 __u32 version;
 __u32 width;
 __u32 height;
 __u32 flags;
 __u32 colorspace;
 __u32 xfer_func;
 __u32 ycbcr_enc;
 __u32 quantization;
};
struct v4l2_vp8_segment {
 __s8 quant_update[4];
 __s8 lf_update[4];
 __u8 segment_probs[3];
 __u8 padding;
 __u32 flags;
};
struct v4l2_vp8_loop_filter {
 __s8 ref_frm_delta[4];
 __s8 mb_mode_delta[4];
 __u8 sharpness_level;
 __u8 level;
 __u16 padding;
 __u32 flags;
};
struct v4l2_vp8_quantization {
 __u8 y_ac_qi;
 __s8 y_dc_delta;
 __s8 y2_dc_delta;
 __s8 y2_ac_delta;
 __s8 uv_dc_delta;
 __s8 uv_ac_delta;
 __u16 padding;
};
struct v4l2_vp8_entropy {
 __u8 coeff_probs[4][8][3][11];
 __u8 y_mode_probs[4];
 __u8 uv_mode_probs[3];
 __u8 mv_probs[2][19];
 __u8 padding[3];
};
struct v4l2_vp8_entropy_coder_state {
 __u8 range;
 __u8 value;
 __u8 bit_count;
 __u8 padding;
};
struct v4l2_ctrl_vp8_frame {
 struct v4l2_vp8_segment segment;
 struct v4l2_vp8_loop_filter lf;
 struct v4l2_vp8_quantization quant;
 struct v4l2_vp8_entropy entropy;
 struct v4l2_vp8_entropy_coder_state coder_state;
 __u16 width;
 __u16 height;
 __u8 horizontal_scale;
 __u8 vertical_scale;
 __u8 version;
 __u8 prob_skip_false;
 __u8 prob_intra;
 __u8 prob_last;
 __u8 prob_gf;
 __u8 num_dct_parts;
 __u32 first_part_size;
 __u32 first_part_header_bits;
 __u32 dct_part_sizes[8];
 __u64 last_frame_ts;
 __u64 golden_frame_ts;
 __u64 alt_frame_ts;
 __u64 flags;
};
struct v4l2_ctrl_mpeg2_sequence {
 __u16 horizontal_size;
 __u16 vertical_size;
 __u32 vbv_buffer_size;
 __u16 profile_and_level_indication;
 __u8 chroma_format;
 __u8 flags;
};
struct v4l2_ctrl_mpeg2_picture {
 __u64 backward_ref_ts;
 __u64 forward_ref_ts;
 __u32 flags;
 __u8 f_code[2][2];
 __u8 picture_coding_type;
 __u8 picture_structure;
 __u8 intra_dc_precision;
 __u8 reserved[5];
};
struct v4l2_ctrl_mpeg2_quantisation {
 __u8 intra_quantiser_matrix[64];
 __u8 non_intra_quantiser_matrix[64];
 __u8 chroma_intra_quantiser_matrix[64];
 __u8 chroma_non_intra_quantiser_matrix[64];
};
enum v4l2_stateless_hevc_decode_mode {
 V4L2_STATELESS_HEVC_DECODE_MODE_SLICE_BASED,
 V4L2_STATELESS_HEVC_DECODE_MODE_FRAME_BASED,
};
enum v4l2_stateless_hevc_start_code {
 V4L2_STATELESS_HEVC_START_CODE_NONE,
 V4L2_STATELESS_HEVC_START_CODE_ANNEX_B,
};
struct v4l2_ctrl_hevc_sps {
 __u8 video_parameter_set_id;
 __u8 seq_parameter_set_id;
 __u16 pic_width_in_luma_samples;
 __u16 pic_height_in_luma_samples;
 __u8 bit_depth_luma_minus8;
 __u8 bit_depth_chroma_minus8;
 __u8 log2_max_pic_order_cnt_lsb_minus4;
 __u8 sps_max_dec_pic_buffering_minus1;
 __u8 sps_max_num_reorder_pics;
 __u8 sps_max_latency_increase_plus1;
 __u8 log2_min_luma_coding_block_size_minus3;
 __u8 log2_diff_max_min_luma_coding_block_size;
 __u8 log2_min_luma_transform_block_size_minus2;
 __u8 log2_diff_max_min_luma_transform_block_size;
 __u8 max_transform_hierarchy_depth_inter;
 __u8 max_transform_hierarchy_depth_intra;
 __u8 pcm_sample_bit_depth_luma_minus1;
 __u8 pcm_sample_bit_depth_chroma_minus1;
 __u8 log2_min_pcm_luma_coding_block_size_minus3;
 __u8 log2_diff_max_min_pcm_luma_coding_block_size;
 __u8 num_short_term_ref_pic_sets;
 __u8 num_long_term_ref_pics_sps;
 __u8 chroma_format_idc;
 __u8 sps_max_sub_layers_minus1;
 __u8 reserved[6];
 __u64 flags;
};
struct v4l2_ctrl_hevc_pps {
 __u8 pic_parameter_set_id;
 __u8 num_extra_slice_header_bits;
 __u8 num_ref_idx_l0_default_active_minus1;
 __u8 num_ref_idx_l1_default_active_minus1;
 __s8 init_qp_minus26;
 __u8 diff_cu_qp_delta_depth;
 __s8 pps_cb_qp_offset;
 __s8 pps_cr_qp_offset;
 __u8 num_tile_columns_minus1;
 __u8 num_tile_rows_minus1;
 __u8 column_width_minus1[20];
 __u8 row_height_minus1[22];
 __s8 pps_beta_offset_div2;
 __s8 pps_tc_offset_div2;
 __u8 log2_parallel_merge_level_minus2;
 __u8 reserved;
 __u64 flags;
};
struct v4l2_hevc_dpb_entry {
 __u64 timestamp;
 __u8 flags;
 __u8 field_pic;
 __u16 reserved;
 __s32 pic_order_cnt_val;
};
struct v4l2_hevc_pred_weight_table {
 __s8 delta_luma_weight_l0[16];
 __s8 luma_offset_l0[16];
 __s8 delta_chroma_weight_l0[16][2];
 __s8 chroma_offset_l0[16][2];
 __s8 delta_luma_weight_l1[16];
 __s8 luma_offset_l1[16];
 __s8 delta_chroma_weight_l1[16][2];
 __s8 chroma_offset_l1[16][2];
 __u8 luma_log2_weight_denom;
 __s8 delta_chroma_log2_weight_denom;
};
struct v4l2_ctrl_hevc_slice_params {
 __u32 bit_size;
 __u32 data_byte_offset;
 __u32 num_entry_point_offsets;
 __u8 nal_unit_type;
 __u8 nuh_temporal_id_plus1;
 __u8 slice_type;
 __u8 colour_plane_id;
 __s32 slice_pic_order_cnt;
 __u8 num_ref_idx_l0_active_minus1;
 __u8 num_ref_idx_l1_active_minus1;
 __u8 collocated_ref_idx;
 __u8 five_minus_max_num_merge_cand;
 __s8 slice_qp_delta;
 __s8 slice_cb_qp_offset;
 __s8 slice_cr_qp_offset;
 __s8 slice_act_y_qp_offset;
 __s8 slice_act_cb_qp_offset;
 __s8 slice_act_cr_qp_offset;
 __s8 slice_beta_offset_div2;
 __s8 slice_tc_offset_div2;
 __u8 pic_struct;
 __u8 reserved0[3];
 __u32 slice_segment_addr;
 __u8 ref_idx_l0[16];
 __u8 ref_idx_l1[16];
 __u16 short_term_ref_pic_set_size;
 __u16 long_term_ref_pic_set_size;
 struct v4l2_hevc_pred_weight_table pred_weight_table;
 __u8 reserved1[2];
 __u64 flags;
};
struct v4l2_ctrl_hevc_decode_params {
 __s32 pic_order_cnt_val;
 __u16 short_term_ref_pic_set_size;
 __u16 long_term_ref_pic_set_size;
 __u8 num_active_dpb_entries;
 __u8 num_poc_st_curr_before;
 __u8 num_poc_st_curr_after;
 __u8 num_poc_lt_curr;
 __u8 poc_st_curr_before[16];
 __u8 poc_st_curr_after[16];
 __u8 poc_lt_curr[16];
 __u8 reserved[4];
 struct v4l2_hevc_dpb_entry dpb[16];
 __u64 flags;
};
struct v4l2_ctrl_hevc_scaling_matrix {
 __u8 scaling_list_4x4[6][16];
 __u8 scaling_list_8x8[6][64];
 __u8 scaling_list_16x16[6][64];
 __u8 scaling_list_32x32[2][64];
 __u8 scaling_list_dc_coef_16x16[6];
 __u8 scaling_list_dc_coef_32x32[2];
};
struct v4l2_ctrl_hdr10_cll_info {
 __u16 max_content_light_level;
 __u16 max_pic_average_light_level;
};
struct v4l2_ctrl_hdr10_mastering_display {
 __u16 display_primaries_x[3];
 __u16 display_primaries_y[3];
 __u16 white_point_x;
 __u16 white_point_y;
 __u32 max_display_mastering_luminance;
 __u32 min_display_mastering_luminance;
};
struct v4l2_vp9_loop_filter {
 __s8 ref_deltas[4];
 __s8 mode_deltas[2];
 __u8 level;
 __u8 sharpness;
 __u8 flags;
 __u8 reserved[7];
};
struct v4l2_vp9_quantization {
 __u8 base_q_idx;
 __s8 delta_q_y_dc;
 __s8 delta_q_uv_dc;
 __s8 delta_q_uv_ac;
 __u8 reserved[4];
};
struct v4l2_vp9_segmentation {
 __s16 feature_data[8][4];
 __u8 feature_enabled[8];
 __u8 tree_probs[7];
 __u8 pred_probs[3];
 __u8 flags;
 __u8 reserved[5];
};
struct v4l2_ctrl_vp9_frame {
 struct v4l2_vp9_loop_filter lf;
 struct v4l2_vp9_quantization quant;
 struct v4l2_vp9_segmentation seg;
 __u32 flags;
 __u16 compressed_header_size;
 __u16 uncompressed_header_size;
 __u16 frame_width_minus_1;
 __u16 frame_height_minus_1;
 __u16 render_width_minus_1;
 __u16 render_height_minus_1;
 __u64 last_frame_ts;
 __u64 golden_frame_ts;
 __u64 alt_frame_ts;
 __u8 ref_frame_sign_bias;
 __u8 reset_frame_context;
 __u8 frame_context_idx;
 __u8 profile;
 __u8 bit_depth;
 __u8 interpolation_filter;
 __u8 tile_cols_log2;
 __u8 tile_rows_log2;
 __u8 reference_mode;
 __u8 reserved[7];
};
struct v4l2_vp9_mv_probs {
 __u8 joint[3];
 __u8 sign[2];
 __u8 classes[2][10];
 __u8 class0_bit[2];
 __u8 bits[2][10];
 __u8 class0_fr[2][2][3];
 __u8 fr[2][3];
 __u8 class0_hp[2];
 __u8 hp[2];
};
struct v4l2_ctrl_vp9_compressed_hdr {
 __u8 tx_mode;
 __u8 tx8[2][1];
 __u8 tx16[2][2];
 __u8 tx32[2][3];
 __u8 coef[4][2][2][6][6][3];
 __u8 skip[3];
 __u8 inter_mode[7][3];
 __u8 interp_filter[4][2];
 __u8 is_inter[4];
 __u8 comp_mode[5];
 __u8 single_ref[5][2];
 __u8 comp_ref[5];
 __u8 y_mode[4][9];
 __u8 uv_mode[10][9];
 __u8 partition[16][3];
 struct v4l2_vp9_mv_probs mv;
};
enum v4l2_field {
 V4L2_FIELD_ANY = 0,
 V4L2_FIELD_NONE = 1,
 V4L2_FIELD_TOP = 2,
 V4L2_FIELD_BOTTOM = 3,
 V4L2_FIELD_INTERLACED = 4,
 V4L2_FIELD_SEQ_TB = 5,
 V4L2_FIELD_SEQ_BT = 6,
 V4L2_FIELD_ALTERNATE = 7,
 V4L2_FIELD_INTERLACED_TB = 8,
 V4L2_FIELD_INTERLACED_BT = 9,
};
enum v4l2_buf_type {
 V4L2_BUF_TYPE_VIDEO_CAPTURE = 1,
 V4L2_BUF_TYPE_VIDEO_OUTPUT = 2,
 V4L2_BUF_TYPE_VIDEO_OVERLAY = 3,
 V4L2_BUF_TYPE_VBI_CAPTURE = 4,
 V4L2_BUF_TYPE_VBI_OUTPUT = 5,
 V4L2_BUF_TYPE_SLICED_VBI_CAPTURE = 6,
 V4L2_BUF_TYPE_SLICED_VBI_OUTPUT = 7,
 V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY = 8,
 V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE = 9,
 V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE = 10,
 V4L2_BUF_TYPE_SDR_CAPTURE = 11,
 V4L2_BUF_TYPE_SDR_OUTPUT = 12,
 V4L2_BUF_TYPE_META_CAPTURE = 13,
 V4L2_BUF_TYPE_META_OUTPUT = 14,
 V4L2_BUF_TYPE_PRIVATE = 0x80,
};
enum v4l2_tuner_type {
 V4L2_TUNER_RADIO = 1,
 V4L2_TUNER_ANALOG_TV = 2,
 V4L2_TUNER_DIGITAL_TV = 3,
 V4L2_TUNER_SDR = 4,
 V4L2_TUNER_RF = 5,
};
enum v4l2_memory {
 V4L2_MEMORY_MMAP = 1,
 V4L2_MEMORY_USERPTR = 2,
 V4L2_MEMORY_OVERLAY = 3,
 V4L2_MEMORY_DMABUF = 4,
};
enum v4l2_colorspace {
 V4L2_COLORSPACE_DEFAULT = 0,
 V4L2_COLORSPACE_SMPTE170M = 1,
 V4L2_COLORSPACE_SMPTE240M = 2,
 V4L2_COLORSPACE_REC709 = 3,
 V4L2_COLORSPACE_BT878 = 4,
 V4L2_COLORSPACE_470_SYSTEM_M = 5,
 V4L2_COLORSPACE_470_SYSTEM_BG = 6,
 V4L2_COLORSPACE_JPEG = 7,
 V4L2_COLORSPACE_SRGB = 8,
 V4L2_COLORSPACE_OPRGB = 9,
 V4L2_COLORSPACE_BT2020 = 10,
 V4L2_COLORSPACE_RAW = 11,
 V4L2_COLORSPACE_DCI_P3 = 12,
};
enum v4l2_xfer_func {
 V4L2_XFER_FUNC_DEFAULT = 0,
 V4L2_XFER_FUNC_709 = 1,
 V4L2_XFER_FUNC_SRGB = 2,
 V4L2_XFER_FUNC_OPRGB = 3,
 V4L2_XFER_FUNC_SMPTE240M = 4,
 V4L2_XFER_FUNC_NONE = 5,
 V4L2_XFER_FUNC_DCI_P3 = 6,
 V4L2_XFER_FUNC_SMPTE2084 = 7,
};
enum v4l2_ycbcr_encoding {
 V4L2_YCBCR_ENC_DEFAULT = 0,
 V4L2_YCBCR_ENC_601 = 1,
 V4L2_YCBCR_ENC_709 = 2,
 V4L2_YCBCR_ENC_XV601 = 3,
 V4L2_YCBCR_ENC_XV709 = 4,
 V4L2_YCBCR_ENC_SYCC = 5,
 V4L2_YCBCR_ENC_BT2020 = 6,
 V4L2_YCBCR_ENC_BT2020_CONST_LUM = 7,
 V4L2_YCBCR_ENC_SMPTE240M = 8,
};
enum v4l2_hsv_encoding {
 V4L2_HSV_ENC_180 = 128,
 V4L2_HSV_ENC_256 = 129,
};
enum v4l2_quantization {
 V4L2_QUANTIZATION_DEFAULT = 0,
 V4L2_QUANTIZATION_FULL_RANGE = 1,
 V4L2_QUANTIZATION_LIM_RANGE = 2,
};
enum v4l2_priority {
 V4L2_PRIORITY_UNSET = 0,
 V4L2_PRIORITY_BACKGROUND = 1,
 V4L2_PRIORITY_INTERACTIVE = 2,
 V4L2_PRIORITY_RECORD = 3,
 V4L2_PRIORITY_DEFAULT = V4L2_PRIORITY_INTERACTIVE,
};
struct v4l2_rect {
 __s32 left;
 __s32 top;
 __u32 width;
 __u32 height;
};
struct v4l2_fract {
 __u32 numerator;
 __u32 denominator;
};
struct v4l2_area {
 __u32 width;
 __u32 height;
};
struct v4l2_capability {
 __u8 driver[16];
 __u8 card[32];
 __u8 bus_info[32];
 __u32 version;
 __u32 capabilities;
 __u32 device_caps;
 __u32 reserved[3];
};
struct v4l2_pix_format {
 __u32 width;
 __u32 height;
 __u32 pixelformat;
 __u32 field;
 __u32 bytesperline;
 __u32 sizeimage;
 __u32 colorspace;
 __u32 priv;
 __u32 flags;
 union {
  __u32 ycbcr_enc;
  __u32 hsv_enc;
 };
 __u32 quantization;
 __u32 xfer_func;
};
struct v4l2_fmtdesc {
 __u32 index;
 __u32 type;
 __u32 flags;
 __u8 description[32];
 __u32 pixelformat;
 __u32 mbus_code;
 __u32 reserved[3];
};
enum v4l2_frmsizetypes {
 V4L2_FRMSIZE_TYPE_DISCRETE = 1,
 V4L2_FRMSIZE_TYPE_CONTINUOUS = 2,
 V4L2_FRMSIZE_TYPE_STEPWISE = 3,
};
struct v4l2_frmsize_discrete {
 __u32 width;
 __u32 height;
};
struct v4l2_frmsize_stepwise {
 __u32 min_width;
 __u32 max_width;
 __u32 step_width;
 __u32 min_height;
 __u32 max_height;
 __u32 step_height;
};
struct v4l2_frmsizeenum {
 __u32 index;
 __u32 pixel_format;
 __u32 type;
 union {
  struct v4l2_frmsize_discrete discrete;
  struct v4l2_frmsize_stepwise stepwise;
 };
 __u32 reserved[2];
};
enum v4l2_frmivaltypes {
 V4L2_FRMIVAL_TYPE_DISCRETE = 1,
 V4L2_FRMIVAL_TYPE_CONTINUOUS = 2,
 V4L2_FRMIVAL_TYPE_STEPWISE = 3,
};
struct v4l2_frmival_stepwise {
 struct v4l2_fract min;
 struct v4l2_fract max;
 struct v4l2_fract step;
};
struct v4l2_frmivalenum {
 __u32 index;
 __u32 pixel_format;
 __u32 width;
 __u32 height;
 __u32 type;
 union {
  struct v4l2_fract discrete;
  struct v4l2_frmival_stepwise stepwise;
 };
 __u32 reserved[2];
};
struct v4l2_timecode {
 __u32 type;
 __u32 flags;
 __u8 frames;
 __u8 seconds;
 __u8 minutes;
 __u8 hours;
 __u8 userbits[4];
};
struct v4l2_jpegcompression {
 int quality;
 int APPn;
 int APP_len;
 char APP_data[60];
 int COM_len;
 char COM_data[60];
 __u32 jpeg_markers;
};
struct v4l2_requestbuffers {
 __u32 count;
 __u32 type;
 __u32 memory;
 __u32 capabilities;
 __u8 flags;
 __u8 reserved[3];
};
struct v4l2_plane {
 __u32 bytesused;
 __u32 length;
 union {
  __u32 mem_offset;
  unsigned long userptr;
  __s32 fd;
 } m;
 __u32 data_offset;
 __u32 reserved[11];
};
struct v4l2_buffer {
 __u32 index;
 __u32 type;
 __u32 bytesused;
 __u32 flags;
 __u32 field;
 struct timeval timestamp;
 struct v4l2_timecode timecode;
 __u32 sequence;
 __u32 memory;
 union {
  __u32 offset;
  unsigned long userptr;
  struct v4l2_plane *planes;
  __s32 fd;
 } m;
 __u32 length;
 __u32 reserved2;
 union {
  __s32 request_fd;
  __u32 reserved;
 };
};
static __inline__ __u64 v4l2_timeval_to_ns(const struct timeval *tv)
{
 return (__u64)tv->tv_sec * 1000000000ULL + tv->tv_usec * 1000;
}
struct v4l2_exportbuffer {
 __u32 type;
 __u32 index;
 __u32 plane;
 __u32 flags;
 __s32 fd;
 __u32 reserved[11];
};
struct v4l2_framebuffer {
 __u32 capability;
 __u32 flags;
 void *base;
 struct {
  __u32 width;
  __u32 height;
  __u32 pixelformat;
  __u32 field;
  __u32 bytesperline;
  __u32 sizeimage;
  __u32 colorspace;
  __u32 priv;
 } fmt;
};
struct v4l2_clip {
 struct v4l2_rect c;
 struct v4l2_clip *next;
};
struct v4l2_window {
 struct v4l2_rect w;
 __u32 field;
 __u32 chromakey;
 struct v4l2_clip *clips;
 __u32 clipcount;
 void *bitmap;
 __u8 global_alpha;
};
struct v4l2_captureparm {
 __u32 capability;
 __u32 capturemode;
 struct v4l2_fract timeperframe;
 __u32 extendedmode;
 __u32 readbuffers;
 __u32 reserved[4];
};
struct v4l2_outputparm {
 __u32 capability;
 __u32 outputmode;
 struct v4l2_fract timeperframe;
 __u32 extendedmode;
 __u32 writebuffers;
 __u32 reserved[4];
};
struct v4l2_cropcap {
 __u32 type;
 struct v4l2_rect bounds;
 struct v4l2_rect defrect;
 struct v4l2_fract pixelaspect;
};
struct v4l2_crop {
 __u32 type;
 struct v4l2_rect c;
};
struct v4l2_selection {
 __u32 type;
 __u32 target;
 __u32 flags;
 struct v4l2_rect r;
 __u32 reserved[9];
};
typedef __u64 v4l2_std_id;
struct v4l2_standard {
 __u32 index;
 v4l2_std_id id;
 __u8 name[24];
 struct v4l2_fract frameperiod;
 __u32 framelines;
 __u32 reserved[4];
};
struct v4l2_bt_timings {
 __u32 width;
 __u32 height;
 __u32 interlaced;
 __u32 polarities;
 __u64 pixelclock;
 __u32 hfrontporch;
 __u32 hsync;
 __u32 hbackporch;
 __u32 vfrontporch;
 __u32 vsync;
 __u32 vbackporch;
 __u32 il_vfrontporch;
 __u32 il_vsync;
 __u32 il_vbackporch;
 __u32 standards;
 __u32 flags;
 struct v4l2_fract picture_aspect;
 __u8 cea861_vic;
 __u8 hdmi_vic;
 __u8 reserved[46];
} __attribute__ ((packed));
struct v4l2_dv_timings {
 __u32 type;
 union {
  struct v4l2_bt_timings bt;
  __u32 reserved[32];
 };
} __attribute__ ((packed));
struct v4l2_enum_dv_timings {
 __u32 index;
 __u32 pad;
 __u32 reserved[2];
 struct v4l2_dv_timings timings;
};
struct v4l2_bt_timings_cap {
 __u32 min_width;
 __u32 max_width;
 __u32 min_height;
 __u32 max_height;
 __u64 min_pixelclock;
 __u64 max_pixelclock;
 __u32 standards;
 __u32 capabilities;
 __u32 reserved[16];
} __attribute__ ((packed));
struct v4l2_dv_timings_cap {
 __u32 type;
 __u32 pad;
 __u32 reserved[2];
 union {
  struct v4l2_bt_timings_cap bt;
  __u32 raw_data[32];
 };
};
struct v4l2_input {
 __u32 index;
 __u8 name[32];
 __u32 type;
 __u32 audioset;
 __u32 tuner;
 v4l2_std_id std;
 __u32 status;
 __u32 capabilities;
 __u32 reserved[3];
};
struct v4l2_output {
 __u32 index;
 __u8 name[32];
 __u32 type;
 __u32 audioset;
 __u32 modulator;
 v4l2_std_id std;
 __u32 capabilities;
 __u32 reserved[3];
};
struct v4l2_control {
 __u32 id;
 __s32 value;
};
struct v4l2_ext_control {
 __u32 id;
 __u32 size;
 __u32 reserved2[1];
 union {
  __s32 value;
  __s64 value64;
  char *string;
  __u8 *p_u8;
  __u16 *p_u16;
  __u32 *p_u32;
  __u32 *p_s32;
  __u32 *p_s64;
  struct v4l2_area *p_area;
  struct v4l2_ctrl_h264_sps *p_h264_sps;
  struct v4l2_ctrl_h264_pps *p_h264_pps;
  struct v4l2_ctrl_h264_scaling_matrix *p_h264_scaling_matrix;
  struct v4l2_ctrl_h264_pred_weights *p_h264_pred_weights;
  struct v4l2_ctrl_h264_slice_params *p_h264_slice_params;
  struct v4l2_ctrl_h264_decode_params *p_h264_decode_params;
  struct v4l2_ctrl_fwht_params *p_fwht_params;
  struct v4l2_ctrl_vp8_frame *p_vp8_frame;
  struct v4l2_ctrl_mpeg2_sequence *p_mpeg2_sequence;
  struct v4l2_ctrl_mpeg2_picture *p_mpeg2_picture;
  struct v4l2_ctrl_mpeg2_quantisation *p_mpeg2_quantisation;
  struct v4l2_ctrl_vp9_compressed_hdr *p_vp9_compressed_hdr_probs;
  struct v4l2_ctrl_vp9_frame *p_vp9_frame;
  struct v4l2_ctrl_hevc_sps *p_hevc_sps;
  struct v4l2_ctrl_hevc_pps *p_hevc_pps;
  struct v4l2_ctrl_hevc_slice_params *p_hevc_slice_params;
  struct v4l2_ctrl_hevc_scaling_matrix *p_hevc_scaling_matrix;
  struct v4l2_ctrl_hevc_decode_params *p_hevc_decode_params;
  void *ptr;
 };
} __attribute__ ((packed));
struct v4l2_ext_controls {
 union {
  __u32 ctrl_class;
  __u32 which;
 };
 __u32 count;
 __u32 error_idx;
 __s32 request_fd;
 __u32 reserved[1];
 struct v4l2_ext_control *controls;
};
enum v4l2_ctrl_type {
 V4L2_CTRL_TYPE_INTEGER = 1,
 V4L2_CTRL_TYPE_BOOLEAN = 2,
 V4L2_CTRL_TYPE_MENU = 3,
 V4L2_CTRL_TYPE_BUTTON = 4,
 V4L2_CTRL_TYPE_INTEGER64 = 5,
 V4L2_CTRL_TYPE_CTRL_CLASS = 6,
 V4L2_CTRL_TYPE_STRING = 7,
 V4L2_CTRL_TYPE_BITMASK = 8,
 V4L2_CTRL_TYPE_INTEGER_MENU = 9,
 V4L2_CTRL_COMPOUND_TYPES = 0x0100,
 V4L2_CTRL_TYPE_U8 = 0x0100,
 V4L2_CTRL_TYPE_U16 = 0x0101,
 V4L2_CTRL_TYPE_U32 = 0x0102,
 V4L2_CTRL_TYPE_AREA = 0x0106,
 V4L2_CTRL_TYPE_HDR10_CLL_INFO = 0x0110,
 V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY = 0x0111,
 V4L2_CTRL_TYPE_H264_SPS = 0x0200,
 V4L2_CTRL_TYPE_H264_PPS = 0x0201,
 V4L2_CTRL_TYPE_H264_SCALING_MATRIX = 0x0202,
 V4L2_CTRL_TYPE_H264_SLICE_PARAMS = 0x0203,
 V4L2_CTRL_TYPE_H264_DECODE_PARAMS = 0x0204,
 V4L2_CTRL_TYPE_H264_PRED_WEIGHTS = 0x0205,
 V4L2_CTRL_TYPE_FWHT_PARAMS = 0x0220,
 V4L2_CTRL_TYPE_VP8_FRAME = 0x0240,
 V4L2_CTRL_TYPE_MPEG2_QUANTISATION = 0x0250,
 V4L2_CTRL_TYPE_MPEG2_SEQUENCE = 0x0251,
 V4L2_CTRL_TYPE_MPEG2_PICTURE = 0x0252,
 V4L2_CTRL_TYPE_VP9_COMPRESSED_HDR = 0x0260,
 V4L2_CTRL_TYPE_VP9_FRAME = 0x0261,
 V4L2_CTRL_TYPE_HEVC_SPS = 0x0270,
 V4L2_CTRL_TYPE_HEVC_PPS = 0x0271,
 V4L2_CTRL_TYPE_HEVC_SLICE_PARAMS = 0x0272,
 V4L2_CTRL_TYPE_HEVC_SCALING_MATRIX = 0x0273,
 V4L2_CTRL_TYPE_HEVC_DECODE_PARAMS = 0x0274,
};
struct v4l2_queryctrl {
 __u32 id;
 __u32 type;
 __u8 name[32];
 __s32 minimum;
 __s32 maximum;
 __s32 step;
 __s32 default_value;
 __u32 flags;
 __u32 reserved[2];
};
struct v4l2_query_ext_ctrl {
 __u32 id;
 __u32 type;
 char name[32];
 __s64 minimum;
 __s64 maximum;
 __u64 step;
 __s64 default_value;
 __u32 flags;
 __u32 elem_size;
 __u32 elems;
 __u32 nr_of_dims;
 __u32 dims[(4)];
 __u32 reserved[32];
};
struct v4l2_querymenu {
 __u32 id;
 __u32 index;
 union {
  __u8 name[32];
  __s64 value;
 };
 __u32 reserved;
} __attribute__ ((packed));
struct v4l2_tuner {
 __u32 index;
 __u8 name[32];
 __u32 type;
 __u32 capability;
 __u32 rangelow;
 __u32 rangehigh;
 __u32 rxsubchans;
 __u32 audmode;
 __s32 signal;
 __s32 afc;
 __u32 reserved[4];
};
struct v4l2_modulator {
 __u32 index;
 __u8 name[32];
 __u32 capability;
 __u32 rangelow;
 __u32 rangehigh;
 __u32 txsubchans;
 __u32 type;
 __u32 reserved[3];
};
struct v4l2_frequency {
 __u32 tuner;
 __u32 type;
 __u32 frequency;
 __u32 reserved[8];
};
struct v4l2_frequency_band {
 __u32 tuner;
 __u32 type;
 __u32 index;
 __u32 capability;
 __u32 rangelow;
 __u32 rangehigh;
 __u32 modulation;
 __u32 reserved[9];
};
struct v4l2_hw_freq_seek {
 __u32 tuner;
 __u32 type;
 __u32 seek_upward;
 __u32 wrap_around;
 __u32 spacing;
 __u32 rangelow;
 __u32 rangehigh;
 __u32 reserved[5];
};
struct v4l2_rds_data {
 __u8 lsb;
 __u8 msb;
 __u8 block;
} __attribute__ ((packed));
struct v4l2_audio {
 __u32 index;
 __u8 name[32];
 __u32 capability;
 __u32 mode;
 __u32 reserved[2];
};
struct v4l2_audioout {
 __u32 index;
 __u8 name[32];
 __u32 capability;
 __u32 mode;
 __u32 reserved[2];
};
struct v4l2_enc_idx_entry {
 __u64 offset;
 __u64 pts;
 __u32 length;
 __u32 flags;
 __u32 reserved[2];
};
struct v4l2_enc_idx {
 __u32 entries;
 __u32 entries_cap;
 __u32 reserved[4];
 struct v4l2_enc_idx_entry entry[(64)];
};
struct v4l2_encoder_cmd {
 __u32 cmd;
 __u32 flags;
 union {
  struct {
   __u32 data[8];
  } raw;
 };
};
struct v4l2_decoder_cmd {
 __u32 cmd;
 __u32 flags;
 union {
  struct {
   __u64 pts;
  } stop;
  struct {
   __s32 speed;
   __u32 format;
  } start;
  struct {
   __u32 data[16];
  } raw;
 };
};
struct v4l2_vbi_format {
 __u32 sampling_rate;
 __u32 offset;
 __u32 samples_per_line;
 __u32 sample_format;
 __s32 start[2];
 __u32 count[2];
 __u32 flags;
 __u32 reserved[2];
};
struct v4l2_sliced_vbi_format {
 __u16 service_set;
 __u16 service_lines[2][24];
 __u32 io_size;
 __u32 reserved[2];
};
struct v4l2_sliced_vbi_cap {
 __u16 service_set;
 __u16 service_lines[2][24];
 __u32 type;
 __u32 reserved[3];
};
struct v4l2_sliced_vbi_data {
 __u32 id;
 __u32 field;
 __u32 line;
 __u32 reserved;
 __u8 data[48];
};
struct v4l2_mpeg_vbi_itv0_line {
 __u8 id;
 __u8 data[42];
} __attribute__ ((packed));
struct v4l2_mpeg_vbi_itv0 {
 __le32 linemask[2];
 struct v4l2_mpeg_vbi_itv0_line line[35];
} __attribute__ ((packed));
struct v4l2_mpeg_vbi_ITV0 {
 struct v4l2_mpeg_vbi_itv0_line line[36];
} __attribute__ ((packed));
struct v4l2_mpeg_vbi_fmt_ivtv {
 __u8 magic[4];
 union {
  struct v4l2_mpeg_vbi_itv0 itv0;
  struct v4l2_mpeg_vbi_ITV0 ITV0;
 };
} __attribute__ ((packed));
struct v4l2_plane_pix_format {
 __u32 sizeimage;
 __u32 bytesperline;
 __u16 reserved[6];
} __attribute__ ((packed));
struct v4l2_pix_format_mplane {
 __u32 width;
 __u32 height;
 __u32 pixelformat;
 __u32 field;
 __u32 colorspace;
 struct v4l2_plane_pix_format plane_fmt[8];
 __u8 num_planes;
 __u8 flags;
  union {
  __u8 ycbcr_enc;
  __u8 hsv_enc;
 };
 __u8 quantization;
 __u8 xfer_func;
 __u8 reserved[7];
} __attribute__ ((packed));
struct v4l2_sdr_format {
 __u32 pixelformat;
 __u32 buffersize;
 __u8 reserved[24];
} __attribute__ ((packed));
struct v4l2_meta_format {
 __u32 dataformat;
 __u32 buffersize;
} __attribute__ ((packed));
struct v4l2_format {
 __u32 type;
 union {
  struct v4l2_pix_format pix;
  struct v4l2_pix_format_mplane pix_mp;
  struct v4l2_window win;
  struct v4l2_vbi_format vbi;
  struct v4l2_sliced_vbi_format sliced;
  struct v4l2_sdr_format sdr;
  struct v4l2_meta_format meta;
  __u8 raw_data[200];
 } fmt;
};
struct v4l2_streamparm {
 __u32 type;
 union {
  struct v4l2_captureparm capture;
  struct v4l2_outputparm output;
  __u8 raw_data[200];
 } parm;
};
struct v4l2_event_vsync {
 __u8 field;
} __attribute__ ((packed));
struct v4l2_event_ctrl {
 __u32 changes;
 __u32 type;
 union {
  __s32 value;
  __s64 value64;
 };
 __u32 flags;
 __s32 minimum;
 __s32 maximum;
 __s32 step;
 __s32 default_value;
};
struct v4l2_event_frame_sync {
 __u32 frame_sequence;
};
struct v4l2_event_src_change {
 __u32 changes;
};
struct v4l2_event_motion_det {
 __u32 flags;
 __u32 frame_sequence;
 __u32 region_mask;
};
struct v4l2_event {
 __u32 type;
 union {
  struct v4l2_event_vsync vsync;
  struct v4l2_event_ctrl ctrl;
  struct v4l2_event_frame_sync frame_sync;
  struct v4l2_event_src_change src_change;
  struct v4l2_event_motion_det motion_det;
  __u8 data[64];
 } u;
 __u32 pending;
 __u32 sequence;
 struct timespec timestamp;
 __u32 id;
 __u32 reserved[8];
};
struct v4l2_event_subscription {
 __u32 type;
 __u32 id;
 __u32 flags;
 __u32 reserved[5];
};
struct v4l2_dbg_match {
 __u32 type;
 union {
  __u32 addr;
  char name[32];
 };
} __attribute__ ((packed));
struct v4l2_dbg_register {
 struct v4l2_dbg_match match;
 __u32 size;
 __u64 reg;
 __u64 val;
} __attribute__ ((packed));
struct v4l2_dbg_chip_info {
 struct v4l2_dbg_match match;
 char name[32];
 __u32 flags;
 __u32 reserved[32];
} __attribute__ ((packed));
struct v4l2_create_buffers {
 __u32 index;
 __u32 count;
 __u32 memory;
 struct v4l2_format format;
 __u32 capabilities;
 __u32 flags;
 __u32 reserved[6];
};
typedef struct {
 long long tv_sec;
 long long tv_usec;
} kernel_timeval64_t;
typedef struct {
 kernel_long_t tv_sec;
 kernel_long_t tv_usec;
} kernel_old_timeval_t;
typedef struct kernel_timespec64_t {
 long long tv_sec;
 long long tv_nsec;
} kernel_timespec64_t;
typedef struct kernel_timespec32_t {
 int tv_sec;
 int tv_nsec;
} kernel_timespec32_t;
typedef kernel_timeval64_t kernel_v4l2_timeval_t;
typedef struct {
 uint32_t index;
 uint32_t type;
 uint32_t bytesused;
 uint32_t flags;
 uint32_t field;
 kernel_v4l2_timeval_t timestamp;
 struct v4l2_timecode timecode;
 uint32_t sequence;
 uint32_t memory;
 union {
  uint32_t offset;
  unsigned long userptr;
  struct v4l2_plane *planes;
  int32_t fd;
 } m;
 uint32_t length;
 uint32_t reserved2;
 union {
  int32_t request_fd;
  uint32_t reserved;
 };
} kernel_v4l2_buffer_t;
typedef struct {
 uint32_t type;
 union {
  uint64_t data[8];
 } u;
 uint32_t pending;
 uint32_t sequence;
 kernel_timespec64_t timestamp;
 uint32_t id;
 uint32_t reserved[8];
} kernel_v4l2_event_t;
typedef struct v4l2_clip struct_v4l2_clip;
typedef struct v4l2_create_buffers struct_v4l2_create_buffers;
typedef struct v4l2_ext_control struct_v4l2_ext_control;
typedef struct v4l2_ext_controls struct_v4l2_ext_controls;
typedef struct v4l2_format struct_v4l2_format;
typedef struct v4l2_framebuffer struct_v4l2_framebuffer;
typedef struct v4l2_input struct_v4l2_input;
typedef struct v4l2_standard struct_v4l2_standard;
typedef struct v4l2_window struct_v4l2_window;
static const char hex_chars[16] = "0123456789abcdef";
static inline _Bool
is_print(uint8_t c)
{
 return (c >= ' ') && (c < 0x7f);
}
static inline char *
sprint_byte_oct(char *s, uint8_t c, _Bool unabbrev)
{
 if (unabbrev) {
  *s++ = '0' + (c >> 6);
  *s++ = '0' + ((c >> 3) & 0x7);
 } else {
  if ((c >> 3) != 0) {
   if ((c >> 6) != 0)
    *s++ = '0' + (c >> 6);
   *s++ = '0' + ((c >> 3) & 0x7);
  }
 }
 *s++ = '0' + (c & 0x7);
 return s;
}
static inline char *
sprint_byte_hex(char *buf, uint8_t val)
{
 *buf++ = hex_chars[val >> 4];
 *buf++ = hex_chars[val & 0xf];
 return buf;
}
enum sprint_char_flag_bits {
 SCF_QUOTES_BIT,
 SCF_NUL_BIT,
 SCF_ESC_WS_BIT,
};
enum sprint_char_flags {
 SCF_QUOTES = (1U << (SCF_QUOTES_BIT)),
 SCF_NUL = (1U << (SCF_NUL_BIT)),
 SCF_ESC_WS = (1U << (SCF_ESC_WS_BIT)),
};
static inline char *
sprint_char(char *buf, const unsigned char c, const enum sprint_char_flags f)
{
 if (f & SCF_QUOTES)
  *buf++ = '\'';
 if (is_print(c)) {
  if (c == '\'' || c == '\\')
   *buf++ = '\\';
  *buf++ = c;
 } else if ((f & SCF_ESC_WS) && (c >= '\t') && (c <= '\r')) {
  static const char ws_chars[] = "tnvfr";
  *buf++ = '\\';
  *buf++ = ws_chars[c - '\t'];
 } else {
  *buf++ = '\\';
  *buf++ = 'x';
  buf = sprint_byte_hex(buf, c);
 }
 if (f & SCF_QUOTES)
  *buf++ = '\'';
 if (f & SCF_NUL)
  *buf++ = '\0';
 return buf;
}
static inline int __attribute__((__format__ (printf, 5, 6)))
xsnprintf_(char *str, size_t size, const char *func, const char *argstr,
    const char *format, ...)
{
 int ret;
 va_list ap;
 __builtin_va_start(ap,format);
 ret = vsnprintf(str, size, format, ap);
 __builtin_va_end(ap);
 if (ret < 0 || (unsigned int) ret >= size)
  error_msg_and_die("%s: got unexpected return value %d for "
      "snprintf(buf, %zu, %s)",
      func, ret, size, argstr);
 return ret;
}
static inline size_t
get_pos_diff_(char *str, size_t size, char *pos, const char *func,
    const char *call)
{
 if ((str + size) < str)
  error_msg_and_die("%s: string size overflow (%p+%zu) in %s",
      func, str, size, call);
 if (pos > (str + size))
  error_msg_and_die("%s: got position (%p) beyond string "
      "(%p+%zu) in %s",
      func, pos, str, size, call);
 if (pos < str)
  error_msg_and_die("%s: got position %p before string %p in %s",
      func, pos, str, call);
 return pos - str;
}
_Static_assert((unsigned long long) (((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('H') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('I') << 8) | ((__u32)('V') << 16) | ((__u32)('D') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_UVC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('H') << 24)))
      > (unsigned long long) ((((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('H') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_VSP1_HGO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('H') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_RK_ISP1_PARAMS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('S') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_RK_ISP1_STAT_3A"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('T') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('S') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_VSP1_HGT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('D') | ((__u32)('4') << 8) | ((__u32)('X') << 16) | ((__u32)('X') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('T') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_META_FMT_D4XX"
      " is not larger than the previous value");

static const struct xlat_data v4l2_meta_fmts_xdata[] = {
 { (unsigned)(((__u32)('V') | ((__u32)('I') << 8) | ((__u32)('V') << 16) | ((__u32)('D') << 24))), "V4L2_META_FMT_VIVID" },
 { (unsigned)(((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('H') << 24))), "V4L2_META_FMT_UVC" },
 { (unsigned)(((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('H') << 24))), "V4L2_META_FMT_VSP1_HGO" },
 { (unsigned)(((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))), "V4L2_META_FMT_RK_ISP1_PARAMS" },
 { (unsigned)(((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('S') << 24))), "V4L2_META_FMT_RK_ISP1_STAT_3A" },
 { (unsigned)(((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('T') << 24))), "V4L2_META_FMT_VSP1_HGT" },
 { (unsigned)(((__u32)('D') | ((__u32)('4') << 8) | ((__u32)('X') << 16) | ((__u32)('X') << 24))), "V4L2_META_FMT_D4XX" },
};
const struct xlat v4l2_meta_fmts[1] = { {
 .data = v4l2_meta_fmts_xdata,
 .size = (sizeof(v4l2_meta_fmts_xdata) / sizeof((v4l2_meta_fmts_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_meta_fmts_xdata)), __typeof__(&(v4l2_meta_fmts_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (((__u32)('V') | ((__u32)('I') << 8) | ((__u32)('V') << 16) | ((__u32)('D') << 24))))
  | ((unsigned) (((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('H') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('H') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('K') << 8) | ((__u32)('1') << 16) | ((__u32)('S') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('S') << 8) | ((__u32)('P') << 16) | ((__u32)('T') << 24))))
  | ((unsigned) (((__u32)('D') | ((__u32)('4') << 8) | ((__u32)('X') << 16) | ((__u32)('X') << 24))))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_META_FMT_VIVID")
  + sizeof("V4L2_META_FMT_UVC")
  + sizeof("V4L2_META_FMT_VSP1_HGO")
  + sizeof("V4L2_META_FMT_RK_ISP1_PARAMS")
  + sizeof("V4L2_META_FMT_RK_ISP1_STAT_3A")
  + sizeof("V4L2_META_FMT_VSP1_HGT")
  + sizeof("V4L2_META_FMT_D4XX")
  ,
} };

_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y4"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y14"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y6"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Z') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Z16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('8') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('Z') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_UV8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('8') << 8) | ((__u32)('I') << 16) | ((__u32)(' ') << 24)))
      > (unsigned long long) ((((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('8') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y8I"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('3') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('8') << 8) | ((__u32)('I') << 16) | ((__u32)(' ') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MR97310A"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('3') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SN9C10X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('D') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG10DPCM8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('D') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('4') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_M420"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('4') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SN9C20X_I420"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('J') | ((__u32)('L') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_JL2005BCD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('J') | ((__u32)('L') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_TM6000"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('6') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_STV0680"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('6') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VP8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('0') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VP9"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('4') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SE401"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('4') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SPCA501"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_OV511"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MM21"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV21M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVU420M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('T') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MT21C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('T') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV21"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SPCA561"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV61M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVU422M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV61"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('8') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('8') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB332"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_H264_NO_SC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_PWC1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('1') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MPEG1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('1') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRA444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12M_8L128"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBA444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ABGR444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XBGR444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12_16L16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12MT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12MT_16X16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV420M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ARGB444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XRGB444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12_32L32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12_4L4"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV420"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVU420"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRX444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBX444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVU444M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV42"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_PWC2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MPEG2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('Y') << 8) | ((__u32)('R') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('3') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('Y') << 8) | ((__u32)('R') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_H263"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('3') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('3') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('3') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('3') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGR24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('3') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_HSV24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG14"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR14"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB14"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG14"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ARGB32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRA32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBA32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBX32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('I') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_HI240"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('I') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV444M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ABGR32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XBGR32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV24"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XRGB32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRX32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV444"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_H264"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_H264_MVC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_H264_SLICE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('N') << 8) | ((__u32)('F') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_CNF4"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('N') << 8) | ((__u32)('F') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MPEG4"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGR32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_HSV32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SPCA505"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRA555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBA555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ABGR555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XBGR555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ARGB555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XRGB555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGRX555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGBX555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('E') | ((__u32)('6') << 8) | ((__u32)('2') << 16) | ((__u32)('5') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ET61X251"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('E') | ((__u32)('6') << 8) | ((__u32)('2') << 16) | ((__u32)('5') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV16M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV422M"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('2') << 8) | ((__u32)('0') << 16) | ((__u32)('7') << 24)))
      > (unsigned long long) ((((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_PAC207"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('2') << 8) | ((__u32)('0') << 16) | ((__u32)('7') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SPCA508"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_OV518"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('a') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR10ALAW8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('b') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('a') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR10DPCM8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('a') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('b') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG10ALAW8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('b') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('a') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG10DPCM8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('a') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('b') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB10ALAW8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('b') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('a') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB10DPCM8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('a') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('b') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG10ALAW8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('A') << 8) | ((__u32)('L') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('a') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_PAL8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('U') << 16) | ((__u32)('9') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('A') << 8) | ((__u32)('L') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVU410"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('9') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('U') << 16) | ((__u32)('9') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV410"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('9') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR10P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG10P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB10P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG10P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('P') << 8) | ((__u32)('I') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_CPIA1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('W') | ((__u32)('N') << 8) | ((__u32)('V') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('P') << 8) | ((__u32)('I') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_WNVA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('A') << 24)))
      > (unsigned long long) ((((__u32)('W') | ((__u32)('N') << 8) | ((__u32)('V') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VUYA32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('B') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('A') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y10BPACK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('G') << 16) | ((__u32)('B') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('B') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Q') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('G') << 16) | ((__u32)('B') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_QC10C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('9') | ((__u32)('0') << 8) | ((__u32)('5') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('Q') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SQ905C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Q') | ((__u32)('0') << 8) | ((__u32)('8') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('9') | ((__u32)('0') << 8) | ((__u32)('5') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_QC08C"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('Q') | ((__u32)('0') << 8) | ((__u32)('8') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR12P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG12P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB12P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG12P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('H') | ((__u32)('E') << 8) | ((__u32)('V') << 16) | ((__u32)('C') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_HEVC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('V') << 8) | ((__u32)('I') << 16) | ((__u32)('D') << 24)))
      > (unsigned long long) ((((__u32)('H') | ((__u32)('E') << 8) | ((__u32)('V') << 16) | ((__u32)('C') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XVID"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('V') << 8) | ((__u32)('I') << 16) | ((__u32)('D') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SBGGR14P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG14P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SRGGB14P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG14P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('F') << 24)))
      > (unsigned long long) ((((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VP8_FRAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('F') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('F') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VP9_FRAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('F') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VC1_ANNEX_G"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_IPU3_SGRBG10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('B') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGRBG8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('B') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_JPEG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MPEG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MJPEG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_PJPG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('R') << 16) | ((__u32)('G') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SGBRG8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('H') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('R') << 16) | ((__u32)('G') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_BGR666"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('F') << 8) | ((__u32)('W') << 16) | ((__u32)('H') << 24)))
      > (unsigned long long) ((((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('H') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_FWHT_STATELESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)('I') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('F') << 8) | ((__u32)('W') << 16) | ((__u32)('H') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y12I"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('C') << 16) | ((__u32)('I') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)('I') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_S5C_UYVY_JPG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('K') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('I') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('C') << 16) | ((__u32)('I') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_KONICA420"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('I') | ((__u32)('N') << 8) | ((__u32)('Z') << 16) | ((__u32)('I') << 24)))
      > (unsigned long long) ((((__u32)('K') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('I') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_INZI"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('L') << 24)))
      > (unsigned long long) ((((__u32)('I') | ((__u32)('N') << 8) | ((__u32)('Z') << 16) | ((__u32)('I') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VC1_ANNEX_L"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('L') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('L') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_JPGL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('O') << 24)))
      > (unsigned long long) ((((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('L') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('O') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('O') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV555"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('O') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y10P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('4') | ((__u32)('1') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV411P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('4') | ((__u32)('1') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y41P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('4') | ((__u32)('2') << 8) | ((__u32)('2') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV422P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('4') | ((__u32)('2') << 8) | ((__u32)('2') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB565"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('P') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUV565"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('Q') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('P') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB555X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('R') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('Q') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_RGB565X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('M') | ((__u32)('G') << 8) | ((__u32)('2') << 16) | ((__u32)('S') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('R') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_MPEG2_SLICE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('F') | ((__u32)('W') << 8) | ((__u32)('H') << 16) | ((__u32)('T') << 24)))
      > (unsigned long long) ((((__u32)('M') | ((__u32)('G') << 8) | ((__u32)('2') << 16) | ((__u32)('S') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_FWHT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('Y') << 16) | ((__u32)('U') << 24)))
      > (unsigned long long) ((((__u32)('F') | ((__u32)('W') << 8) | ((__u32)('H') << 16) | ((__u32)('T') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YVYU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('I') << 8) | ((__u32)('T') << 16) | ((__u32)('V') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('Y') << 16) | ((__u32)('U') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_CIT_YYVYUY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('A') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('I') << 8) | ((__u32)('T') << 16) | ((__u32)('V') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_AYUV32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('X') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))
      > (unsigned long long) ((((__u32)('A') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XYUV32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))
      > (unsigned long long) ((((__u32)('X') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YYUV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('V') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_YUYV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('S') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('X') << 24)))
      > (unsigned long long) ((((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('V') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_SN9C2028"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('X') << 24)))
      > (unsigned long long) ((((__u32)('S') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('X') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VUYX32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('Y') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('X') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_GREY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('V') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('Y') << 24)))
      > (unsigned long long) ((((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('Y') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_VYUY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('U') | ((__u32)('Y') << 8) | ((__u32)('V') << 16) | ((__u32)('Y') << 24)))
      > (unsigned long long) ((((__u32)('V') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('Y') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_UYVY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('b') << 24)))
      > (unsigned long long) ((((__u32)('U') | ((__u32)('Y') << 8) | ((__u32)('V') << 16) | ((__u32)('Y') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_IPU3_SBGGR10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('d') | ((__u32)('v') << 8) | ((__u32)('s') << 16) | ((__u32)('d') << 24)))
      > (unsigned long long) ((((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('b') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_DV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('g') << 24)))
      > (unsigned long long) ((((__u32)('d') | ((__u32)('v') << 8) | ((__u32)('s') << 16) | ((__u32)('d') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_IPU3_SGBRG10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('r') << 24)))
      > (unsigned long long) ((((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('g') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_IPU3_SRGGB10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('y') << 24)))
      > (unsigned long long) ((((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('r') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_IPU3_Y10"
      " is not larger than the previous value");
_Static_assert((unsigned long long) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)) | (1U << 31)))
      > (unsigned long long) ((((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('y') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_Y16_BE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) ((((__u32)('N') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)) | (1U << 31)))
      > (unsigned long long) (((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)) | (1U << 31)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_NV12M_10BE_8L128"
      " is not larger than the previous value");
_Static_assert((unsigned long long) ((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31)))
      > (unsigned long long) (((((__u32)('N') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)) | (1U << 31)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_ARGB555X"
      " is not larger than the previous value");
_Static_assert((unsigned long long) ((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31)))
      > (unsigned long long) (((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31)))),
      "Incorrect order in #sorted xlat: V4L2_PIX_FMT_XRGB555X"
      " is not larger than the previous value");

static const struct xlat_data v4l2_pix_fmts_xdata[] = {
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y10" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y12" },
 { (unsigned)(((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y4" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y14" },
 { (unsigned)(((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y6" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y16" },
 { (unsigned)(((__u32)('Z') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Z16" },
 { (unsigned)(((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('8') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_UV8" },
 { (unsigned)(((__u32)('Y') | ((__u32)('8') << 8) | ((__u32)('I') << 16) | ((__u32)(' ') << 24))), "V4L2_PIX_FMT_Y8I" },
 { (unsigned)(((__u32)('M') | ((__u32)('3') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_MR97310A" },
 { (unsigned)(((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SN9C10X" },
 { (unsigned)(((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SGRBG10" },
 { (unsigned)(((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SGBRG10" },
 { (unsigned)(((__u32)('B') | ((__u32)('D') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SGRBG10DPCM8" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SBGGR10" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SRGGB10" },
 { (unsigned)(((__u32)('M') | ((__u32)('4') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_M420" },
 { (unsigned)(((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_SN9C20X_I420" },
 { (unsigned)(((__u32)('J') | ((__u32)('L') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_JL2005BCD" },
 { (unsigned)(((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_TM6000" },
 { (unsigned)(((__u32)('S') | ((__u32)('6') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_STV0680" },
 { (unsigned)(((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_VP8" },
 { (unsigned)(((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('0') << 24))), "V4L2_PIX_FMT_VP9" },
 { (unsigned)(((__u32)('S') | ((__u32)('4') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_SE401" },
 { (unsigned)(((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_SPCA501" },
 { (unsigned)(((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_OV511" },
 { (unsigned)(((__u32)('M') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_MM21" },
 { (unsigned)(((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_NV21M" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_YVU420M" },
 { (unsigned)(((__u32)('M') | ((__u32)('T') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_MT21C" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_NV21" },
 { (unsigned)(((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_SPCA561" },
 { (unsigned)(((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_NV61M" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_YVU422M" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_NV61" },
 { (unsigned)(((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('8') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_SBGGR8" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_RGB332" },
 { (unsigned)(((__u32)('A') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_H264_NO_SC" },
 { (unsigned)(((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_PWC1" },
 { (unsigned)(((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('1') << 24))), "V4L2_PIX_FMT_MPEG1" },
 { (unsigned)(((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_SGRBG12" },
 { (unsigned)(((__u32)('G') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_BGRA444" },
 { (unsigned)(((__u32)('N') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12M_8L128" },
 { (unsigned)(((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_RGBA444" },
 { (unsigned)(((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_ABGR444" },
 { (unsigned)(((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_SGBRG12" },
 { (unsigned)(((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_XBGR444" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_SBGGR12" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_SRGGB12" },
 { (unsigned)(((__u32)('H') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12_16L16" },
 { (unsigned)(((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12M" },
 { (unsigned)(((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12MT" },
 { (unsigned)(((__u32)('V') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12MT_16X16" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_YUV420M" },
 { (unsigned)(((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_ARGB444" },
 { (unsigned)(((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_XRGB444" },
 { (unsigned)(((__u32)('S') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12_32L32" },
 { (unsigned)(((__u32)('V') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12_4L4" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_YUV420" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV12" },
 { (unsigned)(((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_YVU420" },
 { (unsigned)(((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_BGRX444" },
 { (unsigned)(((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_RGBX444" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_YVU444M" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_NV42" },
 { (unsigned)(((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_PWC2" },
 { (unsigned)(((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_MPEG2" },
 { (unsigned)(((__u32)('B') | ((__u32)('Y') << 8) | ((__u32)('R') << 16) | ((__u32)('2') << 24))), "V4L2_PIX_FMT_SBGGR16" },
 { (unsigned)(((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('3') << 24))), "V4L2_PIX_FMT_H263" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('3') << 24))), "V4L2_PIX_FMT_RGB24" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('3') << 24))), "V4L2_PIX_FMT_BGR24" },
 { (unsigned)(((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24))), "V4L2_PIX_FMT_HSV24" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24))), "V4L2_PIX_FMT_YUV24" },
 { (unsigned)(((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_SGBRG14" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_SBGGR14" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_SRGGB14" },
 { (unsigned)(((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_SGRBG14" },
 { (unsigned)(((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_ARGB32" },
 { (unsigned)(((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_BGRA32" },
 { (unsigned)(((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_RGBA32" },
 { (unsigned)(((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_RGBX32" },
 { (unsigned)(((__u32)('H') | ((__u32)('I') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_HI240" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_YUV444M" },
 { (unsigned)(((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_ABGR32" },
 { (unsigned)(((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_XBGR32" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_NV24" },
 { (unsigned)(((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_XRGB32" },
 { (unsigned)(((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_BGRX32" },
 { (unsigned)(((__u32)('R') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_RGB444" },
 { (unsigned)(((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_YUV444" },
 { (unsigned)(((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_H264" },
 { (unsigned)(((__u32)('M') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_H264_MVC" },
 { (unsigned)(((__u32)('S') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_H264_SLICE" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_RGB32" },
 { (unsigned)(((__u32)('C') | ((__u32)('N') << 8) | ((__u32)('F') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_CNF4" },
 { (unsigned)(((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_MPEG4" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_BGR32" },
 { (unsigned)(((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_HSV32" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24))), "V4L2_PIX_FMT_YUV32" },
 { (unsigned)(((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_SPCA505" },
 { (unsigned)(((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_BGRA555" },
 { (unsigned)(((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_RGBA555" },
 { (unsigned)(((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_ABGR555" },
 { (unsigned)(((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_XBGR555" },
 { (unsigned)(((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_ARGB555" },
 { (unsigned)(((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_XRGB555" },
 { (unsigned)(((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_BGRX555" },
 { (unsigned)(((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_RGBX555" },
 { (unsigned)(((__u32)('E') | ((__u32)('6') << 8) | ((__u32)('2') << 16) | ((__u32)('5') << 24))), "V4L2_PIX_FMT_ET61X251" },
 { (unsigned)(((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_SGBRG16" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_SRGGB16" },
 { (unsigned)(((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_NV16M" },
 { (unsigned)(((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_YUV422M" },
 { (unsigned)(((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_SGRBG16" },
 { (unsigned)(((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_PIX_FMT_NV16" },
 { (unsigned)(((__u32)('P') | ((__u32)('2') << 8) | ((__u32)('0') << 16) | ((__u32)('7') << 24))), "V4L2_PIX_FMT_PAC207" },
 { (unsigned)(((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SPCA508" },
 { (unsigned)(((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_OV518" },
 { (unsigned)(((__u32)('a') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SBGGR10ALAW8" },
 { (unsigned)(((__u32)('b') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SBGGR10DPCM8" },
 { (unsigned)(((__u32)('a') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SGBRG10ALAW8" },
 { (unsigned)(((__u32)('b') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SGBRG10DPCM8" },
 { (unsigned)(((__u32)('a') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SRGGB10ALAW8" },
 { (unsigned)(((__u32)('b') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SRGGB10DPCM8" },
 { (unsigned)(((__u32)('a') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_SGRBG10ALAW8" },
 { (unsigned)(((__u32)('P') | ((__u32)('A') << 8) | ((__u32)('L') << 16) | ((__u32)('8') << 24))), "V4L2_PIX_FMT_PAL8" },
 { (unsigned)(((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('U') << 16) | ((__u32)('9') << 24))), "V4L2_PIX_FMT_YVU410" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('9') << 24))), "V4L2_PIX_FMT_YUV410" },
 { (unsigned)(((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_SBGGR10P" },
 { (unsigned)(((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_SGBRG10P" },
 { (unsigned)(((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_SRGGB10P" },
 { (unsigned)(((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_SGRBG10P" },
 { (unsigned)(((__u32)('C') | ((__u32)('P') << 8) | ((__u32)('I') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_CPIA1" },
 { (unsigned)(((__u32)('W') | ((__u32)('N') << 8) | ((__u32)('V') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_WNVA" },
 { (unsigned)(((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('A') << 24))), "V4L2_PIX_FMT_VUYA32" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('B') << 24))), "V4L2_PIX_FMT_Y10BPACK" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('G') << 16) | ((__u32)('B') << 24))), "V4L2_PIX_FMT_SRGGB8" },
 { (unsigned)(((__u32)('Q') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_QC10C" },
 { (unsigned)(((__u32)('9') | ((__u32)('0') << 8) | ((__u32)('5') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_SQ905C" },
 { (unsigned)(((__u32)('Q') | ((__u32)('0') << 8) | ((__u32)('8') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_QC08C" },
 { (unsigned)(((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_SBGGR12P" },
 { (unsigned)(((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_SGBRG12P" },
 { (unsigned)(((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_SRGGB12P" },
 { (unsigned)(((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_SGRBG12P" },
 { (unsigned)(((__u32)('H') | ((__u32)('E') << 8) | ((__u32)('V') << 16) | ((__u32)('C') << 24))), "V4L2_PIX_FMT_HEVC" },
 { (unsigned)(((__u32)('X') | ((__u32)('V') << 8) | ((__u32)('I') << 16) | ((__u32)('D') << 24))), "V4L2_PIX_FMT_XVID" },
 { (unsigned)(((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))), "V4L2_PIX_FMT_SBGGR14P" },
 { (unsigned)(((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))), "V4L2_PIX_FMT_SGBRG14P" },
 { (unsigned)(((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))), "V4L2_PIX_FMT_SRGGB14P" },
 { (unsigned)(((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))), "V4L2_PIX_FMT_SGRBG14P" },
 { (unsigned)(((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('F') << 24))), "V4L2_PIX_FMT_VP8_FRAME" },
 { (unsigned)(((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('F') << 24))), "V4L2_PIX_FMT_VP9_FRAME" },
 { (unsigned)(((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_VC1_ANNEX_G" },
 { (unsigned)(((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_IPU3_SGRBG10" },
 { (unsigned)(((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('B') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_SGRBG8" },
 { (unsigned)(((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_JPEG" },
 { (unsigned)(((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_MPEG" },
 { (unsigned)(((__u32)('M') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_MJPEG" },
 { (unsigned)(((__u32)('P') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_PJPG" },
 { (unsigned)(((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('R') << 16) | ((__u32)('G') << 24))), "V4L2_PIX_FMT_SGBRG8" },
 { (unsigned)(((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('H') << 24))), "V4L2_PIX_FMT_BGR666" },
 { (unsigned)(((__u32)('S') | ((__u32)('F') << 8) | ((__u32)('W') << 16) | ((__u32)('H') << 24))), "V4L2_PIX_FMT_FWHT_STATELESS" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)('I') << 24))), "V4L2_PIX_FMT_Y12I" },
 { (unsigned)(((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('C') << 16) | ((__u32)('I') << 24))), "V4L2_PIX_FMT_S5C_UYVY_JPG" },
 { (unsigned)(((__u32)('K') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('I') << 24))), "V4L2_PIX_FMT_KONICA420" },
 { (unsigned)(((__u32)('I') | ((__u32)('N') << 8) | ((__u32)('Z') << 16) | ((__u32)('I') << 24))), "V4L2_PIX_FMT_INZI" },
 { (unsigned)(((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('L') << 24))), "V4L2_PIX_FMT_VC1_ANNEX_L" },
 { (unsigned)(((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('L') << 24))), "V4L2_PIX_FMT_JPGL" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('O') << 24))), "V4L2_PIX_FMT_RGB555" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('O') << 24))), "V4L2_PIX_FMT_YUV555" },
 { (unsigned)(((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_Y10P" },
 { (unsigned)(((__u32)('4') | ((__u32)('1') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_YUV411P" },
 { (unsigned)(((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_Y41P" },
 { (unsigned)(((__u32)('4') | ((__u32)('2') << 8) | ((__u32)('2') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_YUV422P" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_RGB565" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('P') << 24))), "V4L2_PIX_FMT_YUV565" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('Q') << 24))), "V4L2_PIX_FMT_RGB555X" },
 { (unsigned)(((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('R') << 24))), "V4L2_PIX_FMT_RGB565X" },
 { (unsigned)(((__u32)('M') | ((__u32)('G') << 8) | ((__u32)('2') << 16) | ((__u32)('S') << 24))), "V4L2_PIX_FMT_MPEG2_SLICE" },
 { (unsigned)(((__u32)('F') | ((__u32)('W') << 8) | ((__u32)('H') << 16) | ((__u32)('T') << 24))), "V4L2_PIX_FMT_FWHT" },
 { (unsigned)(((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('Y') << 16) | ((__u32)('U') << 24))), "V4L2_PIX_FMT_YVYU" },
 { (unsigned)(((__u32)('C') | ((__u32)('I') << 8) | ((__u32)('T') << 16) | ((__u32)('V') << 24))), "V4L2_PIX_FMT_CIT_YYVYUY" },
 { (unsigned)(((__u32)('A') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))), "V4L2_PIX_FMT_AYUV32" },
 { (unsigned)(((__u32)('X') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))), "V4L2_PIX_FMT_XYUV32" },
 { (unsigned)(((__u32)('Y') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))), "V4L2_PIX_FMT_YYUV" },
 { (unsigned)(((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('V') << 24))), "V4L2_PIX_FMT_YUYV" },
 { (unsigned)(((__u32)('S') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('X') << 24))), "V4L2_PIX_FMT_SN9C2028" },
 { (unsigned)(((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('X') << 24))), "V4L2_PIX_FMT_VUYX32" },
 { (unsigned)(((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('Y') << 24))), "V4L2_PIX_FMT_GREY" },
 { (unsigned)(((__u32)('V') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('Y') << 24))), "V4L2_PIX_FMT_VYUY" },
 { (unsigned)(((__u32)('U') | ((__u32)('Y') << 8) | ((__u32)('V') << 16) | ((__u32)('Y') << 24))), "V4L2_PIX_FMT_UYVY" },
 { (unsigned)(((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('b') << 24))), "V4L2_PIX_FMT_IPU3_SBGGR10" },
 { (unsigned)(((__u32)('d') | ((__u32)('v') << 8) | ((__u32)('s') << 16) | ((__u32)('d') << 24))), "V4L2_PIX_FMT_DV" },
 { (unsigned)(((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('g') << 24))), "V4L2_PIX_FMT_IPU3_SGBRG10" },
 { (unsigned)(((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('r') << 24))), "V4L2_PIX_FMT_IPU3_SRGGB10" },
 { (unsigned)(((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('y') << 24))), "V4L2_PIX_FMT_IPU3_Y10" },
 { (unsigned)((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)) | (1U << 31))), "V4L2_PIX_FMT_Y16_BE" },
 { (unsigned)((((__u32)('N') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)) | (1U << 31))), "V4L2_PIX_FMT_NV12M_10BE_8L128" },
 { (unsigned)((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31))), "V4L2_PIX_FMT_ARGB555X" },
 { (unsigned)((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31))), "V4L2_PIX_FMT_XRGB555X" },
};
const struct xlat v4l2_pix_fmts[1] = { {
 .data = v4l2_pix_fmts_xdata,
 .size = (sizeof(v4l2_pix_fmts_xdata) / sizeof((v4l2_pix_fmts_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_pix_fmts_xdata)), __typeof__(&(v4l2_pix_fmts_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('4') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('0') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Z') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('U') | ((__u32)('V') << 8) | ((__u32)('8') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('8') << 8) | ((__u32)('I') << 16) | ((__u32)(' ') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('3') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('D') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('4') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('9') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('J') | ((__u32)('L') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('6') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('4') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('T') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('6') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('8') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('V') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('1') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('T') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('4') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('W') << 8) | ((__u32)('C') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('Y') << 8) | ((__u32)('R') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('3') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('3') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('3') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('3') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('I') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('2') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('4') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('2') << 8) | ((__u32)('6') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('N') << 8) | ((__u32)('F') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('S') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('A') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('X') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('E') | ((__u32)('6') << 8) | ((__u32)('2') << 16) | ((__u32)('5') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('M') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('N') | ((__u32)('V') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('2') << 8) | ((__u32)('0') << 16) | ((__u32)('7') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('O') | ((__u32)('5') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('a') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('b') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('a') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('b') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('a') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('b') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('a') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('A') << 8) | ((__u32)('L') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('U') << 16) | ((__u32)('9') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('9') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('A') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('P') << 8) | ((__u32)('I') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('W') | ((__u32)('N') << 8) | ((__u32)('V') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('A') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('B') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('G') << 16) | ((__u32)('B') << 24))))
  | ((unsigned) (((__u32)('Q') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('9') | ((__u32)('0') << 8) | ((__u32)('5') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('Q') | ((__u32)('0') << 8) | ((__u32)('8') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('C') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('H') | ((__u32)('E') << 8) | ((__u32)('V') << 16) | ((__u32)('C') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('V') << 8) | ((__u32)('I') << 16) | ((__u32)('D') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('B') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('G') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))))
  | ((unsigned) (((__u32)('p') | ((__u32)('g') << 8) | ((__u32)('E') << 16) | ((__u32)('E') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('8') << 16) | ((__u32)('F') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('P') << 8) | ((__u32)('9') << 16) | ((__u32)('F') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('B') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('P') << 8) | ((__u32)('E') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('J') << 8) | ((__u32)('P') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('B') << 8) | ((__u32)('R') << 16) | ((__u32)('G') << 24))))
  | ((unsigned) (((__u32)('B') | ((__u32)('G') << 8) | ((__u32)('R') << 16) | ((__u32)('H') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('F') << 8) | ((__u32)('W') << 16) | ((__u32)('H') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('2') << 16) | ((__u32)('I') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('5') << 8) | ((__u32)('C') << 16) | ((__u32)('I') << 24))))
  | ((unsigned) (((__u32)('K') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('I') << 24))))
  | ((unsigned) (((__u32)('I') | ((__u32)('N') << 8) | ((__u32)('Z') << 16) | ((__u32)('I') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('L') << 24))))
  | ((unsigned) (((__u32)('J') | ((__u32)('P') << 8) | ((__u32)('G') << 16) | ((__u32)('L') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('O') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('O') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('0') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('4') | ((__u32)('1') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('4') << 8) | ((__u32)('1') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('4') | ((__u32)('2') << 8) | ((__u32)('2') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('V') << 16) | ((__u32)('P') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('Q') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('G') << 8) | ((__u32)('B') << 16) | ((__u32)('R') << 24))))
  | ((unsigned) (((__u32)('M') | ((__u32)('G') << 8) | ((__u32)('2') << 16) | ((__u32)('S') << 24))))
  | ((unsigned) (((__u32)('F') | ((__u32)('W') << 8) | ((__u32)('H') << 16) | ((__u32)('T') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('V') << 8) | ((__u32)('Y') << 16) | ((__u32)('U') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('I') << 8) | ((__u32)('T') << 16) | ((__u32)('V') << 24))))
  | ((unsigned) (((__u32)('A') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))))
  | ((unsigned) (((__u32)('X') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('V') << 24))))
  | ((unsigned) (((__u32)('Y') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('V') << 24))))
  | ((unsigned) (((__u32)('S') | ((__u32)('O') << 8) | ((__u32)('N') << 16) | ((__u32)('X') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('U') << 8) | ((__u32)('Y') << 16) | ((__u32)('X') << 24))))
  | ((unsigned) (((__u32)('G') | ((__u32)('R') << 8) | ((__u32)('E') << 16) | ((__u32)('Y') << 24))))
  | ((unsigned) (((__u32)('V') | ((__u32)('Y') << 8) | ((__u32)('U') << 16) | ((__u32)('Y') << 24))))
  | ((unsigned) (((__u32)('U') | ((__u32)('Y') << 8) | ((__u32)('V') << 16) | ((__u32)('Y') << 24))))
  | ((unsigned) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('b') << 24))))
  | ((unsigned) (((__u32)('d') | ((__u32)('v') << 8) | ((__u32)('s') << 16) | ((__u32)('d') << 24))))
  | ((unsigned) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('g') << 24))))
  | ((unsigned) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('r') << 24))))
  | ((unsigned) (((__u32)('i') | ((__u32)('p') << 8) | ((__u32)('3') << 16) | ((__u32)('y') << 24))))
  | ((unsigned) ((((__u32)('Y') | ((__u32)('1') << 8) | ((__u32)('6') << 16) | ((__u32)(' ') << 24)) | (1U << 31))))
  | ((unsigned) ((((__u32)('N') | ((__u32)('T') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)) | (1U << 31))))
  | ((unsigned) ((((__u32)('A') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31))))
  | ((unsigned) ((((__u32)('X') | ((__u32)('R') << 8) | ((__u32)('1') << 16) | ((__u32)('5') << 24)) | (1U << 31))))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_PIX_FMT_Y10")
  + sizeof("V4L2_PIX_FMT_Y12")
  + sizeof("V4L2_PIX_FMT_Y4")
  + sizeof("V4L2_PIX_FMT_Y14")
  + sizeof("V4L2_PIX_FMT_Y6")
  + sizeof("V4L2_PIX_FMT_Y16")
  + sizeof("V4L2_PIX_FMT_Z16")
  + sizeof("V4L2_PIX_FMT_UV8")
  + sizeof("V4L2_PIX_FMT_Y8I")
  + sizeof("V4L2_PIX_FMT_MR97310A")
  + sizeof("V4L2_PIX_FMT_SN9C10X")
  + sizeof("V4L2_PIX_FMT_SGRBG10")
  + sizeof("V4L2_PIX_FMT_SGBRG10")
  + sizeof("V4L2_PIX_FMT_SGRBG10DPCM8")
  + sizeof("V4L2_PIX_FMT_SBGGR10")
  + sizeof("V4L2_PIX_FMT_SRGGB10")
  + sizeof("V4L2_PIX_FMT_M420")
  + sizeof("V4L2_PIX_FMT_SN9C20X_I420")
  + sizeof("V4L2_PIX_FMT_JL2005BCD")
  + sizeof("V4L2_PIX_FMT_TM6000")
  + sizeof("V4L2_PIX_FMT_STV0680")
  + sizeof("V4L2_PIX_FMT_VP8")
  + sizeof("V4L2_PIX_FMT_VP9")
  + sizeof("V4L2_PIX_FMT_SE401")
  + sizeof("V4L2_PIX_FMT_SPCA501")
  + sizeof("V4L2_PIX_FMT_OV511")
  + sizeof("V4L2_PIX_FMT_MM21")
  + sizeof("V4L2_PIX_FMT_NV21M")
  + sizeof("V4L2_PIX_FMT_YVU420M")
  + sizeof("V4L2_PIX_FMT_MT21C")
  + sizeof("V4L2_PIX_FMT_NV21")
  + sizeof("V4L2_PIX_FMT_SPCA561")
  + sizeof("V4L2_PIX_FMT_NV61M")
  + sizeof("V4L2_PIX_FMT_YVU422M")
  + sizeof("V4L2_PIX_FMT_NV61")
  + sizeof("V4L2_PIX_FMT_SBGGR8")
  + sizeof("V4L2_PIX_FMT_RGB332")
  + sizeof("V4L2_PIX_FMT_H264_NO_SC")
  + sizeof("V4L2_PIX_FMT_PWC1")
  + sizeof("V4L2_PIX_FMT_MPEG1")
  + sizeof("V4L2_PIX_FMT_SGRBG12")
  + sizeof("V4L2_PIX_FMT_BGRA444")
  + sizeof("V4L2_PIX_FMT_NV12M_8L128")
  + sizeof("V4L2_PIX_FMT_RGBA444")
  + sizeof("V4L2_PIX_FMT_ABGR444")
  + sizeof("V4L2_PIX_FMT_SGBRG12")
  + sizeof("V4L2_PIX_FMT_XBGR444")
  + sizeof("V4L2_PIX_FMT_SBGGR12")
  + sizeof("V4L2_PIX_FMT_SRGGB12")
  + sizeof("V4L2_PIX_FMT_NV12_16L16")
  + sizeof("V4L2_PIX_FMT_NV12M")
  + sizeof("V4L2_PIX_FMT_NV12MT")
  + sizeof("V4L2_PIX_FMT_NV12MT_16X16")
  + sizeof("V4L2_PIX_FMT_YUV420M")
  + sizeof("V4L2_PIX_FMT_ARGB444")
  + sizeof("V4L2_PIX_FMT_XRGB444")
  + sizeof("V4L2_PIX_FMT_NV12_32L32")
  + sizeof("V4L2_PIX_FMT_NV12_4L4")
  + sizeof("V4L2_PIX_FMT_YUV420")
  + sizeof("V4L2_PIX_FMT_NV12")
  + sizeof("V4L2_PIX_FMT_YVU420")
  + sizeof("V4L2_PIX_FMT_BGRX444")
  + sizeof("V4L2_PIX_FMT_RGBX444")
  + sizeof("V4L2_PIX_FMT_YVU444M")
  + sizeof("V4L2_PIX_FMT_NV42")
  + sizeof("V4L2_PIX_FMT_PWC2")
  + sizeof("V4L2_PIX_FMT_MPEG2")
  + sizeof("V4L2_PIX_FMT_SBGGR16")
  + sizeof("V4L2_PIX_FMT_H263")
  + sizeof("V4L2_PIX_FMT_RGB24")
  + sizeof("V4L2_PIX_FMT_BGR24")
  + sizeof("V4L2_PIX_FMT_HSV24")
  + sizeof("V4L2_PIX_FMT_YUV24")
  + sizeof("V4L2_PIX_FMT_SGBRG14")
  + sizeof("V4L2_PIX_FMT_SBGGR14")
  + sizeof("V4L2_PIX_FMT_SRGGB14")
  + sizeof("V4L2_PIX_FMT_SGRBG14")
  + sizeof("V4L2_PIX_FMT_ARGB32")
  + sizeof("V4L2_PIX_FMT_BGRA32")
  + sizeof("V4L2_PIX_FMT_RGBA32")
  + sizeof("V4L2_PIX_FMT_RGBX32")
  + sizeof("V4L2_PIX_FMT_HI240")
  + sizeof("V4L2_PIX_FMT_YUV444M")
  + sizeof("V4L2_PIX_FMT_ABGR32")
  + sizeof("V4L2_PIX_FMT_XBGR32")
  + sizeof("V4L2_PIX_FMT_NV24")
  + sizeof("V4L2_PIX_FMT_XRGB32")
  + sizeof("V4L2_PIX_FMT_BGRX32")
  + sizeof("V4L2_PIX_FMT_RGB444")
  + sizeof("V4L2_PIX_FMT_YUV444")
  + sizeof("V4L2_PIX_FMT_H264")
  + sizeof("V4L2_PIX_FMT_H264_MVC")
  + sizeof("V4L2_PIX_FMT_H264_SLICE")
  + sizeof("V4L2_PIX_FMT_RGB32")
  + sizeof("V4L2_PIX_FMT_CNF4")
  + sizeof("V4L2_PIX_FMT_MPEG4")
  + sizeof("V4L2_PIX_FMT_BGR32")
  + sizeof("V4L2_PIX_FMT_HSV32")
  + sizeof("V4L2_PIX_FMT_YUV32")
  + sizeof("V4L2_PIX_FMT_SPCA505")
  + sizeof("V4L2_PIX_FMT_BGRA555")
  + sizeof("V4L2_PIX_FMT_RGBA555")
  + sizeof("V4L2_PIX_FMT_ABGR555")
  + sizeof("V4L2_PIX_FMT_XBGR555")
  + sizeof("V4L2_PIX_FMT_ARGB555")
  + sizeof("V4L2_PIX_FMT_XRGB555")
  + sizeof("V4L2_PIX_FMT_BGRX555")
  + sizeof("V4L2_PIX_FMT_RGBX555")
  + sizeof("V4L2_PIX_FMT_ET61X251")
  + sizeof("V4L2_PIX_FMT_SGBRG16")
  + sizeof("V4L2_PIX_FMT_SRGGB16")
  + sizeof("V4L2_PIX_FMT_NV16M")
  + sizeof("V4L2_PIX_FMT_YUV422M")
  + sizeof("V4L2_PIX_FMT_SGRBG16")
  + sizeof("V4L2_PIX_FMT_NV16")
  + sizeof("V4L2_PIX_FMT_PAC207")
  + sizeof("V4L2_PIX_FMT_SPCA508")
  + sizeof("V4L2_PIX_FMT_OV518")
  + sizeof("V4L2_PIX_FMT_SBGGR10ALAW8")
  + sizeof("V4L2_PIX_FMT_SBGGR10DPCM8")
  + sizeof("V4L2_PIX_FMT_SGBRG10ALAW8")
  + sizeof("V4L2_PIX_FMT_SGBRG10DPCM8")
  + sizeof("V4L2_PIX_FMT_SRGGB10ALAW8")
  + sizeof("V4L2_PIX_FMT_SRGGB10DPCM8")
  + sizeof("V4L2_PIX_FMT_SGRBG10ALAW8")
  + sizeof("V4L2_PIX_FMT_PAL8")
  + sizeof("V4L2_PIX_FMT_YVU410")
  + sizeof("V4L2_PIX_FMT_YUV410")
  + sizeof("V4L2_PIX_FMT_SBGGR10P")
  + sizeof("V4L2_PIX_FMT_SGBRG10P")
  + sizeof("V4L2_PIX_FMT_SRGGB10P")
  + sizeof("V4L2_PIX_FMT_SGRBG10P")
  + sizeof("V4L2_PIX_FMT_CPIA1")
  + sizeof("V4L2_PIX_FMT_WNVA")
  + sizeof("V4L2_PIX_FMT_VUYA32")
  + sizeof("V4L2_PIX_FMT_Y10BPACK")
  + sizeof("V4L2_PIX_FMT_SRGGB8")
  + sizeof("V4L2_PIX_FMT_QC10C")
  + sizeof("V4L2_PIX_FMT_SQ905C")
  + sizeof("V4L2_PIX_FMT_QC08C")
  + sizeof("V4L2_PIX_FMT_SBGGR12P")
  + sizeof("V4L2_PIX_FMT_SGBRG12P")
  + sizeof("V4L2_PIX_FMT_SRGGB12P")
  + sizeof("V4L2_PIX_FMT_SGRBG12P")
  + sizeof("V4L2_PIX_FMT_HEVC")
  + sizeof("V4L2_PIX_FMT_XVID")
  + sizeof("V4L2_PIX_FMT_SBGGR14P")
  + sizeof("V4L2_PIX_FMT_SGBRG14P")
  + sizeof("V4L2_PIX_FMT_SRGGB14P")
  + sizeof("V4L2_PIX_FMT_SGRBG14P")
  + sizeof("V4L2_PIX_FMT_VP8_FRAME")
  + sizeof("V4L2_PIX_FMT_VP9_FRAME")
  + sizeof("V4L2_PIX_FMT_VC1_ANNEX_G")
  + sizeof("V4L2_PIX_FMT_IPU3_SGRBG10")
  + sizeof("V4L2_PIX_FMT_SGRBG8")
  + sizeof("V4L2_PIX_FMT_JPEG")
  + sizeof("V4L2_PIX_FMT_MPEG")
  + sizeof("V4L2_PIX_FMT_MJPEG")
  + sizeof("V4L2_PIX_FMT_PJPG")
  + sizeof("V4L2_PIX_FMT_SGBRG8")
  + sizeof("V4L2_PIX_FMT_BGR666")
  + sizeof("V4L2_PIX_FMT_FWHT_STATELESS")
  + sizeof("V4L2_PIX_FMT_Y12I")
  + sizeof("V4L2_PIX_FMT_S5C_UYVY_JPG")
  + sizeof("V4L2_PIX_FMT_KONICA420")
  + sizeof("V4L2_PIX_FMT_INZI")
  + sizeof("V4L2_PIX_FMT_VC1_ANNEX_L")
  + sizeof("V4L2_PIX_FMT_JPGL")
  + sizeof("V4L2_PIX_FMT_RGB555")
  + sizeof("V4L2_PIX_FMT_YUV555")
  + sizeof("V4L2_PIX_FMT_Y10P")
  + sizeof("V4L2_PIX_FMT_YUV411P")
  + sizeof("V4L2_PIX_FMT_Y41P")
  + sizeof("V4L2_PIX_FMT_YUV422P")
  + sizeof("V4L2_PIX_FMT_RGB565")
  + sizeof("V4L2_PIX_FMT_YUV565")
  + sizeof("V4L2_PIX_FMT_RGB555X")
  + sizeof("V4L2_PIX_FMT_RGB565X")
  + sizeof("V4L2_PIX_FMT_MPEG2_SLICE")
  + sizeof("V4L2_PIX_FMT_FWHT")
  + sizeof("V4L2_PIX_FMT_YVYU")
  + sizeof("V4L2_PIX_FMT_CIT_YYVYUY")
  + sizeof("V4L2_PIX_FMT_AYUV32")
  + sizeof("V4L2_PIX_FMT_XYUV32")
  + sizeof("V4L2_PIX_FMT_YYUV")
  + sizeof("V4L2_PIX_FMT_YUYV")
  + sizeof("V4L2_PIX_FMT_SN9C2028")
  + sizeof("V4L2_PIX_FMT_VUYX32")
  + sizeof("V4L2_PIX_FMT_GREY")
  + sizeof("V4L2_PIX_FMT_VYUY")
  + sizeof("V4L2_PIX_FMT_UYVY")
  + sizeof("V4L2_PIX_FMT_IPU3_SBGGR10")
  + sizeof("V4L2_PIX_FMT_DV")
  + sizeof("V4L2_PIX_FMT_IPU3_SGBRG10")
  + sizeof("V4L2_PIX_FMT_IPU3_SRGGB10")
  + sizeof("V4L2_PIX_FMT_IPU3_Y10")
  + sizeof("V4L2_PIX_FMT_Y16_BE")
  + sizeof("V4L2_PIX_FMT_NV12M_10BE_8L128")
  + sizeof("V4L2_PIX_FMT_ARGB555X")
  + sizeof("V4L2_PIX_FMT_XRGB555X")
  ,
} };

_Static_assert((unsigned long long) (((__u32)('R') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_RU12LE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))
      > (unsigned long long) ((((__u32)('R') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_CS14LE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_PCU16BE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))
      > (unsigned long long) ((((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_CU16LE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_CS8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_CU8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24)))
      > (unsigned long long) ((((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24)))),
      "Incorrect order in #sorted xlat: V4L2_SDR_FMT_PCU18BE"
      " is not larger than the previous value");

static const struct xlat_data v4l2_sdr_fmts_xdata[] = {
 { (unsigned)(((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))), "V4L2_SDR_FMT_PCU20BE" },
 { (unsigned)(((__u32)('R') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))), "V4L2_SDR_FMT_RU12LE" },
 { (unsigned)(((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))), "V4L2_SDR_FMT_CS14LE" },
 { (unsigned)(((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_SDR_FMT_PCU16BE" },
 { (unsigned)(((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))), "V4L2_SDR_FMT_CU16LE" },
 { (unsigned)(((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))), "V4L2_SDR_FMT_CS8" },
 { (unsigned)(((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))), "V4L2_SDR_FMT_CU8" },
 { (unsigned)(((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24))), "V4L2_SDR_FMT_PCU18BE" },
};
const struct xlat v4l2_sdr_fmts[1] = { {
 .data = v4l2_sdr_fmts_xdata,
 .size = (sizeof(v4l2_sdr_fmts_xdata) / sizeof((v4l2_sdr_fmts_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_sdr_fmts_xdata)), __typeof__(&(v4l2_sdr_fmts_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('2') << 16) | ((__u32)('0') << 24))))
  | ((unsigned) (((__u32)('R') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('2') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('1') << 16) | ((__u32)('4') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('1') << 16) | ((__u32)('6') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('S') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('C') | ((__u32)('U') << 8) | ((__u32)('0') << 16) | ((__u32)('8') << 24))))
  | ((unsigned) (((__u32)('P') | ((__u32)('C') << 8) | ((__u32)('1') << 16) | ((__u32)('8') << 24))))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_SDR_FMT_PCU20BE")
  + sizeof("V4L2_SDR_FMT_RU12LE")
  + sizeof("V4L2_SDR_FMT_CS14LE")
  + sizeof("V4L2_SDR_FMT_PCU16BE")
  + sizeof("V4L2_SDR_FMT_CU16LE")
  + sizeof("V4L2_SDR_FMT_CS8")
  + sizeof("V4L2_SDR_FMT_CU8")
  + sizeof("V4L2_SDR_FMT_PCU18BE")
  ,
} };

static void
print_v4l2_rect(const struct v4l2_rect * const arg)
{
 const struct v4l2_rect *const p = arg;
 tprint_struct_begin();
 do { tprints_field_name("left"); tprintf_string("%lld", (sizeof((*p).left) == sizeof(char) ? (long long) (char) ((*p).left) : sizeof((*p).left) == sizeof(short) ? (long long) (short) ((*p).left) : sizeof((*p).left) == sizeof(int) ? (long long) (int) ((*p).left) : sizeof((*p).left) == sizeof(long) ? (long long) (long) ((*p).left) : (long long) ((*p).left))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("top"); tprintf_string("%lld", (sizeof((*p).top) == sizeof(char) ? (long long) (char) ((*p).top) : sizeof((*p).top) == sizeof(short) ? (long long) (short) ((*p).top) : sizeof((*p).top) == sizeof(int) ? (long long) (int) ((*p).top) : sizeof((*p).top) == sizeof(long) ? (long long) (long) ((*p).top) : (long long) ((*p).top))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("width"); tprintf_string("%llu", (sizeof((*p).width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).width) : sizeof((*p).width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).width) : sizeof((*p).width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).width) : sizeof((*p).width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).width) : (unsigned long long) ((*p).width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("height"); tprintf_string("%llu", (sizeof((*p).height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).height) : sizeof((*p).height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).height) : sizeof((*p).height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).height) : sizeof((*p).height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).height) : (unsigned long long) ((*p).height))); } while (0);
 tprint_struct_end();
}
static void
print_pixelformat(uint32_t fourcc, const struct xlat *xlat)
{
 if (((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_RAW) {
  tprintf_string("%#llx", (sizeof(fourcc) == sizeof(char) ? (unsigned long long) (unsigned char) (fourcc) : sizeof(fourcc) == sizeof(short) ? (unsigned long long) (unsigned short) (fourcc) : sizeof(fourcc) == sizeof(int) ? (unsigned long long) (unsigned int) (fourcc) : sizeof(fourcc) == sizeof(long) ? (unsigned long long) (unsigned long) (fourcc) : (unsigned long long) (fourcc)));
  return;
 }
 unsigned char a[] = {
  (unsigned char) fourcc,
  (unsigned char) (fourcc >> 8),
  (unsigned char) (fourcc >> 16),
  (unsigned char) (fourcc >> 24),
 };
 tprints_arg_begin("v4l2_fourcc");
 for (unsigned int i = 0; i < (sizeof(a) / sizeof((a)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((a)), __typeof__(&(a)[0])))]) * 0)); ++i) {
  unsigned char c = a[i];
  if (i)
   tprint_arg_next();
  do { char buf[7]; sprint_char(buf, (c), (SCF_QUOTES) | SCF_NUL); tprints_string(buf); } while (0);
 }
 tprint_arg_end();
 if (xlat) {
  const char *pixfmt_name = xlookup(xlat, fourcc);
  if (pixfmt_name)
   tprints_comment(pixfmt_name);
 }
}

static const struct xlat_data v4l2_device_capabilities_flags_xdata[] = {
 { (unsigned)(0x00000001), "V4L2_CAP_VIDEO_CAPTURE" },
 { (unsigned)(0x00000002), "V4L2_CAP_VIDEO_OUTPUT" },
 { (unsigned)(0x00000004), "V4L2_CAP_VIDEO_OVERLAY" },
 { (unsigned)(0x00000010), "V4L2_CAP_VBI_CAPTURE" },
 { (unsigned)(0x00000020), "V4L2_CAP_VBI_OUTPUT" },
 { (unsigned)(0x00000040), "V4L2_CAP_SLICED_VBI_CAPTURE" },
 { (unsigned)(0x00000080), "V4L2_CAP_SLICED_VBI_OUTPUT" },
 { (unsigned)(0x00000100), "V4L2_CAP_RDS_CAPTURE" },
 { (unsigned)(0x00000200), "V4L2_CAP_VIDEO_OUTPUT_OVERLAY" },
 { (unsigned)(0x00000400), "V4L2_CAP_HW_FREQ_SEEK" },
 { (unsigned)(0x00000800), "V4L2_CAP_RDS_OUTPUT" },
 { (unsigned)(0x00001000), "V4L2_CAP_VIDEO_CAPTURE_MPLANE" },
 { (unsigned)(0x00002000), "V4L2_CAP_VIDEO_OUTPUT_MPLANE" },
 { (unsigned)(0x00004000), "V4L2_CAP_VIDEO_M2M_MPLANE" },
 { (unsigned)(0x00008000), "V4L2_CAP_VIDEO_M2M" },
 { (unsigned)(0x00010000), "V4L2_CAP_TUNER" },
 { (unsigned)(0x00020000), "V4L2_CAP_AUDIO" },
 { (unsigned)(0x00040000), "V4L2_CAP_RADIO" },
 { (unsigned)(0x00080000), "V4L2_CAP_MODULATOR" },
 { (unsigned)(0x00100000), "V4L2_CAP_SDR_CAPTURE" },
 { (unsigned)(0x00200000), "V4L2_CAP_EXT_PIX_FORMAT" },
 { (unsigned)(0x00400000), "V4L2_CAP_SDR_OUTPUT" },
 { (unsigned)(0x00800000), "V4L2_CAP_META_CAPTURE" },
 { (unsigned)(0x01000000), "V4L2_CAP_READWRITE" },
 { (unsigned)(0x02000000), "V4L2_CAP_ASYNCIO" },
 { (unsigned)(0x04000000), "V4L2_CAP_STREAMING" },
 { (unsigned)(0x08000000), "V4L2_CAP_META_OUTPUT" },
 { (unsigned)(0x10000000), "V4L2_CAP_TOUCH" },
 { (unsigned)(0x80000000), "V4L2_CAP_DEVICE_CAPS" },
};
const struct xlat v4l2_device_capabilities_flags[1] = { {
 .data = v4l2_device_capabilities_flags_xdata,
 .size = (sizeof(v4l2_device_capabilities_flags_xdata) / sizeof((v4l2_device_capabilities_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_device_capabilities_flags_xdata)), __typeof__(&(v4l2_device_capabilities_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x00000001))
  | ((unsigned) (0x00000002))
  | ((unsigned) (0x00000004))
  | ((unsigned) (0x00000010))
  | ((unsigned) (0x00000020))
  | ((unsigned) (0x00000040))
  | ((unsigned) (0x00000080))
  | ((unsigned) (0x00000100))
  | ((unsigned) (0x00000200))
  | ((unsigned) (0x00000400))
  | ((unsigned) (0x00000800))
  | ((unsigned) (0x00001000))
  | ((unsigned) (0x00002000))
  | ((unsigned) (0x00004000))
  | ((unsigned) (0x00008000))
  | ((unsigned) (0x00010000))
  | ((unsigned) (0x00020000))
  | ((unsigned) (0x00040000))
  | ((unsigned) (0x00080000))
  | ((unsigned) (0x00100000))
  | ((unsigned) (0x00200000))
  | ((unsigned) (0x00400000))
  | ((unsigned) (0x00800000))
  | ((unsigned) (0x01000000))
  | ((unsigned) (0x02000000))
  | ((unsigned) (0x04000000))
  | ((unsigned) (0x08000000))
  | ((unsigned) (0x10000000))
  | ((unsigned) (0x80000000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CAP_VIDEO_CAPTURE")
  + sizeof("V4L2_CAP_VIDEO_OUTPUT")
  + sizeof("V4L2_CAP_VIDEO_OVERLAY")
  + sizeof("V4L2_CAP_VBI_CAPTURE")
  + sizeof("V4L2_CAP_VBI_OUTPUT")
  + sizeof("V4L2_CAP_SLICED_VBI_CAPTURE")
  + sizeof("V4L2_CAP_SLICED_VBI_OUTPUT")
  + sizeof("V4L2_CAP_RDS_CAPTURE")
  + sizeof("V4L2_CAP_VIDEO_OUTPUT_OVERLAY")
  + sizeof("V4L2_CAP_HW_FREQ_SEEK")
  + sizeof("V4L2_CAP_RDS_OUTPUT")
  + sizeof("V4L2_CAP_VIDEO_CAPTURE_MPLANE")
  + sizeof("V4L2_CAP_VIDEO_OUTPUT_MPLANE")
  + sizeof("V4L2_CAP_VIDEO_M2M_MPLANE")
  + sizeof("V4L2_CAP_VIDEO_M2M")
  + sizeof("V4L2_CAP_TUNER")
  + sizeof("V4L2_CAP_AUDIO")
  + sizeof("V4L2_CAP_RADIO")
  + sizeof("V4L2_CAP_MODULATOR")
  + sizeof("V4L2_CAP_SDR_CAPTURE")
  + sizeof("V4L2_CAP_EXT_PIX_FORMAT")
  + sizeof("V4L2_CAP_SDR_OUTPUT")
  + sizeof("V4L2_CAP_META_CAPTURE")
  + sizeof("V4L2_CAP_READWRITE")
  + sizeof("V4L2_CAP_ASYNCIO")
  + sizeof("V4L2_CAP_STREAMING")
  + sizeof("V4L2_CAP_META_OUTPUT")
  + sizeof("V4L2_CAP_TOUCH")
  + sizeof("V4L2_CAP_DEVICE_CAPS")
  ,
} };

static int
print_v4l2_capability(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_capability caps;
 if ((!((tcp)->flags & 0x04)))
  return 0;
 tprint_arg_next();
 if (umoven_or_printaddr((tcp), (arg), sizeof(*(&caps)), (void *) (&caps)))
  return 0200;
 tprint_struct_begin();
 do { tprints_field_name("driver"); print_quoted_cstring((const char *) (caps).driver, sizeof((caps).driver) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((caps).driver)), __typeof__(&((caps).driver)[0])))]) * 0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("card"); print_quoted_cstring((const char *) (caps).card, sizeof((caps).card) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((caps).card)), __typeof__(&((caps).card)[0])))]) * 0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("bus_info"); print_quoted_cstring((const char *) (caps).bus_info, sizeof((caps).bus_info) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((caps).bus_info)), __typeof__(&((caps).bus_info)[0])))]) * 0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("version"); (print_kernel_version)((caps).version); } while (0);
 tprint_struct_next();
 do { tprints_field_name("capabilities"); printflags64((v4l2_device_capabilities_flags), (sizeof((caps).capabilities) == sizeof(char) ? (unsigned long long) (unsigned char) ((caps).capabilities) : sizeof((caps).capabilities) == sizeof(short) ? (unsigned long long) (unsigned short) ((caps).capabilities) : sizeof((caps).capabilities) == sizeof(int) ? (unsigned long long) (unsigned int) ((caps).capabilities) : sizeof((caps).capabilities) == sizeof(long) ? (unsigned long long) (unsigned long) ((caps).capabilities) : (unsigned long long) ((caps).capabilities)), ("V4L2_CAP_???")); } while (0);
 if (caps.device_caps) {
  tprint_struct_next();
  do { tprints_field_name("device_caps"); printflags64((v4l2_device_capabilities_flags), (sizeof((caps).device_caps) == sizeof(char) ? (unsigned long long) (unsigned char) ((caps).device_caps) : sizeof((caps).device_caps) == sizeof(short) ? (unsigned long long) (unsigned short) ((caps).device_caps) : sizeof((caps).device_caps) == sizeof(int) ? (unsigned long long) (unsigned int) ((caps).device_caps) : sizeof((caps).device_caps) == sizeof(long) ? (unsigned long long) (unsigned long) ((caps).device_caps) : (unsigned long long) ((caps).device_caps)), ("V4L2_CAP_???")); } while (0);
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_buf_types_xdata[] = {
 [V4L2_BUF_TYPE_VIDEO_CAPTURE] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_CAPTURE), "V4L2_BUF_TYPE_VIDEO_CAPTURE" },
 [V4L2_BUF_TYPE_VIDEO_OUTPUT] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_OUTPUT), "V4L2_BUF_TYPE_VIDEO_OUTPUT" },
 [V4L2_BUF_TYPE_VIDEO_OVERLAY] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_OVERLAY), "V4L2_BUF_TYPE_VIDEO_OVERLAY" },
 [V4L2_BUF_TYPE_VBI_CAPTURE] = { (unsigned)(V4L2_BUF_TYPE_VBI_CAPTURE), "V4L2_BUF_TYPE_VBI_CAPTURE" },
 [V4L2_BUF_TYPE_VBI_OUTPUT] = { (unsigned)(V4L2_BUF_TYPE_VBI_OUTPUT), "V4L2_BUF_TYPE_VBI_OUTPUT" },
 [V4L2_BUF_TYPE_SLICED_VBI_CAPTURE] = { (unsigned)(V4L2_BUF_TYPE_SLICED_VBI_CAPTURE), "V4L2_BUF_TYPE_SLICED_VBI_CAPTURE" },
 [V4L2_BUF_TYPE_SLICED_VBI_OUTPUT] = { (unsigned)(V4L2_BUF_TYPE_SLICED_VBI_OUTPUT), "V4L2_BUF_TYPE_SLICED_VBI_OUTPUT" },
 [V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY), "V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY" },
 [V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE), "V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE" },
 [V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE] = { (unsigned)(V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE), "V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE" },
 [V4L2_BUF_TYPE_SDR_CAPTURE] = { (unsigned)(V4L2_BUF_TYPE_SDR_CAPTURE), "V4L2_BUF_TYPE_SDR_CAPTURE" },
 [V4L2_BUF_TYPE_SDR_OUTPUT] = { (unsigned)(V4L2_BUF_TYPE_SDR_OUTPUT), "V4L2_BUF_TYPE_SDR_OUTPUT" },
 [V4L2_BUF_TYPE_META_CAPTURE] = { (unsigned)(V4L2_BUF_TYPE_META_CAPTURE), "V4L2_BUF_TYPE_META_CAPTURE" },
 [V4L2_BUF_TYPE_META_OUTPUT] = { (unsigned)(V4L2_BUF_TYPE_META_OUTPUT), "V4L2_BUF_TYPE_META_OUTPUT" },
};
const struct xlat v4l2_buf_types[1] = { {
 .data = v4l2_buf_types_xdata,
 .size = (sizeof(v4l2_buf_types_xdata) / sizeof((v4l2_buf_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_buf_types_xdata)), __typeof__(&(v4l2_buf_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_CAPTURE))
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_OUTPUT))
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_OVERLAY))
  | ((unsigned) (V4L2_BUF_TYPE_VBI_CAPTURE))
  | ((unsigned) (V4L2_BUF_TYPE_VBI_OUTPUT))
  | ((unsigned) (V4L2_BUF_TYPE_SLICED_VBI_CAPTURE))
  | ((unsigned) (V4L2_BUF_TYPE_SLICED_VBI_OUTPUT))
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY))
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE))
  | ((unsigned) (V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE))
  | ((unsigned) (V4L2_BUF_TYPE_SDR_CAPTURE))
  | ((unsigned) (V4L2_BUF_TYPE_SDR_OUTPUT))
  | ((unsigned) (V4L2_BUF_TYPE_META_CAPTURE))
  | ((unsigned) (V4L2_BUF_TYPE_META_OUTPUT))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_BUF_TYPE_VIDEO_CAPTURE")
  + sizeof("V4L2_BUF_TYPE_VIDEO_OUTPUT")
  + sizeof("V4L2_BUF_TYPE_VIDEO_OVERLAY")
  + sizeof("V4L2_BUF_TYPE_VBI_CAPTURE")
  + sizeof("V4L2_BUF_TYPE_VBI_OUTPUT")
  + sizeof("V4L2_BUF_TYPE_SLICED_VBI_CAPTURE")
  + sizeof("V4L2_BUF_TYPE_SLICED_VBI_OUTPUT")
  + sizeof("V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY")
  + sizeof("V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE")
  + sizeof("V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE")
  + sizeof("V4L2_BUF_TYPE_SDR_CAPTURE")
  + sizeof("V4L2_BUF_TYPE_SDR_OUTPUT")
  + sizeof("V4L2_BUF_TYPE_META_CAPTURE")
  + sizeof("V4L2_BUF_TYPE_META_OUTPUT")
  ,
} };


static const struct xlat_data v4l2_format_description_flags_xdata[] = {
 { (unsigned)(0x0001), "V4L2_FMT_FLAG_COMPRESSED" },
 { (unsigned)(0x0002), "V4L2_FMT_FLAG_EMULATED" },
 { (unsigned)(0x0004), "V4L2_FMT_FLAG_CONTINUOUS_BYTESTREAM" },
 { (unsigned)(0x0008), "V4L2_FMT_FLAG_DYN_RESOLUTION" },
 { (unsigned)(0x0010), "V4L2_FMT_FLAG_ENC_CAP_FRAME_INTERVAL" },
 { (unsigned)(0x0020), "V4L2_FMT_FLAG_CSC_COLORSPACE" },
 { (unsigned)(0x0040), "V4L2_FMT_FLAG_CSC_XFER_FUNC" },
 { (unsigned)(0x0080), "V4L2_FMT_FLAG_CSC_YCBCR_ENC" },
 { (unsigned)(0x0100), "V4L2_FMT_FLAG_CSC_QUANTIZATION" },
};
const struct xlat v4l2_format_description_flags[1] = { {
 .data = v4l2_format_description_flags_xdata,
 .size = (sizeof(v4l2_format_description_flags_xdata) / sizeof((v4l2_format_description_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_format_description_flags_xdata)), __typeof__(&(v4l2_format_description_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x0001))
  | ((unsigned) (0x0002))
  | ((unsigned) (0x0004))
  | ((unsigned) (0x0008))
  | ((unsigned) (0x0010))
  | ((unsigned) (0x0020))
  | ((unsigned) (0x0040))
  | ((unsigned) (0x0080))
  | ((unsigned) (0x0100))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_FMT_FLAG_COMPRESSED")
  + sizeof("V4L2_FMT_FLAG_EMULATED")
  + sizeof("V4L2_FMT_FLAG_CONTINUOUS_BYTESTREAM")
  + sizeof("V4L2_FMT_FLAG_DYN_RESOLUTION")
  + sizeof("V4L2_FMT_FLAG_ENC_CAP_FRAME_INTERVAL")
  + sizeof("V4L2_FMT_FLAG_CSC_COLORSPACE")
  + sizeof("V4L2_FMT_FLAG_CSC_XFER_FUNC")
  + sizeof("V4L2_FMT_FLAG_CSC_YCBCR_ENC")
  + sizeof("V4L2_FMT_FLAG_CSC_QUANTIZATION")
  ,
} };

static int
print_v4l2_fmtdesc(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_fmtdesc f;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&f)), (void *) (&f)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((f).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).index) : sizeof((f).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).index) : sizeof((f).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).index) : sizeof((f).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).index) : (unsigned long long) ((f).index))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((f).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).type) : sizeof((f).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).type) : sizeof((f).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).type) : sizeof((f).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).type) : (unsigned long long) ((f).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&f)), (void *) (&f))) {
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((v4l2_format_description_flags), (sizeof((f).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).flags) : sizeof((f).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).flags) : sizeof((f).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).flags) : sizeof((f).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).flags) : (unsigned long long) ((f).flags)), ("V4L2_FMT_FLAG_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("description"); print_quoted_cstring((const char *) (f).description, sizeof((f).description) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((f).description)), __typeof__(&((f).description)[0])))]) * 0)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("pixelformat"); print_pixelformat((f).pixelformat, (v4l2_pix_fmts)); } while (0);
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_fields_xdata[] = {
 [V4L2_FIELD_ANY] = { (unsigned)(V4L2_FIELD_ANY), "V4L2_FIELD_ANY" },
 [V4L2_FIELD_NONE] = { (unsigned)(V4L2_FIELD_NONE), "V4L2_FIELD_NONE" },
 [V4L2_FIELD_TOP] = { (unsigned)(V4L2_FIELD_TOP), "V4L2_FIELD_TOP" },
 [V4L2_FIELD_BOTTOM] = { (unsigned)(V4L2_FIELD_BOTTOM), "V4L2_FIELD_BOTTOM" },
 [V4L2_FIELD_INTERLACED] = { (unsigned)(V4L2_FIELD_INTERLACED), "V4L2_FIELD_INTERLACED" },
 [V4L2_FIELD_SEQ_TB] = { (unsigned)(V4L2_FIELD_SEQ_TB), "V4L2_FIELD_SEQ_TB" },
 [V4L2_FIELD_SEQ_BT] = { (unsigned)(V4L2_FIELD_SEQ_BT), "V4L2_FIELD_SEQ_BT" },
 [V4L2_FIELD_ALTERNATE] = { (unsigned)(V4L2_FIELD_ALTERNATE), "V4L2_FIELD_ALTERNATE" },
 [V4L2_FIELD_INTERLACED_TB] = { (unsigned)(V4L2_FIELD_INTERLACED_TB), "V4L2_FIELD_INTERLACED_TB" },
 [V4L2_FIELD_INTERLACED_BT] = { (unsigned)(V4L2_FIELD_INTERLACED_BT), "V4L2_FIELD_INTERLACED_BT" },
};
const struct xlat v4l2_fields[1] = { {
 .data = v4l2_fields_xdata,
 .size = (sizeof(v4l2_fields_xdata) / sizeof((v4l2_fields_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_fields_xdata)), __typeof__(&(v4l2_fields_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_FIELD_ANY))
  | ((unsigned) (V4L2_FIELD_NONE))
  | ((unsigned) (V4L2_FIELD_TOP))
  | ((unsigned) (V4L2_FIELD_BOTTOM))
  | ((unsigned) (V4L2_FIELD_INTERLACED))
  | ((unsigned) (V4L2_FIELD_SEQ_TB))
  | ((unsigned) (V4L2_FIELD_SEQ_BT))
  | ((unsigned) (V4L2_FIELD_ALTERNATE))
  | ((unsigned) (V4L2_FIELD_INTERLACED_TB))
  | ((unsigned) (V4L2_FIELD_INTERLACED_BT))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_FIELD_ANY")
  + sizeof("V4L2_FIELD_NONE")
  + sizeof("V4L2_FIELD_TOP")
  + sizeof("V4L2_FIELD_BOTTOM")
  + sizeof("V4L2_FIELD_INTERLACED")
  + sizeof("V4L2_FIELD_SEQ_TB")
  + sizeof("V4L2_FIELD_SEQ_BT")
  + sizeof("V4L2_FIELD_ALTERNATE")
  + sizeof("V4L2_FIELD_INTERLACED_TB")
  + sizeof("V4L2_FIELD_INTERLACED_BT")
  ,
} };


static const struct xlat_data v4l2_colorspaces_xdata[] = {
 [V4L2_COLORSPACE_DEFAULT] = { (unsigned)(V4L2_COLORSPACE_DEFAULT), "V4L2_COLORSPACE_DEFAULT" },
 [V4L2_COLORSPACE_SMPTE170M] = { (unsigned)(V4L2_COLORSPACE_SMPTE170M), "V4L2_COLORSPACE_SMPTE170M" },
 [V4L2_COLORSPACE_SMPTE240M] = { (unsigned)(V4L2_COLORSPACE_SMPTE240M), "V4L2_COLORSPACE_SMPTE240M" },
 [V4L2_COLORSPACE_REC709] = { (unsigned)(V4L2_COLORSPACE_REC709), "V4L2_COLORSPACE_REC709" },
 [V4L2_COLORSPACE_BT878] = { (unsigned)(V4L2_COLORSPACE_BT878), "V4L2_COLORSPACE_BT878" },
 [V4L2_COLORSPACE_470_SYSTEM_M] = { (unsigned)(V4L2_COLORSPACE_470_SYSTEM_M), "V4L2_COLORSPACE_470_SYSTEM_M" },
 [V4L2_COLORSPACE_470_SYSTEM_BG] = { (unsigned)(V4L2_COLORSPACE_470_SYSTEM_BG), "V4L2_COLORSPACE_470_SYSTEM_BG" },
 [V4L2_COLORSPACE_JPEG] = { (unsigned)(V4L2_COLORSPACE_JPEG), "V4L2_COLORSPACE_JPEG" },
 [V4L2_COLORSPACE_SRGB] = { (unsigned)(V4L2_COLORSPACE_SRGB), "V4L2_COLORSPACE_SRGB" },
 [V4L2_COLORSPACE_OPRGB] = { (unsigned)(V4L2_COLORSPACE_OPRGB), "V4L2_COLORSPACE_OPRGB" },
 [V4L2_COLORSPACE_BT2020] = { (unsigned)(V4L2_COLORSPACE_BT2020), "V4L2_COLORSPACE_BT2020" },
 [V4L2_COLORSPACE_RAW] = { (unsigned)(V4L2_COLORSPACE_RAW), "V4L2_COLORSPACE_RAW" },
 [V4L2_COLORSPACE_DCI_P3] = { (unsigned)(V4L2_COLORSPACE_DCI_P3), "V4L2_COLORSPACE_DCI_P3" },
};
const struct xlat v4l2_colorspaces[1] = { {
 .data = v4l2_colorspaces_xdata,
 .size = (sizeof(v4l2_colorspaces_xdata) / sizeof((v4l2_colorspaces_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_colorspaces_xdata)), __typeof__(&(v4l2_colorspaces_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_COLORSPACE_DEFAULT))
  | ((unsigned) (V4L2_COLORSPACE_SMPTE170M))
  | ((unsigned) (V4L2_COLORSPACE_SMPTE240M))
  | ((unsigned) (V4L2_COLORSPACE_REC709))
  | ((unsigned) (V4L2_COLORSPACE_BT878))
  | ((unsigned) (V4L2_COLORSPACE_470_SYSTEM_M))
  | ((unsigned) (V4L2_COLORSPACE_470_SYSTEM_BG))
  | ((unsigned) (V4L2_COLORSPACE_JPEG))
  | ((unsigned) (V4L2_COLORSPACE_SRGB))
  | ((unsigned) (V4L2_COLORSPACE_OPRGB))
  | ((unsigned) (V4L2_COLORSPACE_BT2020))
  | ((unsigned) (V4L2_COLORSPACE_RAW))
  | ((unsigned) (V4L2_COLORSPACE_DCI_P3))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_COLORSPACE_DEFAULT")
  + sizeof("V4L2_COLORSPACE_SMPTE170M")
  + sizeof("V4L2_COLORSPACE_SMPTE240M")
  + sizeof("V4L2_COLORSPACE_REC709")
  + sizeof("V4L2_COLORSPACE_BT878")
  + sizeof("V4L2_COLORSPACE_470_SYSTEM_M")
  + sizeof("V4L2_COLORSPACE_470_SYSTEM_BG")
  + sizeof("V4L2_COLORSPACE_JPEG")
  + sizeof("V4L2_COLORSPACE_SRGB")
  + sizeof("V4L2_COLORSPACE_OPRGB")
  + sizeof("V4L2_COLORSPACE_BT2020")
  + sizeof("V4L2_COLORSPACE_RAW")
  + sizeof("V4L2_COLORSPACE_DCI_P3")
  ,
} };


static const struct xlat_data v4l2_vbi_flags_xdata[] = {
 { (unsigned)((1 << 0)), "V4L2_VBI_UNSYNC" },
 { (unsigned)((1 << 1)), "V4L2_VBI_INTERLACED" },
};
const struct xlat v4l2_vbi_flags[1] = { {
 .data = v4l2_vbi_flags_xdata,
 .size = (sizeof(v4l2_vbi_flags_xdata) / sizeof((v4l2_vbi_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_vbi_flags_xdata)), __typeof__(&(v4l2_vbi_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((1 << 0)))
  | ((unsigned) ((1 << 1)))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_VBI_UNSYNC")
  + sizeof("V4L2_VBI_INTERLACED")
  ,
} };


static const struct xlat_data v4l2_sliced_flags_xdata[] = {
 { (unsigned)(((0x0001) | (0x0400) | (0x4000))), "V4L2_SLICED_VBI_625" },
 { (unsigned)((0x0001)), "V4L2_SLICED_TELETEXT_B" },
 { (unsigned)((0x0400)), "V4L2_SLICED_VPS" },
 { (unsigned)((0x1000)), "V4L2_SLICED_CAPTION_525" },
 { (unsigned)((0x4000)), "V4L2_SLICED_WSS_625" },
};
const struct xlat v4l2_sliced_flags[1] = { {
 .data = v4l2_sliced_flags_xdata,
 .size = (sizeof(v4l2_sliced_flags_xdata) / sizeof((v4l2_sliced_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_sliced_flags_xdata)), __typeof__(&(v4l2_sliced_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (((0x0001) | (0x0400) | (0x4000))))
  | ((unsigned) ((0x0001)))
  | ((unsigned) ((0x0400)))
  | ((unsigned) ((0x1000)))
  | ((unsigned) ((0x4000)))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_SLICED_VBI_625")
  + sizeof("V4L2_SLICED_TELETEXT_B")
  + sizeof("V4L2_SLICED_VPS")
  + sizeof("V4L2_SLICED_CAPTION_525")
  + sizeof("V4L2_SLICED_WSS_625")
  ,
} };

static _Bool
print_v4l2_clip(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
 const struct_v4l2_clip *p = elem_buf;
 tprint_struct_begin();
 do { tprints_field_name("c"); (print_v4l2_rect)(&((*p).c)); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_pix(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.pix) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("width"); tprintf_string("%llu", (sizeof((*p).width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).width) : sizeof((*p).width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).width) : sizeof((*p).width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).width) : sizeof((*p).width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).width) : (unsigned long long) ((*p).width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("height"); tprintf_string("%llu", (sizeof((*p).height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).height) : sizeof((*p).height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).height) : sizeof((*p).height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).height) : sizeof((*p).height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).height) : (unsigned long long) ((*p).height))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("pixelformat"); print_pixelformat((*p).pixelformat, (v4l2_pix_fmts)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("field"); printxval64((v4l2_fields), (sizeof((*p).field) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).field) : sizeof((*p).field) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).field) : sizeof((*p).field) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).field) : sizeof((*p).field) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).field) : (unsigned long long) ((*p).field)), ("V4L2_FIELD_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("bytesperline"); tprintf_string("%llu", (sizeof((*p).bytesperline) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).bytesperline) : (unsigned long long) ((*p).bytesperline))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("sizeimage"); tprintf_string("%llu", (sizeof((*p).sizeimage) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).sizeimage) : (unsigned long long) ((*p).sizeimage))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("colorspace"); printxval64((v4l2_colorspaces), (sizeof((*p).colorspace) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).colorspace) : (unsigned long long) ((*p).colorspace)), ("V4L2_COLORSPACE_???")); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_plane_pix_format_array_member(struct tcb *tcp, void *elem_buf,
      size_t elem_size, void *data)
{
 struct v4l2_plane_pix_format *p = elem_buf;
 tprint_struct_begin();
 do { tprints_field_name("sizeimage"); tprintf_string("%llu", (sizeof((*p).sizeimage) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).sizeimage) : sizeof((*p).sizeimage) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).sizeimage) : (unsigned long long) ((*p).sizeimage))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("bytesperline"); tprintf_string("%llu", (sizeof((*p).bytesperline) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).bytesperline) : sizeof((*p).bytesperline) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).bytesperline) : (unsigned long long) ((*p).bytesperline))); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_pix_mp(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.pix_mp) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("width"); tprintf_string("%llu", (sizeof((*p).width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).width) : sizeof((*p).width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).width) : sizeof((*p).width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).width) : sizeof((*p).width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).width) : (unsigned long long) ((*p).width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("height"); tprintf_string("%llu", (sizeof((*p).height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).height) : sizeof((*p).height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).height) : sizeof((*p).height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).height) : sizeof((*p).height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).height) : (unsigned long long) ((*p).height))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("pixelformat"); print_pixelformat((*p).pixelformat, (v4l2_pix_fmts)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("field"); printxval64((v4l2_fields), (sizeof((*p).field) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).field) : sizeof((*p).field) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).field) : sizeof((*p).field) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).field) : sizeof((*p).field) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).field) : (unsigned long long) ((*p).field)), ("V4L2_FIELD_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("colorspace"); printxval64((v4l2_colorspaces), (sizeof((*p).colorspace) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).colorspace) : sizeof((*p).colorspace) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).colorspace) : (unsigned long long) ((*p).colorspace)), ("V4L2_COLORSPACE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("plane_fmt"); print_local_array_ex(((tcp)), ((*p).plane_fmt), ((((((((p->num_planes))) > (0)) ? (((p->num_planes))) : (0))) < ((typeof((p->num_planes))) (sizeof((*p).plane_fmt) / sizeof(((*p).plane_fmt)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((*p).plane_fmt)), __typeof__(&((*p).plane_fmt)[0])))]) * 0)))) ? ((((((p->num_planes))) > (0)) ? (((p->num_planes))) : (0))) : ((typeof((p->num_planes))) (sizeof((*p).plane_fmt) / sizeof(((*p).plane_fmt)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((*p).plane_fmt)), __typeof__(&((*p).plane_fmt)[0])))]) * 0)))), sizeof(((*p).plane_fmt)[0]), ((print_v4l2_plane_pix_format_array_member)), ((void *)0), 0, ((void *)0), ((void *)0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("num_planes"); tprintf_string("%llu", (sizeof((*p).num_planes) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).num_planes) : sizeof((*p).num_planes) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).num_planes) : sizeof((*p).num_planes) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).num_planes) : sizeof((*p).num_planes) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).num_planes) : (unsigned long long) ((*p).num_planes))); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_win(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.win) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("w"); (print_v4l2_rect)(&((*p).w)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("field"); printxval64((v4l2_fields), (sizeof((*p).field) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).field) : sizeof((*p).field) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).field) : sizeof((*p).field) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).field) : sizeof((*p).field) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).field) : (unsigned long long) ((*p).field)), ("V4L2_FIELD_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("chromakey"); tprintf_string("%#llx", (sizeof((*p).chromakey) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).chromakey) : sizeof((*p).chromakey) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).chromakey) : sizeof((*p).chromakey) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).chromakey) : sizeof((*p).chromakey) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).chromakey) : (unsigned long long) ((*p).chromakey))); } while (0);
 tprint_struct_next();
 tprints_field_name("clips");
 struct_v4l2_clip clip;
 _Bool rc = print_array(tcp, ((kernel_ulong_t) (unsigned long) (p->clips)),
      p->clipcount, &clip, sizeof(clip),
      tfetch_mem, print_v4l2_clip, 0);
 tprint_struct_next();
 do { tprints_field_name("clipcount"); tprintf_string("%llu", (sizeof((*p).clipcount) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).clipcount) : sizeof((*p).clipcount) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).clipcount) : sizeof((*p).clipcount) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).clipcount) : sizeof((*p).clipcount) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).clipcount) : (unsigned long long) ((*p).clipcount))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("bitmap"); printaddr((mpers_ptr_t) (*p).bitmap); } while (0);
 if (p->global_alpha) {
  tprint_struct_next();
  do { tprints_field_name("global_alpha"); tprintf_string("%#llx", (sizeof((*p).global_alpha) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).global_alpha) : sizeof((*p).global_alpha) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).global_alpha) : sizeof((*p).global_alpha) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).global_alpha) : sizeof((*p).global_alpha) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).global_alpha) : (unsigned long long) ((*p).global_alpha))); } while (0);
 }
 tprint_struct_end();
 return rc;
}
static _Bool
print_v4l2_format_fmt_vbi(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.vbi) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("sampling_rate"); tprintf_string("%llu", (sizeof((*p).sampling_rate) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).sampling_rate) : sizeof((*p).sampling_rate) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).sampling_rate) : sizeof((*p).sampling_rate) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).sampling_rate) : sizeof((*p).sampling_rate) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).sampling_rate) : (unsigned long long) ((*p).sampling_rate))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("offset"); tprintf_string("%llu", (sizeof((*p).offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).offset) : sizeof((*p).offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).offset) : sizeof((*p).offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).offset) : sizeof((*p).offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).offset) : (unsigned long long) ((*p).offset))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("samples_per_line"); tprintf_string("%llu", (sizeof((*p).samples_per_line) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).samples_per_line) : sizeof((*p).samples_per_line) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).samples_per_line) : sizeof((*p).samples_per_line) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).samples_per_line) : sizeof((*p).samples_per_line) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).samples_per_line) : (unsigned long long) ((*p).samples_per_line))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("sample_format"); print_pixelformat((*p).sample_format, (v4l2_pix_fmts)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("start"); for (size_t i_ = 0; i_ < (sizeof(((*p)).start) / sizeof((((*p)).start)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((((*p)).start)), __typeof__(&(((*p)).start)[0])))]) * 0)); ++i_) { if (i_) tprint_array_next(); else tprint_array_begin(); tprintf_string("%lld", (sizeof(((*p)).start[i_]) == sizeof(char) ? (long long) (char) (((*p)).start[i_]) : sizeof(((*p)).start[i_]) == sizeof(short) ? (long long) (short) (((*p)).start[i_]) : sizeof(((*p)).start[i_]) == sizeof(int) ? (long long) (int) (((*p)).start[i_]) : sizeof(((*p)).start[i_]) == sizeof(long) ? (long long) (long) (((*p)).start[i_]) : (long long) (((*p)).start[i_]))); } tprint_array_end(); } while (0);
 tprint_struct_next();
 do { tprints_field_name("count"); for (size_t i_ = 0; i_ < (sizeof(((*p)).count) / sizeof((((*p)).count)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((((*p)).count)), __typeof__(&(((*p)).count)[0])))]) * 0)); ++i_) { if (i_) tprint_array_next(); else tprint_array_begin(); tprintf_string("%llu", (sizeof(((*p)).count[i_]) == sizeof(char) ? (unsigned long long) (unsigned char) (((*p)).count[i_]) : sizeof(((*p)).count[i_]) == sizeof(short) ? (unsigned long long) (unsigned short) (((*p)).count[i_]) : sizeof(((*p)).count[i_]) == sizeof(int) ? (unsigned long long) (unsigned int) (((*p)).count[i_]) : sizeof(((*p)).count[i_]) == sizeof(long) ? (unsigned long long) (unsigned long) (((*p)).count[i_]) : (unsigned long long) (((*p)).count[i_]))); } tprint_array_end(); } while (0);
 tprint_struct_next();
 do { tprints_field_name("flags"); printflags64((v4l2_vbi_flags), (sizeof((*p).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).flags) : sizeof((*p).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).flags) : sizeof((*p).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).flags) : sizeof((*p).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).flags) : (unsigned long long) ((*p).flags)), ("V4L2_VBI_???")); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_sliced(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.sliced) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("service_set"); printflags64((v4l2_sliced_flags), (sizeof((*p).service_set) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).service_set) : sizeof((*p).service_set) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).service_set) : sizeof((*p).service_set) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).service_set) : sizeof((*p).service_set) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).service_set) : (unsigned long long) ((*p).service_set)), ("V4L2_SLICED_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("service_lines"); for (size_t i_ = 0; i_ < (sizeof(((*p)).service_lines) / sizeof((((*p)).service_lines)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((((*p)).service_lines)), __typeof__(&(((*p)).service_lines)[0])))]) * 0)); ++i_) { if (i_) tprint_array_next(); else tprint_array_begin(); for (size_t j_ = 0; j_ < (sizeof(((*p)).service_lines[i_]) / sizeof((((*p)).service_lines[i_])[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((((*p)).service_lines[i_])), __typeof__(&(((*p)).service_lines[i_])[0])))]) * 0)); ++j_) { if (j_) tprint_array_next(); else tprint_array_begin(); tprintf_string("%#llx", (sizeof(((*p)).service_lines[i_][j_]) == sizeof(char) ? (unsigned long long) (unsigned char) (((*p)).service_lines[i_][j_]) : sizeof(((*p)).service_lines[i_][j_]) == sizeof(short) ? (unsigned long long) (unsigned short) (((*p)).service_lines[i_][j_]) : sizeof(((*p)).service_lines[i_][j_]) == sizeof(int) ? (unsigned long long) (unsigned int) (((*p)).service_lines[i_][j_]) : sizeof(((*p)).service_lines[i_][j_]) == sizeof(long) ? (unsigned long long) (unsigned long) (((*p)).service_lines[i_][j_]) : (unsigned long long) (((*p)).service_lines[i_][j_]))); } tprint_array_end(); } tprint_array_end(); } while (0);
 tprint_struct_next();
 do { tprints_field_name("io_size"); tprintf_string("%llu", (sizeof((*p).io_size) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).io_size) : sizeof((*p).io_size) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).io_size) : sizeof((*p).io_size) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).io_size) : sizeof((*p).io_size) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).io_size) : (unsigned long long) ((*p).io_size))); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_sdr(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.sdr) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("pixelformat"); print_pixelformat((*p).pixelformat, (v4l2_sdr_fmts)); } while (0);
 if (p->buffersize) {
  tprint_struct_next();
  do { tprints_field_name("buffersize"); tprintf_string("%llu", (sizeof((*p).buffersize) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).buffersize) : (unsigned long long) ((*p).buffersize))); } while (0);
 }
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt_meta(struct tcb *const tcp, const typeof(((struct_v4l2_format *)0)->fmt.meta) *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("dataformat"); print_pixelformat((*p).dataformat, (v4l2_meta_fmts)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("buffersize"); tprintf_string("%llu", (sizeof((*p).buffersize) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).buffersize) : sizeof((*p).buffersize) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).buffersize) : (unsigned long long) ((*p).buffersize))); } while (0);
 tprint_struct_end();
 return 1;
}
static _Bool
print_v4l2_format_fmt(struct tcb *const tcp, void (*const prefix_fun)(void),
        const struct_v4l2_format *const f)
{
 _Bool ret = 1;
 switch (f->type) {
 case V4L2_BUF_TYPE_VIDEO_CAPTURE:
 case V4L2_BUF_TYPE_VIDEO_OUTPUT:
  prefix_fun();
  do { tprints_field_name("fmt" "." "pix"); (ret) = (print_v4l2_format_fmt_pix) ((tcp), &((*f).fmt.pix)); } while (0);
  break;
 case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
 case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
  prefix_fun();
  do { tprints_field_name("fmt" "." "pix_mp"); (ret) = (print_v4l2_format_fmt_pix_mp) ((tcp), &((*f).fmt.pix_mp)); } while (0);
  break;
 case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
 case V4L2_BUF_TYPE_VIDEO_OVERLAY:
  prefix_fun();
  do { tprints_field_name("fmt" "." "win"); (ret) = (print_v4l2_format_fmt_win) ((tcp), &((*f).fmt.win)); } while (0);
  break;
 case V4L2_BUF_TYPE_VBI_CAPTURE:
 case V4L2_BUF_TYPE_VBI_OUTPUT:
  prefix_fun();
  do { tprints_field_name("fmt" "." "vbi"); (ret) = (print_v4l2_format_fmt_vbi) ((tcp), &((*f).fmt.vbi)); } while (0);
  break;
 case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
 case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
  prefix_fun();
  do { tprints_field_name("fmt" "." "sliced"); (ret) = (print_v4l2_format_fmt_sliced) ((tcp), &((*f).fmt.sliced)); } while (0);
  break;
 case V4L2_BUF_TYPE_SDR_OUTPUT:
 case V4L2_BUF_TYPE_SDR_CAPTURE:
  prefix_fun();
  do { tprints_field_name("fmt" "." "sdr"); (ret) = (print_v4l2_format_fmt_sdr) ((tcp), &((*f).fmt.sdr)); } while (0);
  break;
 case V4L2_BUF_TYPE_META_OUTPUT:
 case V4L2_BUF_TYPE_META_CAPTURE:
  prefix_fun();
  do { tprints_field_name("fmt" "." "meta"); (ret) = (print_v4l2_format_fmt_meta) ((tcp), &((*f).fmt.meta)); } while (0);
  break;
 default:
  return 0;
 }
 return ret;
}
static void
tprint_struct_end_value_changed_struct_begin(void)
{
 tprint_struct_end();
 tprint_value_changed();
 tprint_struct_begin();
}
static int
print_v4l2_format(struct tcb *const tcp, const kernel_ulong_t arg,
    const _Bool is_get)
{
 struct_v4l2_format f;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&f)), (void *) (&f)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((f).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).type) : sizeof((f).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).type) : sizeof((f).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).type) : sizeof((f).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).type) : (unsigned long long) ((f).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  if (is_get)
   return 0;
  if (!print_v4l2_format_fmt(tcp, tprint_struct_next, &f)) {
   tprint_struct_end();
   return 0200;
  }
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&f)), (void *) (&f))) {
  void (*const prefix_fun)(void) =
   is_get ? tprint_struct_next :
   tprint_struct_end_value_changed_struct_begin;
  print_v4l2_format_fmt(tcp, prefix_fun, &f);
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_memories_xdata[] = {
 [V4L2_MEMORY_MMAP] = { (unsigned)(V4L2_MEMORY_MMAP), "V4L2_MEMORY_MMAP" },
 [V4L2_MEMORY_USERPTR] = { (unsigned)(V4L2_MEMORY_USERPTR), "V4L2_MEMORY_USERPTR" },
 [V4L2_MEMORY_OVERLAY] = { (unsigned)(V4L2_MEMORY_OVERLAY), "V4L2_MEMORY_OVERLAY" },
 [V4L2_MEMORY_DMABUF] = { (unsigned)(V4L2_MEMORY_DMABUF), "V4L2_MEMORY_DMABUF" },
};
const struct xlat v4l2_memories[1] = { {
 .data = v4l2_memories_xdata,
 .size = (sizeof(v4l2_memories_xdata) / sizeof((v4l2_memories_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_memories_xdata)), __typeof__(&(v4l2_memories_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_MEMORY_MMAP))
  | ((unsigned) (V4L2_MEMORY_USERPTR))
  | ((unsigned) (V4L2_MEMORY_OVERLAY))
  | ((unsigned) (V4L2_MEMORY_DMABUF))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_MEMORY_MMAP")
  + sizeof("V4L2_MEMORY_USERPTR")
  + sizeof("V4L2_MEMORY_OVERLAY")
  + sizeof("V4L2_MEMORY_DMABUF")
  ,
} };

static int
print_v4l2_requestbuffers(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_requestbuffers reqbufs;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&reqbufs)), (void *) (&reqbufs)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((reqbufs).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((reqbufs).type) : sizeof((reqbufs).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((reqbufs).type) : sizeof((reqbufs).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((reqbufs).type) : sizeof((reqbufs).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((reqbufs).type) : (unsigned long long) ((reqbufs).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("memory"); printxval64((v4l2_memories), (sizeof((reqbufs).memory) == sizeof(char) ? (unsigned long long) (unsigned char) ((reqbufs).memory) : sizeof((reqbufs).memory) == sizeof(short) ? (unsigned long long) (unsigned short) ((reqbufs).memory) : sizeof((reqbufs).memory) == sizeof(int) ? (unsigned long long) (unsigned int) ((reqbufs).memory) : sizeof((reqbufs).memory) == sizeof(long) ? (unsigned long long) (unsigned long) ((reqbufs).memory) : (unsigned long long) ((reqbufs).memory)), ("V4L2_MEMORY_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("count"); tprintf_string("%llu", (sizeof((reqbufs).count) == sizeof(char) ? (unsigned long long) (unsigned char) ((reqbufs).count) : sizeof((reqbufs).count) == sizeof(short) ? (unsigned long long) (unsigned short) ((reqbufs).count) : sizeof((reqbufs).count) == sizeof(int) ? (unsigned long long) (unsigned int) ((reqbufs).count) : sizeof((reqbufs).count) == sizeof(long) ? (unsigned long long) (unsigned long) ((reqbufs).count) : (unsigned long long) ((reqbufs).count))); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&reqbufs)), (void *) (&reqbufs))) {
  tprint_value_changed();
  tprintf_string("%llu", (sizeof(reqbufs.count) == sizeof(char) ? (unsigned long long) (unsigned char) (reqbufs.count) : sizeof(reqbufs.count) == sizeof(short) ? (unsigned long long) (unsigned short) (reqbufs.count) : sizeof(reqbufs.count) == sizeof(int) ? (unsigned long long) (unsigned int) (reqbufs.count) : sizeof(reqbufs.count) == sizeof(long) ? (unsigned long long) (unsigned long) (reqbufs.count) : (unsigned long long) (reqbufs.count)));
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_buf_flags_xdata[] = {
 { (unsigned)(0x00000001), "V4L2_BUF_FLAG_MAPPED" },
 { (unsigned)(0x00000002), "V4L2_BUF_FLAG_QUEUED" },
 { (unsigned)(0x00000004), "V4L2_BUF_FLAG_DONE" },
 { (unsigned)(0x00000008), "V4L2_BUF_FLAG_KEYFRAME" },
 { (unsigned)(0x00000010), "V4L2_BUF_FLAG_PFRAME" },
 { (unsigned)(0x00000020), "V4L2_BUF_FLAG_BFRAME" },
 { (unsigned)(0x00000040), "V4L2_BUF_FLAG_ERROR" },
 { (unsigned)(0x00000080), "V4L2_BUF_FLAG_IN_REQUEST" },
 { (unsigned)(0x00000100), "V4L2_BUF_FLAG_TIMECODE" },
 { (unsigned)(0x0200), "V4L2_BUF_FLAG_INPUT" },
 { (unsigned)(0x00000400), "V4L2_BUF_FLAG_PREPARED" },
 { (unsigned)(0x00000800), "V4L2_BUF_FLAG_NO_CACHE_INVALIDATE" },
 { (unsigned)(0x00001000), "V4L2_BUF_FLAG_NO_CACHE_CLEAN" },
 { (unsigned)(0x00100000), "V4L2_BUF_FLAG_LAST" },
 { (unsigned)(0x00800000), "V4L2_BUF_FLAG_REQUEST_FD" },
};
const struct xlat v4l2_buf_flags[1] = { {
 .data = v4l2_buf_flags_xdata,
 .size = (sizeof(v4l2_buf_flags_xdata) / sizeof((v4l2_buf_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_buf_flags_xdata)), __typeof__(&(v4l2_buf_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x00000001))
  | ((unsigned) (0x00000002))
  | ((unsigned) (0x00000004))
  | ((unsigned) (0x00000008))
  | ((unsigned) (0x00000010))
  | ((unsigned) (0x00000020))
  | ((unsigned) (0x00000040))
  | ((unsigned) (0x00000080))
  | ((unsigned) (0x00000100))
  | ((unsigned) (0x0200))
  | ((unsigned) (0x00000400))
  | ((unsigned) (0x00000800))
  | ((unsigned) (0x00001000))
  | ((unsigned) (0x00100000))
  | ((unsigned) (0x00800000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_BUF_FLAG_MAPPED")
  + sizeof("V4L2_BUF_FLAG_QUEUED")
  + sizeof("V4L2_BUF_FLAG_DONE")
  + sizeof("V4L2_BUF_FLAG_KEYFRAME")
  + sizeof("V4L2_BUF_FLAG_PFRAME")
  + sizeof("V4L2_BUF_FLAG_BFRAME")
  + sizeof("V4L2_BUF_FLAG_ERROR")
  + sizeof("V4L2_BUF_FLAG_IN_REQUEST")
  + sizeof("V4L2_BUF_FLAG_TIMECODE")
  + sizeof("V4L2_BUF_FLAG_INPUT")
  + sizeof("V4L2_BUF_FLAG_PREPARED")
  + sizeof("V4L2_BUF_FLAG_NO_CACHE_INVALIDATE")
  + sizeof("V4L2_BUF_FLAG_NO_CACHE_CLEAN")
  + sizeof("V4L2_BUF_FLAG_LAST")
  + sizeof("V4L2_BUF_FLAG_REQUEST_FD")
  ,
} };


static const struct xlat_data v4l2_buf_flags_ts_type_xdata[] = {
 { (unsigned)(0x00000000), "V4L2_BUF_FLAG_TIMESTAMP_UNKNOWN" },
 { (unsigned)(0x00002000), "V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC" },
 { (unsigned)(0x00004000), "V4L2_BUF_FLAG_TIMESTAMP_COPY" },
};
const struct xlat v4l2_buf_flags_ts_type[1] = { {
 .data = v4l2_buf_flags_ts_type_xdata,
 .size = (sizeof(v4l2_buf_flags_ts_type_xdata) / sizeof((v4l2_buf_flags_ts_type_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_buf_flags_ts_type_xdata)), __typeof__(&(v4l2_buf_flags_ts_type_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x00000000))
  | ((unsigned) (0x00002000))
  | ((unsigned) (0x00004000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_BUF_FLAG_TIMESTAMP_UNKNOWN")
  + sizeof("V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC")
  + sizeof("V4L2_BUF_FLAG_TIMESTAMP_COPY")
  ,
} };


static const struct xlat_data v4l2_buf_flags_ts_src_xdata[] = {
 { (unsigned)(0x00000000), "V4L2_BUF_FLAG_TSTAMP_SRC_EOF" },
 { (unsigned)(0x00010000), "V4L2_BUF_FLAG_TSTAMP_SRC_SOE" },
};
const struct xlat v4l2_buf_flags_ts_src[1] = { {
 .data = v4l2_buf_flags_ts_src_xdata,
 .size = (sizeof(v4l2_buf_flags_ts_src_xdata) / sizeof((v4l2_buf_flags_ts_src_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_buf_flags_ts_src_xdata)), __typeof__(&(v4l2_buf_flags_ts_src_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x00000000))
  | ((unsigned) (0x00010000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_BUF_FLAG_TSTAMP_SRC_EOF")
  + sizeof("V4L2_BUF_FLAG_TSTAMP_SRC_SOE")
  ,
} };

static void
print_v4l2_buffer_flags(uint32_t val)
{
 const uint32_t ts_type = val & 0x0000e000;
 const uint32_t ts_src = val & 0x00070000;
 const uint32_t flags = val & ~ts_type & ~ts_src;
 if (((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_RAW) {
  tprintf_string("%#llx", (sizeof(val) == sizeof(char) ? (unsigned long long) (unsigned char) (val) : sizeof(val) == sizeof(short) ? (unsigned long long) (unsigned short) (val) : sizeof(val) == sizeof(int) ? (unsigned long long) (unsigned int) (val) : sizeof(val) == sizeof(long) ? (unsigned long long) (unsigned long) (val) : (unsigned long long) (val)));
  return;
 }
 tprint_flags_begin();
 if (flags) {
  printflags_in(v4l2_buf_flags, flags, "V4L2_BUF_FLAG_???");
  tprint_flags_or();
 }
 printxval(v4l2_buf_flags_ts_type, ts_type,
    "V4L2_BUF_FLAG_TIMESTAMP_???");
 tprint_flags_or();
 printxval(v4l2_buf_flags_ts_src, ts_src,
    "V4L2_BUF_FLAG_TSTAMP_SRC_???");
 tprint_flags_end();
}
static void
print_v4l2_timeval(const kernel_v4l2_timeval_t * const arg)
{
 const kernel_v4l2_timeval_t *const t = arg;
 kernel_timeval64_t tv;
 if (sizeof(tv.tv_sec) == sizeof(t->tv_sec) &&
     sizeof(tv.tv_usec) == sizeof(t->tv_usec)) {
  print_timeval64_data_size(t, sizeof(*t));
 } else {
  tv.tv_sec = (sizeof(t->tv_sec) == sizeof(char) ? (long long) (char) (t->tv_sec) : sizeof(t->tv_sec) == sizeof(short) ? (long long) (short) (t->tv_sec) : sizeof(t->tv_sec) == sizeof(int) ? (long long) (int) (t->tv_sec) : sizeof(t->tv_sec) == sizeof(long) ? (long long) (long) (t->tv_sec) : (long long) (t->tv_sec));
  tv.tv_usec = (sizeof(t->tv_usec) == sizeof(char) ? (unsigned long long) (unsigned char) (t->tv_usec) : sizeof(t->tv_usec) == sizeof(short) ? (unsigned long long) (unsigned short) (t->tv_usec) : sizeof(t->tv_usec) == sizeof(int) ? (unsigned long long) (unsigned int) (t->tv_usec) : sizeof(t->tv_usec) == sizeof(long) ? (unsigned long long) (unsigned long) (t->tv_usec) : (unsigned long long) (t->tv_usec));
  print_timeval64_data_size(&tv, sizeof(tv));
 }
}
static int
print_v4l2_buffer(struct tcb *const tcp, const unsigned int code,
    const kernel_ulong_t arg)
{
 kernel_v4l2_buffer_t b;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&b)), (void *) (&b)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((b).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).type) : sizeof((b).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).type) : sizeof((b).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).type) : sizeof((b).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).type) : (unsigned long long) ((b).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  if (code != (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((17)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8)))) {
   tprint_struct_next();
   do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((b).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).index) : sizeof((b).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).index) : sizeof((b).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).index) : sizeof((b).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).index) : (unsigned long long) ((b).index))); } while (0);
  }
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&b)), (void *) (&b))) {
  if (code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((17)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8)))) {
   tprint_struct_next();
   do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((b).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).index) : sizeof((b).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).index) : sizeof((b).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).index) : sizeof((b).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).index) : (unsigned long long) ((b).index))); } while (0);
  }
  tprint_struct_next();
  do { tprints_field_name("memory"); printxval64((v4l2_memories), (sizeof((b).memory) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).memory) : sizeof((b).memory) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).memory) : sizeof((b).memory) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).memory) : sizeof((b).memory) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).memory) : (unsigned long long) ((b).memory)), ("V4L2_MEMORY_???")); } while (0);
  if (b.memory == V4L2_MEMORY_MMAP) {
   tprint_struct_next();
   do { tprints_field_name("m.offset"); tprintf_string("%#llx", (sizeof((b).m.offset) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).m.offset) : sizeof((b).m.offset) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).m.offset) : sizeof((b).m.offset) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).m.offset) : sizeof((b).m.offset) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).m.offset) : (unsigned long long) ((b).m.offset))); } while (0);
  } else if (b.memory == V4L2_MEMORY_USERPTR) {
   tprint_struct_next();
   do { tprints_field_name("m.userptr"); printaddr((mpers_ptr_t) (b).m.userptr); } while (0);
  }
  tprint_struct_next();
  do { tprints_field_name("length"); tprintf_string("%llu", (sizeof((b).length) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).length) : sizeof((b).length) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).length) : sizeof((b).length) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).length) : sizeof((b).length) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).length) : (unsigned long long) ((b).length))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("bytesused"); tprintf_string("%llu", (sizeof((b).bytesused) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).bytesused) : sizeof((b).bytesused) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).bytesused) : sizeof((b).bytesused) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).bytesused) : sizeof((b).bytesused) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).bytesused) : (unsigned long long) ((b).bytesused))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); print_v4l2_buffer_flags((b).flags); } while (0);
  if (code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((17)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8)))) {
   tprint_struct_next();
   do { tprints_field_name("timestamp"); print_v4l2_timeval(&((b).timestamp)); } while (0);
  }
  tprint_struct_next();
  tprint_more_data_follows();
 }
 tprint_struct_end();
 return 0200;
}
static int
print_v4l2_framebuffer(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct_v4l2_framebuffer b;
 tprint_arg_next();
 if (!umoven_or_printaddr((tcp), (arg), sizeof(*(&b)), (void *) (&b))) {
  tprint_struct_begin();
  do { tprints_field_name("capability"); tprintf_string("%#llx", (sizeof((b).capability) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).capability) : sizeof((b).capability) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).capability) : sizeof((b).capability) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).capability) : sizeof((b).capability) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).capability) : (unsigned long long) ((b).capability))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); tprintf_string("%#llx", (sizeof((b).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).flags) : sizeof((b).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).flags) : sizeof((b).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).flags) : sizeof((b).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).flags) : (unsigned long long) ((b).flags))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("base"); printaddr((mpers_ptr_t) (b).base); } while (0);
  tprint_struct_end();
 }
 return 0200;
}
static int
print_v4l2_buf_type(struct tcb *const tcp, const kernel_ulong_t arg)
{
 int type;
 tprint_arg_next();
 if (!umoven_or_printaddr((tcp), (arg), sizeof(*(&type)), (void *) (&type))) {
  tprint_indirect_begin();
  printxval(v4l2_buf_types, type, "V4L2_BUF_TYPE_???");
  tprint_indirect_end();
 }
 return 0200;
}

static const struct xlat_data v4l2_streaming_capabilities_xdata[] = {
 { (unsigned)(0x1000), "V4L2_CAP_TIMEPERFRAME" },
};
const struct xlat v4l2_streaming_capabilities[1] = { {
 .data = v4l2_streaming_capabilities_xdata,
 .size = (sizeof(v4l2_streaming_capabilities_xdata) / sizeof((v4l2_streaming_capabilities_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_streaming_capabilities_xdata)), __typeof__(&(v4l2_streaming_capabilities_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x1000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CAP_TIMEPERFRAME")
  ,
} };


static const struct xlat_data v4l2_capture_modes_xdata[] = {
 { (unsigned)(0x0001), "V4L2_MODE_HIGHQUALITY" },
};
const struct xlat v4l2_capture_modes[1] = { {
 .data = v4l2_capture_modes_xdata,
 .size = (sizeof(v4l2_capture_modes_xdata) / sizeof((v4l2_capture_modes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_capture_modes_xdata)), __typeof__(&(v4l2_capture_modes_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x0001))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_MODE_HIGHQUALITY")
  ,
} };

static void
print_v4l2_streamparm_capture(const struct v4l2_captureparm *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("capability"); printflags64((v4l2_streaming_capabilities), (sizeof((*p).capability) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).capability) : sizeof((*p).capability) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).capability) : sizeof((*p).capability) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).capability) : sizeof((*p).capability) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).capability) : (unsigned long long) ((*p).capability)), ("V4L2_CAP_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("capturemode"); printflags64((v4l2_capture_modes), (sizeof((*p).capturemode) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).capturemode) : sizeof((*p).capturemode) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).capturemode) : sizeof((*p).capturemode) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).capturemode) : sizeof((*p).capturemode) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).capturemode) : (unsigned long long) ((*p).capturemode)), ("V4L2_MODE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("timeperframe"); tprintf_string("%u/%u", (*p).timeperframe.numerator, (*p).timeperframe.denominator); } while (0);
 tprint_struct_next();
 do { tprints_field_name("extendedmode"); tprintf_string("%#llx", (sizeof((*p).extendedmode) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).extendedmode) : (unsigned long long) ((*p).extendedmode))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("readbuffers"); tprintf_string("%llu", (sizeof((*p).readbuffers) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).readbuffers) : sizeof((*p).readbuffers) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).readbuffers) : sizeof((*p).readbuffers) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).readbuffers) : sizeof((*p).readbuffers) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).readbuffers) : (unsigned long long) ((*p).readbuffers))); } while (0);
 tprint_struct_end();
}
static void
print_v4l2_streamparm_output(const struct v4l2_outputparm *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("capability"); printflags64((v4l2_streaming_capabilities), (sizeof((*p).capability) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).capability) : sizeof((*p).capability) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).capability) : sizeof((*p).capability) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).capability) : sizeof((*p).capability) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).capability) : (unsigned long long) ((*p).capability)), ("V4L2_CAP_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("outputmode"); printflags64((v4l2_capture_modes), (sizeof((*p).outputmode) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).outputmode) : sizeof((*p).outputmode) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).outputmode) : sizeof((*p).outputmode) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).outputmode) : sizeof((*p).outputmode) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).outputmode) : (unsigned long long) ((*p).outputmode)), ("V4L2_MODE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("timeperframe"); tprintf_string("%u/%u", (*p).timeperframe.numerator, (*p).timeperframe.denominator); } while (0);
 tprint_struct_next();
 do { tprints_field_name("extendedmode"); tprintf_string("%#llx", (sizeof((*p).extendedmode) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).extendedmode) : sizeof((*p).extendedmode) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).extendedmode) : (unsigned long long) ((*p).extendedmode))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("writebuffers"); tprintf_string("%llu", (sizeof((*p).writebuffers) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).writebuffers) : sizeof((*p).writebuffers) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).writebuffers) : sizeof((*p).writebuffers) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).writebuffers) : sizeof((*p).writebuffers) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).writebuffers) : (unsigned long long) ((*p).writebuffers))); } while (0);
 tprint_struct_end();
}
static int
print_v4l2_streamparm(struct tcb *const tcp, const kernel_ulong_t arg,
        const _Bool is_get)
{
 struct v4l2_streamparm s;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&s)), (void *) (&s)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((s).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((s).type) : sizeof((s).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((s).type) : sizeof((s).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((s).type) : sizeof((s).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((s).type) : (unsigned long long) ((s).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  switch (s.type) {
   case V4L2_BUF_TYPE_VIDEO_CAPTURE:
   case V4L2_BUF_TYPE_VIDEO_OUTPUT:
    if (is_get)
     return 0;
    tprint_struct_next();
    break;
   default:
    tprint_struct_end();
    return 0200;
  }
 } else {
  if (((tcp)->u_error != 0) || umoven((tcp), (arg), sizeof(*(&s)), (void *) (&s)) < 0) {
   tprint_struct_end();
   return 0200;
  }
  if (is_get) {
   tprint_struct_next();
  } else {
   tprint_struct_end();
   tprint_value_changed();
   tprint_struct_begin();
  }
 }
 if (s.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
  do { tprints_field_name("parm" "." "capture"); print_v4l2_streamparm_capture(&((s).parm.capture)); } while (0);
 } else {
  do { tprints_field_name("parm" "." "output"); print_v4l2_streamparm_output(&((s).parm.output)); } while (0);
 }
 if ((!((tcp)->flags & 0x04))) {
  return 0;
 } else {
  tprint_struct_end();
  return 0200;
 }
}
static int
print_v4l2_standard(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct_v4l2_standard s;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&s)), (void *) (&s)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((s).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((s).index) : sizeof((s).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((s).index) : sizeof((s).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((s).index) : sizeof((s).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((s).index) : (unsigned long long) ((s).index))); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&s)), (void *) (&s))) {
  tprint_struct_next();
  do { tprints_field_name("name"); print_quoted_cstring((const char *) (s).name, sizeof((s).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((s).name)), __typeof__(&((s).name)[0])))]) * 0)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("frameperiod"); tprintf_string("%u/%u", (s).frameperiod.numerator, (s).frameperiod.denominator); } while (0);
  tprint_struct_next();
  do { tprints_field_name("framelines"); tprintf_string("%llu", (sizeof((s).framelines) == sizeof(char) ? (unsigned long long) (unsigned char) ((s).framelines) : sizeof((s).framelines) == sizeof(short) ? (unsigned long long) (unsigned short) ((s).framelines) : sizeof((s).framelines) == sizeof(int) ? (unsigned long long) (unsigned int) ((s).framelines) : sizeof((s).framelines) == sizeof(long) ? (unsigned long long) (unsigned long) ((s).framelines) : (unsigned long long) ((s).framelines))); } while (0);
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_input_types_xdata[] = {
 [1] = { (unsigned)(1), "V4L2_INPUT_TYPE_TUNER" },
 [2] = { (unsigned)(2), "V4L2_INPUT_TYPE_CAMERA" },
 [3] = { (unsigned)(3), "V4L2_INPUT_TYPE_TOUCH" },
};
const struct xlat v4l2_input_types[1] = { {
 .data = v4l2_input_types_xdata,
 .size = (sizeof(v4l2_input_types_xdata) / sizeof((v4l2_input_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_input_types_xdata)), __typeof__(&(v4l2_input_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (1))
  | ((unsigned) (2))
  | ((unsigned) (3))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_INPUT_TYPE_TUNER")
  + sizeof("V4L2_INPUT_TYPE_CAMERA")
  + sizeof("V4L2_INPUT_TYPE_TOUCH")
  ,
} };

static int
print_v4l2_input(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct_v4l2_input i;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&i)), (void *) (&i)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((i).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((i).index) : sizeof((i).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((i).index) : sizeof((i).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((i).index) : sizeof((i).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((i).index) : (unsigned long long) ((i).index))); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&i)), (void *) (&i))) {
  tprint_struct_next();
  do { tprints_field_name("name"); print_quoted_cstring((const char *) (i).name, sizeof((i).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((i).name)), __typeof__(&((i).name)[0])))]) * 0)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("type"); printxval64((v4l2_input_types), (sizeof((i).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((i).type) : sizeof((i).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((i).type) : sizeof((i).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((i).type) : sizeof((i).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((i).type) : (unsigned long long) ((i).type)), ("V4L2_INPUT_TYPE_???")); } while (0);
 }
 tprint_struct_end();
 return 0200;
}
_Static_assert((unsigned long long) (0x00990000)
      > (unsigned long long) ((0x00980000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_CODEC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009a0000)
      > (unsigned long long) ((0x00990000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_CAMERA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009b0000)
      > (unsigned long long) ((0x009a0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_FM_TX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009c0000)
      > (unsigned long long) ((0x009b0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_FLASH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009d0000)
      > (unsigned long long) ((0x009c0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_JPEG"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009e0000)
      > (unsigned long long) ((0x009d0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_IMAGE_SOURCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x009f0000)
      > (unsigned long long) ((0x009e0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_IMAGE_PROC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a00000)
      > (unsigned long long) ((0x009f0000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_DV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a10000)
      > (unsigned long long) ((0x00a00000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_FM_RX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a20000)
      > (unsigned long long) ((0x00a10000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_RF_TUNER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a30000)
      > (unsigned long long) ((0x00a20000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_DETECT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a40000)
      > (unsigned long long) ((0x00a30000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_CODEC_STATELESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (0x00a50000)
      > (unsigned long long) ((0x00a40000)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_CLASS_COLORIMETRY"
      " is not larger than the previous value");

static const struct xlat_data v4l2_control_classes_xdata[] = {
 { (unsigned)(0x00980000), "V4L2_CTRL_CLASS_USER" },
 { (unsigned)(0x00990000), "V4L2_CTRL_CLASS_CODEC" },
 { (unsigned)(0x009a0000), "V4L2_CTRL_CLASS_CAMERA" },
 { (unsigned)(0x009b0000), "V4L2_CTRL_CLASS_FM_TX" },
 { (unsigned)(0x009c0000), "V4L2_CTRL_CLASS_FLASH" },
 { (unsigned)(0x009d0000), "V4L2_CTRL_CLASS_JPEG" },
 { (unsigned)(0x009e0000), "V4L2_CTRL_CLASS_IMAGE_SOURCE" },
 { (unsigned)(0x009f0000), "V4L2_CTRL_CLASS_IMAGE_PROC" },
 { (unsigned)(0x00a00000), "V4L2_CTRL_CLASS_DV" },
 { (unsigned)(0x00a10000), "V4L2_CTRL_CLASS_FM_RX" },
 { (unsigned)(0x00a20000), "V4L2_CTRL_CLASS_RF_TUNER" },
 { (unsigned)(0x00a30000), "V4L2_CTRL_CLASS_DETECT" },
 { (unsigned)(0x00a40000), "V4L2_CTRL_CLASS_CODEC_STATELESS" },
 { (unsigned)(0x00a50000), "V4L2_CTRL_CLASS_COLORIMETRY" },
};
const struct xlat v4l2_control_classes[1] = { {
 .data = v4l2_control_classes_xdata,
 .size = (sizeof(v4l2_control_classes_xdata) / sizeof((v4l2_control_classes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_classes_xdata)), __typeof__(&(v4l2_control_classes_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (0x00980000))
  | ((unsigned) (0x00990000))
  | ((unsigned) (0x009a0000))
  | ((unsigned) (0x009b0000))
  | ((unsigned) (0x009c0000))
  | ((unsigned) (0x009d0000))
  | ((unsigned) (0x009e0000))
  | ((unsigned) (0x009f0000))
  | ((unsigned) (0x00a00000))
  | ((unsigned) (0x00a10000))
  | ((unsigned) (0x00a20000))
  | ((unsigned) (0x00a30000))
  | ((unsigned) (0x00a40000))
  | ((unsigned) (0x00a50000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CTRL_CLASS_USER")
  + sizeof("V4L2_CTRL_CLASS_CODEC")
  + sizeof("V4L2_CTRL_CLASS_CAMERA")
  + sizeof("V4L2_CTRL_CLASS_FM_TX")
  + sizeof("V4L2_CTRL_CLASS_FLASH")
  + sizeof("V4L2_CTRL_CLASS_JPEG")
  + sizeof("V4L2_CTRL_CLASS_IMAGE_SOURCE")
  + sizeof("V4L2_CTRL_CLASS_IMAGE_PROC")
  + sizeof("V4L2_CTRL_CLASS_DV")
  + sizeof("V4L2_CTRL_CLASS_FM_RX")
  + sizeof("V4L2_CTRL_CLASS_RF_TUNER")
  + sizeof("V4L2_CTRL_CLASS_DETECT")
  + sizeof("V4L2_CTRL_CLASS_CODEC_STATELESS")
  + sizeof("V4L2_CTRL_CLASS_COLORIMETRY")
  ,
} };


static const struct xlat_data v4l2_control_id_bases_xdata[] = {
 { (unsigned)((0x00980000 | 0x900)), "V4L2_CID_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1000)), "V4L2_CID_USER_MEYE_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1010)), "V4L2_CID_USER_BTTV_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1030)), "V4L2_CID_USER_S2255_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1040)), "V4L2_CID_USER_SI476X_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1050)), "V4L2_CID_USER_TI_VPE_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1060)), "V4L2_CID_USER_SAA7134_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1070)), "V4L2_CID_USER_ADV7180_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1080)), "V4L2_CID_USER_TC358743_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1090)), "V4L2_CID_USER_MAX217X_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x10b0)), "V4L2_CID_USER_IMX_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x10c0)), "V4L2_CID_USER_ATMEL_ISC_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x10e0)), "V4L2_CID_USER_CODA_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x10f0)), "V4L2_CID_USER_CCS_BASE" },
 { (unsigned)(((0x00980000 | 0x900) + 0x1170)), "V4L2_CID_USER_ALLEGRO_BASE" },
 { (unsigned)((0x00990000 | 0x900)), "V4L2_CID_CODEC_BASE" },
 { (unsigned)((0x00990000 | 0x1000)), "V4L2_CID_MPEG_CX2341X_BASE" },
 { (unsigned)((0x00990000 | 0x1100)), "V4L2_CID_MPEG_MFC51_BASE" },
 { (unsigned)((0x009a0000 | 0x900)), "V4L2_CID_CAMERA_CLASS_BASE" },
 { (unsigned)((0x009b0000 | 0x900)), "V4L2_CID_FM_TX_CLASS_BASE" },
 { (unsigned)((0x009c0000 | 0x900)), "V4L2_CID_FLASH_CLASS_BASE" },
 { (unsigned)((0x009d0000 | 0x900)), "V4L2_CID_JPEG_CLASS_BASE" },
 { (unsigned)((0x009e0000 | 0x900)), "V4L2_CID_IMAGE_SOURCE_CLASS_BASE" },
 { (unsigned)((0x009f0000 | 0x900)), "V4L2_CID_IMAGE_PROC_CLASS_BASE" },
 { (unsigned)((0x00a00000 | 0x900)), "V4L2_CID_DV_CLASS_BASE" },
 { (unsigned)((0x00a10000 | 0x900)), "V4L2_CID_FM_RX_CLASS_BASE" },
 { (unsigned)((0x00a20000 | 0x900)), "V4L2_CID_RF_TUNER_CLASS_BASE" },
 { (unsigned)((0x00a30000 | 0x900)), "V4L2_CID_DETECT_CLASS_BASE" },
 { (unsigned)((0x00a40000 | 0x900)), "V4L2_CID_CODEC_STATELESS_BASE" },
};
const struct xlat v4l2_control_id_bases[1] = { {
 .data = v4l2_control_id_bases_xdata,
 .size = (sizeof(v4l2_control_id_bases_xdata) / sizeof((v4l2_control_id_bases_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_id_bases_xdata)), __typeof__(&(v4l2_control_id_bases_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) ((0x00980000 | 0x900)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1000)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1010)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1030)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1040)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1050)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1060)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1070)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1080)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1090)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x10b0)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x10c0)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x10e0)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x10f0)))
  | ((unsigned) (((0x00980000 | 0x900) + 0x1170)))
  | ((unsigned) ((0x00990000 | 0x900)))
  | ((unsigned) ((0x00990000 | 0x1000)))
  | ((unsigned) ((0x00990000 | 0x1100)))
  | ((unsigned) ((0x009a0000 | 0x900)))
  | ((unsigned) ((0x009b0000 | 0x900)))
  | ((unsigned) ((0x009c0000 | 0x900)))
  | ((unsigned) ((0x009d0000 | 0x900)))
  | ((unsigned) ((0x009e0000 | 0x900)))
  | ((unsigned) ((0x009f0000 | 0x900)))
  | ((unsigned) ((0x00a00000 | 0x900)))
  | ((unsigned) ((0x00a10000 | 0x900)))
  | ((unsigned) ((0x00a20000 | 0x900)))
  | ((unsigned) ((0x00a30000 | 0x900)))
  | ((unsigned) ((0x00a40000 | 0x900)))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CID_BASE")
  + sizeof("V4L2_CID_USER_MEYE_BASE")
  + sizeof("V4L2_CID_USER_BTTV_BASE")
  + sizeof("V4L2_CID_USER_S2255_BASE")
  + sizeof("V4L2_CID_USER_SI476X_BASE")
  + sizeof("V4L2_CID_USER_TI_VPE_BASE")
  + sizeof("V4L2_CID_USER_SAA7134_BASE")
  + sizeof("V4L2_CID_USER_ADV7180_BASE")
  + sizeof("V4L2_CID_USER_TC358743_BASE")
  + sizeof("V4L2_CID_USER_MAX217X_BASE")
  + sizeof("V4L2_CID_USER_IMX_BASE")
  + sizeof("V4L2_CID_USER_ATMEL_ISC_BASE")
  + sizeof("V4L2_CID_USER_CODA_BASE")
  + sizeof("V4L2_CID_USER_CCS_BASE")
  + sizeof("V4L2_CID_USER_ALLEGRO_BASE")
  + sizeof("V4L2_CID_CODEC_BASE")
  + sizeof("V4L2_CID_MPEG_CX2341X_BASE")
  + sizeof("V4L2_CID_MPEG_MFC51_BASE")
  + sizeof("V4L2_CID_CAMERA_CLASS_BASE")
  + sizeof("V4L2_CID_FM_TX_CLASS_BASE")
  + sizeof("V4L2_CID_FLASH_CLASS_BASE")
  + sizeof("V4L2_CID_JPEG_CLASS_BASE")
  + sizeof("V4L2_CID_IMAGE_SOURCE_CLASS_BASE")
  + sizeof("V4L2_CID_IMAGE_PROC_CLASS_BASE")
  + sizeof("V4L2_CID_DV_CLASS_BASE")
  + sizeof("V4L2_CID_FM_RX_CLASS_BASE")
  + sizeof("V4L2_CID_RF_TUNER_CLASS_BASE")
  + sizeof("V4L2_CID_DETECT_CLASS_BASE")
  + sizeof("V4L2_CID_CODEC_STATELESS_BASE")
  ,
} };

_Static_assert((unsigned long long) (((0x00980000 | 0x900)+1))
      > (unsigned long long) ((((0x00980000 | 0x900)+0))),
      "Incorrect order in #sorted xlat: V4L2_CID_CONTRAST"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+2))
      > (unsigned long long) ((((0x00980000 | 0x900)+1))),
      "Incorrect order in #sorted xlat: V4L2_CID_SATURATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+3))
      > (unsigned long long) ((((0x00980000 | 0x900)+2))),
      "Incorrect order in #sorted xlat: V4L2_CID_HUE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+5))
      > (unsigned long long) ((((0x00980000 | 0x900)+3))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_VOLUME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+6))
      > (unsigned long long) ((((0x00980000 | 0x900)+5))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+7))
      > (unsigned long long) ((((0x00980000 | 0x900)+6))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_BASS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+8))
      > (unsigned long long) ((((0x00980000 | 0x900)+7))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_TREBLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+9))
      > (unsigned long long) ((((0x00980000 | 0x900)+8))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_MUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+10))
      > (unsigned long long) ((((0x00980000 | 0x900)+9))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_LOUDNESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+11))
      > (unsigned long long) ((((0x00980000 | 0x900)+10))),
      "Incorrect order in #sorted xlat: V4L2_CID_BLACK_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+12))
      > (unsigned long long) ((((0x00980000 | 0x900)+11))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_WHITE_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+13))
      > (unsigned long long) ((((0x00980000 | 0x900)+12))),
      "Incorrect order in #sorted xlat: V4L2_CID_DO_WHITE_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+14))
      > (unsigned long long) ((((0x00980000 | 0x900)+13))),
      "Incorrect order in #sorted xlat: V4L2_CID_RED_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+15))
      > (unsigned long long) ((((0x00980000 | 0x900)+14))),
      "Incorrect order in #sorted xlat: V4L2_CID_BLUE_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+16))
      > (unsigned long long) ((((0x00980000 | 0x900)+15))),
      "Incorrect order in #sorted xlat: V4L2_CID_GAMMA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+17))
      > (unsigned long long) ((((0x00980000 | 0x900)+16))),
      "Incorrect order in #sorted xlat: V4L2_CID_EXPOSURE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+18))
      > (unsigned long long) ((((0x00980000 | 0x900)+17))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTOGAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+19))
      > (unsigned long long) ((((0x00980000 | 0x900)+18))),
      "Incorrect order in #sorted xlat: V4L2_CID_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+20))
      > (unsigned long long) ((((0x00980000 | 0x900)+19))),
      "Incorrect order in #sorted xlat: V4L2_CID_HFLIP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+21))
      > (unsigned long long) ((((0x00980000 | 0x900)+20))),
      "Incorrect order in #sorted xlat: V4L2_CID_VFLIP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+22))
      > (unsigned long long) ((((0x00980000 | 0x900)+21))),
      "Incorrect order in #sorted xlat: V4L2_CID_HCENTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+23))
      > (unsigned long long) ((((0x00980000 | 0x900)+22))),
      "Incorrect order in #sorted xlat: V4L2_CID_VCENTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+24))
      > (unsigned long long) ((((0x00980000 | 0x900)+23))),
      "Incorrect order in #sorted xlat: V4L2_CID_POWER_LINE_FREQUENCY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+25))
      > (unsigned long long) ((((0x00980000 | 0x900)+24))),
      "Incorrect order in #sorted xlat: V4L2_CID_HUE_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+26))
      > (unsigned long long) ((((0x00980000 | 0x900)+25))),
      "Incorrect order in #sorted xlat: V4L2_CID_WHITE_BALANCE_TEMPERATURE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+27))
      > (unsigned long long) ((((0x00980000 | 0x900)+26))),
      "Incorrect order in #sorted xlat: V4L2_CID_SHARPNESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+28))
      > (unsigned long long) ((((0x00980000 | 0x900)+27))),
      "Incorrect order in #sorted xlat: V4L2_CID_BACKLIGHT_COMPENSATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+29))
      > (unsigned long long) ((((0x00980000 | 0x900)+28))),
      "Incorrect order in #sorted xlat: V4L2_CID_CHROMA_AGC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+30))
      > (unsigned long long) ((((0x00980000 | 0x900)+29))),
      "Incorrect order in #sorted xlat: V4L2_CID_COLOR_KILLER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+31))
      > (unsigned long long) ((((0x00980000 | 0x900)+30))),
      "Incorrect order in #sorted xlat: V4L2_CID_COLORFX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+32))
      > (unsigned long long) ((((0x00980000 | 0x900)+31))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTOBRIGHTNESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+33))
      > (unsigned long long) ((((0x00980000 | 0x900)+32))),
      "Incorrect order in #sorted xlat: V4L2_CID_BAND_STOP_FILTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+34))
      > (unsigned long long) ((((0x00980000 | 0x900)+33))),
      "Incorrect order in #sorted xlat: V4L2_CID_ROTATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+35))
      > (unsigned long long) ((((0x00980000 | 0x900)+34))),
      "Incorrect order in #sorted xlat: V4L2_CID_BG_COLOR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+36))
      > (unsigned long long) ((((0x00980000 | 0x900)+35))),
      "Incorrect order in #sorted xlat: V4L2_CID_CHROMA_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+37))
      > (unsigned long long) ((((0x00980000 | 0x900)+36))),
      "Incorrect order in #sorted xlat: V4L2_CID_ILLUMINATORS_1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+38))
      > (unsigned long long) ((((0x00980000 | 0x900)+37))),
      "Incorrect order in #sorted xlat: V4L2_CID_ILLUMINATORS_2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+39))
      > (unsigned long long) ((((0x00980000 | 0x900)+38))),
      "Incorrect order in #sorted xlat: V4L2_CID_MIN_BUFFERS_FOR_CAPTURE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+40))
      > (unsigned long long) ((((0x00980000 | 0x900)+39))),
      "Incorrect order in #sorted xlat: V4L2_CID_MIN_BUFFERS_FOR_OUTPUT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+41))
      > (unsigned long long) ((((0x00980000 | 0x900)+40))),
      "Incorrect order in #sorted xlat: V4L2_CID_ALPHA_COMPONENT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00980000 | 0x900)+42))
      > (unsigned long long) ((((0x00980000 | 0x900)+41))),
      "Incorrect order in #sorted xlat: V4L2_CID_COLORFX_CBCR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+0))
      > (unsigned long long) ((((0x00980000 | 0x900)+42))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+1))
      > (unsigned long long) ((((0x00990000 | 0x900)+0))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PID_PMT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+2))
      > (unsigned long long) ((((0x00990000 | 0x900)+1))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PID_AUDIO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+3))
      > (unsigned long long) ((((0x00990000 | 0x900)+2))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PID_VIDEO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+4))
      > (unsigned long long) ((((0x00990000 | 0x900)+3))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PID_PCR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+5))
      > (unsigned long long) ((((0x00990000 | 0x900)+4))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PES_ID_AUDIO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+6))
      > (unsigned long long) ((((0x00990000 | 0x900)+5))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_PES_ID_VIDEO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+7))
      > (unsigned long long) ((((0x00990000 | 0x900)+6))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_STREAM_VBI_FMT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+100))
      > (unsigned long long) ((((0x00990000 | 0x900)+7))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_SAMPLING_FREQ"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+101))
      > (unsigned long long) ((((0x00990000 | 0x900)+100))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_ENCODING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+102))
      > (unsigned long long) ((((0x00990000 | 0x900)+101))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_L1_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+103))
      > (unsigned long long) ((((0x00990000 | 0x900)+102))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_L2_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+104))
      > (unsigned long long) ((((0x00990000 | 0x900)+103))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_L3_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+105))
      > (unsigned long long) ((((0x00990000 | 0x900)+104))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+106))
      > (unsigned long long) ((((0x00990000 | 0x900)+105))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_MODE_EXTENSION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+107))
      > (unsigned long long) ((((0x00990000 | 0x900)+106))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_EMPHASIS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+108))
      > (unsigned long long) ((((0x00990000 | 0x900)+107))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_CRC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+109))
      > (unsigned long long) ((((0x00990000 | 0x900)+108))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_MUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+110))
      > (unsigned long long) ((((0x00990000 | 0x900)+109))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_AAC_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+111))
      > (unsigned long long) ((((0x00990000 | 0x900)+110))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_AC3_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+112))
      > (unsigned long long) ((((0x00990000 | 0x900)+111))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_DEC_PLAYBACK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+113))
      > (unsigned long long) ((((0x00990000 | 0x900)+112))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_AUDIO_DEC_MULTILINGUAL_PLAYBACK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+200))
      > (unsigned long long) ((((0x00990000 | 0x900)+113))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_ENCODING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+201))
      > (unsigned long long) ((((0x00990000 | 0x900)+200))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_ASPECT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+202))
      > (unsigned long long) ((((0x00990000 | 0x900)+201))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_B_FRAMES"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+203))
      > (unsigned long long) ((((0x00990000 | 0x900)+202))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_GOP_SIZE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+204))
      > (unsigned long long) ((((0x00990000 | 0x900)+203))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_GOP_CLOSURE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+205))
      > (unsigned long long) ((((0x00990000 | 0x900)+204))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_PULLDOWN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+206))
      > (unsigned long long) ((((0x00990000 | 0x900)+205))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_BITRATE_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+207))
      > (unsigned long long) ((((0x00990000 | 0x900)+206))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_BITRATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+208))
      > (unsigned long long) ((((0x00990000 | 0x900)+207))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_BITRATE_PEAK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+209))
      > (unsigned long long) ((((0x00990000 | 0x900)+208))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_TEMPORAL_DECIMATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+210))
      > (unsigned long long) ((((0x00990000 | 0x900)+209))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+211))
      > (unsigned long long) ((((0x00990000 | 0x900)+210))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MUTE_YUV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+212))
      > (unsigned long long) ((((0x00990000 | 0x900)+211))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DECODER_SLICE_INTERFACE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+213))
      > (unsigned long long) ((((0x00990000 | 0x900)+212))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DECODER_MPEG4_DEBLOCK_FILTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+214))
      > (unsigned long long) ((((0x00990000 | 0x900)+213))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_CYCLIC_INTRA_REFRESH_MB"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+215))
      > (unsigned long long) ((((0x00990000 | 0x900)+214))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_FRAME_RC_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+216))
      > (unsigned long long) ((((0x00990000 | 0x900)+215))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEADER_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+217))
      > (unsigned long long) ((((0x00990000 | 0x900)+216))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MAX_REF_PIC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+218))
      > (unsigned long long) ((((0x00990000 | 0x900)+217))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MB_RC_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+219))
      > (unsigned long long) ((((0x00990000 | 0x900)+218))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_BYTES"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+220))
      > (unsigned long long) ((((0x00990000 | 0x900)+219))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_MB"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+221))
      > (unsigned long long) ((((0x00990000 | 0x900)+220))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+222))
      > (unsigned long long) ((((0x00990000 | 0x900)+221))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VBV_SIZE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+223))
      > (unsigned long long) ((((0x00990000 | 0x900)+222))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DEC_PTS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+224))
      > (unsigned long long) ((((0x00990000 | 0x900)+223))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DEC_FRAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+225))
      > (unsigned long long) ((((0x00990000 | 0x900)+224))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VBV_DELAY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+226))
      > (unsigned long long) ((((0x00990000 | 0x900)+225))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+227))
      > (unsigned long long) ((((0x00990000 | 0x900)+226))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MV_H_SEARCH_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+228))
      > (unsigned long long) ((((0x00990000 | 0x900)+227))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MV_V_SEARCH_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+229))
      > (unsigned long long) ((((0x00990000 | 0x900)+228))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+230))
      > (unsigned long long) ((((0x00990000 | 0x900)+229))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_BASELAYER_PRIORITY_ID"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+231))
      > (unsigned long long) ((((0x00990000 | 0x900)+230))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_AU_DELIMITER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+232))
      > (unsigned long long) ((((0x00990000 | 0x900)+231))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_LTR_COUNT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+233))
      > (unsigned long long) ((((0x00990000 | 0x900)+232))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_FRAME_LTR_INDEX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+234))
      > (unsigned long long) ((((0x00990000 | 0x900)+233))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_USE_LTR_FRAMES"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+235))
      > (unsigned long long) ((((0x00990000 | 0x900)+234))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DEC_CONCEAL_COLOR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+236))
      > (unsigned long long) ((((0x00990000 | 0x900)+235))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+237))
      > (unsigned long long) ((((0x00990000 | 0x900)+236))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 250))
      > (unsigned long long) ((((0x00990000 | 0x900)+237))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG2_SLICE_PARAMS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 251))
      > (unsigned long long) ((((0x00990000 | 0x900) + 250))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG2_QUANTIZATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 290))
      > (unsigned long long) ((((0x00990000 | 0x900) + 251))),
      "Incorrect order in #sorted xlat: V4L2_CID_FWHT_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 291))
      > (unsigned long long) ((((0x00990000 | 0x900) + 290))),
      "Incorrect order in #sorted xlat: V4L2_CID_FWHT_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+300))
      > (unsigned long long) ((((0x00990000 | 0x900) + 291))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H263_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+301))
      > (unsigned long long) ((((0x00990000 | 0x900)+300))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H263_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+302))
      > (unsigned long long) ((((0x00990000 | 0x900)+301))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H263_B_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+303))
      > (unsigned long long) ((((0x00990000 | 0x900)+302))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H263_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+304))
      > (unsigned long long) ((((0x00990000 | 0x900)+303))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H263_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+350))
      > (unsigned long long) ((((0x00990000 | 0x900)+304))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+351))
      > (unsigned long long) ((((0x00990000 | 0x900)+350))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+352))
      > (unsigned long long) ((((0x00990000 | 0x900)+351))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_B_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+353))
      > (unsigned long long) ((((0x00990000 | 0x900)+352))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+354))
      > (unsigned long long) ((((0x00990000 | 0x900)+353))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+355))
      > (unsigned long long) ((((0x00990000 | 0x900)+354))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_8X8_TRANSFORM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+356))
      > (unsigned long long) ((((0x00990000 | 0x900)+355))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_CPB_SIZE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+357))
      > (unsigned long long) ((((0x00990000 | 0x900)+356))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_ENTROPY_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+358))
      > (unsigned long long) ((((0x00990000 | 0x900)+357))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_I_PERIOD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+359))
      > (unsigned long long) ((((0x00990000 | 0x900)+358))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+360))
      > (unsigned long long) ((((0x00990000 | 0x900)+359))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_ALPHA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+361))
      > (unsigned long long) ((((0x00990000 | 0x900)+360))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_BETA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+362))
      > (unsigned long long) ((((0x00990000 | 0x900)+361))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+363))
      > (unsigned long long) ((((0x00990000 | 0x900)+362))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_PROFILE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+364))
      > (unsigned long long) ((((0x00990000 | 0x900)+363))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_HEIGHT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+365))
      > (unsigned long long) ((((0x00990000 | 0x900)+364))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_WIDTH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+366))
      > (unsigned long long) ((((0x00990000 | 0x900)+365))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+367))
      > (unsigned long long) ((((0x00990000 | 0x900)+366))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_IDC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+368))
      > (unsigned long long) ((((0x00990000 | 0x900)+367))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_SEI_FRAME_PACKING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+369))
      > (unsigned long long) ((((0x00990000 | 0x900)+368))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_SEI_FP_CURRENT_FRAME_0"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+370))
      > (unsigned long long) ((((0x00990000 | 0x900)+369))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+371))
      > (unsigned long long) ((((0x00990000 | 0x900)+370))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+372))
      > (unsigned long long) ((((0x00990000 | 0x900)+371))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO_MAP_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+373))
      > (unsigned long long) ((((0x00990000 | 0x900)+372))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO_SLICE_GROUP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+374))
      > (unsigned long long) ((((0x00990000 | 0x900)+373))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_DIRECTION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+375))
      > (unsigned long long) ((((0x00990000 | 0x900)+374))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_RATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+376))
      > (unsigned long long) ((((0x00990000 | 0x900)+375))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_FMO_RUN_LENGTH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+377))
      > (unsigned long long) ((((0x00990000 | 0x900)+376))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_ASO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+378))
      > (unsigned long long) ((((0x00990000 | 0x900)+377))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_ASO_SLICE_ORDER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+379))
      > (unsigned long long) ((((0x00990000 | 0x900)+378))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+380))
      > (unsigned long long) ((((0x00990000 | 0x900)+379))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+381))
      > (unsigned long long) ((((0x00990000 | 0x900)+380))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+382))
      > (unsigned long long) ((((0x00990000 | 0x900)+381))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+383))
      > (unsigned long long) ((((0x00990000 | 0x900)+382))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_CONSTRAINED_INTRA_PREDICTION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+384))
      > (unsigned long long) ((((0x00990000 | 0x900)+383))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_CHROMA_QP_INDEX_OFFSET"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+385))
      > (unsigned long long) ((((0x00990000 | 0x900)+384))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+386))
      > (unsigned long long) ((((0x00990000 | 0x900)+385))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+387))
      > (unsigned long long) ((((0x00990000 | 0x900)+386))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+388))
      > (unsigned long long) ((((0x00990000 | 0x900)+387))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+389))
      > (unsigned long long) ((((0x00990000 | 0x900)+388))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+390))
      > (unsigned long long) ((((0x00990000 | 0x900)+389))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+391))
      > (unsigned long long) ((((0x00990000 | 0x900)+390))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L0_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+392))
      > (unsigned long long) ((((0x00990000 | 0x900)+391))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L1_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+393))
      > (unsigned long long) ((((0x00990000 | 0x900)+392))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L2_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+394))
      > (unsigned long long) ((((0x00990000 | 0x900)+393))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L3_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+395))
      > (unsigned long long) ((((0x00990000 | 0x900)+394))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L4_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+396))
      > (unsigned long long) ((((0x00990000 | 0x900)+395))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L5_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+397))
      > (unsigned long long) ((((0x00990000 | 0x900)+396))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L6_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+400))
      > (unsigned long long) ((((0x00990000 | 0x900)+397))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+401))
      > (unsigned long long) ((((0x00990000 | 0x900)+400))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+402))
      > (unsigned long long) ((((0x00990000 | 0x900)+401))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_B_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+403))
      > (unsigned long long) ((((0x00990000 | 0x900)+402))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+404))
      > (unsigned long long) ((((0x00990000 | 0x900)+403))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+405))
      > (unsigned long long) ((((0x00990000 | 0x900)+404))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+406))
      > (unsigned long long) ((((0x00990000 | 0x900)+405))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_PROFILE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+407))
      > (unsigned long long) ((((0x00990000 | 0x900)+406))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_MPEG4_QPEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+500))
      > (unsigned long long) ((((0x00990000 | 0x900)+407))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_NUM_PARTITIONS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+501))
      > (unsigned long long) ((((0x00990000 | 0x900)+500))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_IMD_DISABLE_4X4"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+502))
      > (unsigned long long) ((((0x00990000 | 0x900)+501))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_NUM_REF_FRAMES"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+503))
      > (unsigned long long) ((((0x00990000 | 0x900)+502))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_FILTER_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+504))
      > (unsigned long long) ((((0x00990000 | 0x900)+503))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_FILTER_SHARPNESS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+505))
      > (unsigned long long) ((((0x00990000 | 0x900)+504))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_REF_PERIOD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+506))
      > (unsigned long long) ((((0x00990000 | 0x900)+505))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_SEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+507))
      > (unsigned long long) ((((0x00990000 | 0x900)+506))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+508))
      > (unsigned long long) ((((0x00990000 | 0x900)+507))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+509))
      > (unsigned long long) ((((0x00990000 | 0x900)+508))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+510))
      > (unsigned long long) ((((0x00990000 | 0x900)+509))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VPX_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+511))
      > (unsigned long long) ((((0x00990000 | 0x900)+510))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VP8_PROFILE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900)+512))
      > (unsigned long long) ((((0x00990000 | 0x900)+511))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_VP9_PROFILE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 600))
      > (unsigned long long) ((((0x00990000 | 0x900)+512))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 601))
      > (unsigned long long) ((((0x00990000 | 0x900) + 600))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 602))
      > (unsigned long long) ((((0x00990000 | 0x900) + 601))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 603))
      > (unsigned long long) ((((0x00990000 | 0x900) + 602))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 604))
      > (unsigned long long) ((((0x00990000 | 0x900) + 603))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 605))
      > (unsigned long long) ((((0x00990000 | 0x900) + 604))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 606))
      > (unsigned long long) ((((0x00990000 | 0x900) + 605))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 607))
      > (unsigned long long) ((((0x00990000 | 0x900) + 606))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_LAYER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 608))
      > (unsigned long long) ((((0x00990000 | 0x900) + 607))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 609))
      > (unsigned long long) ((((0x00990000 | 0x900) + 608))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 610))
      > (unsigned long long) ((((0x00990000 | 0x900) + 609))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 611))
      > (unsigned long long) ((((0x00990000 | 0x900) + 610))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 612))
      > (unsigned long long) ((((0x00990000 | 0x900) + 611))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 613))
      > (unsigned long long) ((((0x00990000 | 0x900) + 612))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 614))
      > (unsigned long long) ((((0x00990000 | 0x900) + 613))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 615))
      > (unsigned long long) ((((0x00990000 | 0x900) + 614))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_PROFILE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 616))
      > (unsigned long long) ((((0x00990000 | 0x900) + 615))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 617))
      > (unsigned long long) ((((0x00990000 | 0x900) + 616))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_FRAME_RATE_RESOLUTION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 618))
      > (unsigned long long) ((((0x00990000 | 0x900) + 617))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_TIER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 619))
      > (unsigned long long) ((((0x00990000 | 0x900) + 618))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_MAX_PARTITION_DEPTH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 620))
      > (unsigned long long) ((((0x00990000 | 0x900) + 619))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 621))
      > (unsigned long long) ((((0x00990000 | 0x900) + 620))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_LF_BETA_OFFSET_DIV2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 622))
      > (unsigned long long) ((((0x00990000 | 0x900) + 621))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_LF_TC_OFFSET_DIV2"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 623))
      > (unsigned long long) ((((0x00990000 | 0x900) + 622))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 624))
      > (unsigned long long) ((((0x00990000 | 0x900) + 623))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_PERIOD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 625))
      > (unsigned long long) ((((0x00990000 | 0x900) + 624))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_LOSSLESS_CU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 626))
      > (unsigned long long) ((((0x00990000 | 0x900) + 625))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_CONST_INTRA_PRED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 627))
      > (unsigned long long) ((((0x00990000 | 0x900) + 626))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_WAVEFRONT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 628))
      > (unsigned long long) ((((0x00990000 | 0x900) + 627))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_GENERAL_PB"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 629))
      > (unsigned long long) ((((0x00990000 | 0x900) + 628))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_TEMPORAL_ID"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 630))
      > (unsigned long long) ((((0x00990000 | 0x900) + 629))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_STRONG_SMOOTHING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 631))
      > (unsigned long long) ((((0x00990000 | 0x900) + 630))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_MAX_NUM_MERGE_MV_MINUS1"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 632))
      > (unsigned long long) ((((0x00990000 | 0x900) + 631))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_INTRA_PU_SPLIT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 633))
      > (unsigned long long) ((((0x00990000 | 0x900) + 632))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_TMV_PREDICTION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 634))
      > (unsigned long long) ((((0x00990000 | 0x900) + 633))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_WITHOUT_STARTCODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 635))
      > (unsigned long long) ((((0x00990000 | 0x900) + 634))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_SIZE_OF_LENGTH_FIELD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 636))
      > (unsigned long long) ((((0x00990000 | 0x900) + 635))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 637))
      > (unsigned long long) ((((0x00990000 | 0x900) + 636))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 638))
      > (unsigned long long) ((((0x00990000 | 0x900) + 637))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 639))
      > (unsigned long long) ((((0x00990000 | 0x900) + 638))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 640))
      > (unsigned long long) ((((0x00990000 | 0x900) + 639))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 641))
      > (unsigned long long) ((((0x00990000 | 0x900) + 640))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 642))
      > (unsigned long long) ((((0x00990000 | 0x900) + 641))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_BR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 643))
      > (unsigned long long) ((((0x00990000 | 0x900) + 642))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_REF_NUMBER_FOR_PFRAMES"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 644))
      > (unsigned long long) ((((0x00990000 | 0x900) + 643))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 645))
      > (unsigned long long) ((((0x00990000 | 0x900) + 644))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_CONSTANT_QUALITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 646))
      > (unsigned long long) ((((0x00990000 | 0x900) + 645))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_FRAME_SKIP_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 647))
      > (unsigned long long) ((((0x00990000 | 0x900) + 646))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 648))
      > (unsigned long long) ((((0x00990000 | 0x900) + 647))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 649))
      > (unsigned long long) ((((0x00990000 | 0x900) + 648))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 650))
      > (unsigned long long) ((((0x00990000 | 0x900) + 649))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 651))
      > (unsigned long long) ((((0x00990000 | 0x900) + 650))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MIN_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 652))
      > (unsigned long long) ((((0x00990000 | 0x900) + 651))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MAX_QP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 653))
      > (unsigned long long) ((((0x00990000 | 0x900) + 652))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x900) + 654))
      > (unsigned long long) ((((0x00990000 | 0x900) + 653))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+0))
      > (unsigned long long) ((((0x00990000 | 0x900) + 654))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+1))
      > (unsigned long long) ((((0x00990000 | 0x1000)+0))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+2))
      > (unsigned long long) ((((0x00990000 | 0x1000)+1))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+3))
      > (unsigned long long) ((((0x00990000 | 0x1000)+2))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+4))
      > (unsigned long long) ((((0x00990000 | 0x1000)+3))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+5))
      > (unsigned long long) ((((0x00990000 | 0x1000)+4))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+6))
      > (unsigned long long) ((((0x00990000 | 0x1000)+5))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+7))
      > (unsigned long long) ((((0x00990000 | 0x1000)+6))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_BOTTOM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+8))
      > (unsigned long long) ((((0x00990000 | 0x1000)+7))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_TOP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+9))
      > (unsigned long long) ((((0x00990000 | 0x1000)+8))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_BOTTOM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+10))
      > (unsigned long long) ((((0x00990000 | 0x1000)+9))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_TOP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1000)+11))
      > (unsigned long long) ((((0x00990000 | 0x1000)+10))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_CX2341X_STREAM_INSERT_NAV_PACKETS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+0))
      > (unsigned long long) ((((0x00990000 | 0x1000)+11))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+1))
      > (unsigned long long) ((((0x00990000 | 0x1100)+0))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+2))
      > (unsigned long long) ((((0x00990000 | 0x1100)+1))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+3))
      > (unsigned long long) ((((0x00990000 | 0x1100)+2))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+4))
      > (unsigned long long) ((((0x00990000 | 0x1100)+3))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_PADDING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+5))
      > (unsigned long long) ((((0x00990000 | 0x1100)+4))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_PADDING_YUV"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+6))
      > (unsigned long long) ((((0x00990000 | 0x1100)+5))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_RC_FIXED_TARGET_BIT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+7))
      > (unsigned long long) ((((0x00990000 | 0x1100)+6))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_RC_REACTION_COEFF"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+50))
      > (unsigned long long) ((((0x00990000 | 0x1100)+7))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_ACTIVITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+51))
      > (unsigned long long) ((((0x00990000 | 0x1100)+50))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_DARK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+52))
      > (unsigned long long) ((((0x00990000 | 0x1100)+51))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_SMOOTH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+53))
      > (unsigned long long) ((((0x00990000 | 0x1100)+52))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_STATIC"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00990000 | 0x1100)+54))
      > (unsigned long long) ((((0x00990000 | 0x1100)+53))),
      "Incorrect order in #sorted xlat: V4L2_CID_MPEG_MFC51_VIDEO_H264_NUM_REF_PIC_FOR_P"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+1))
      > (unsigned long long) ((((0x00990000 | 0x1100)+54))),
      "Incorrect order in #sorted xlat: V4L2_CID_EXPOSURE_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+2))
      > (unsigned long long) ((((0x009a0000 | 0x900)+1))),
      "Incorrect order in #sorted xlat: V4L2_CID_EXPOSURE_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+3))
      > (unsigned long long) ((((0x009a0000 | 0x900)+2))),
      "Incorrect order in #sorted xlat: V4L2_CID_EXPOSURE_AUTO_PRIORITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+4))
      > (unsigned long long) ((((0x009a0000 | 0x900)+3))),
      "Incorrect order in #sorted xlat: V4L2_CID_PAN_RELATIVE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+5))
      > (unsigned long long) ((((0x009a0000 | 0x900)+4))),
      "Incorrect order in #sorted xlat: V4L2_CID_TILT_RELATIVE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+6))
      > (unsigned long long) ((((0x009a0000 | 0x900)+5))),
      "Incorrect order in #sorted xlat: V4L2_CID_PAN_RESET"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+7))
      > (unsigned long long) ((((0x009a0000 | 0x900)+6))),
      "Incorrect order in #sorted xlat: V4L2_CID_TILT_RESET"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+8))
      > (unsigned long long) ((((0x009a0000 | 0x900)+7))),
      "Incorrect order in #sorted xlat: V4L2_CID_PAN_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+9))
      > (unsigned long long) ((((0x009a0000 | 0x900)+8))),
      "Incorrect order in #sorted xlat: V4L2_CID_TILT_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+10))
      > (unsigned long long) ((((0x009a0000 | 0x900)+9))),
      "Incorrect order in #sorted xlat: V4L2_CID_FOCUS_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+11))
      > (unsigned long long) ((((0x009a0000 | 0x900)+10))),
      "Incorrect order in #sorted xlat: V4L2_CID_FOCUS_RELATIVE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+12))
      > (unsigned long long) ((((0x009a0000 | 0x900)+11))),
      "Incorrect order in #sorted xlat: V4L2_CID_FOCUS_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+13))
      > (unsigned long long) ((((0x009a0000 | 0x900)+12))),
      "Incorrect order in #sorted xlat: V4L2_CID_ZOOM_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+14))
      > (unsigned long long) ((((0x009a0000 | 0x900)+13))),
      "Incorrect order in #sorted xlat: V4L2_CID_ZOOM_RELATIVE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+15))
      > (unsigned long long) ((((0x009a0000 | 0x900)+14))),
      "Incorrect order in #sorted xlat: V4L2_CID_ZOOM_CONTINUOUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+16))
      > (unsigned long long) ((((0x009a0000 | 0x900)+15))),
      "Incorrect order in #sorted xlat: V4L2_CID_PRIVACY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+17))
      > (unsigned long long) ((((0x009a0000 | 0x900)+16))),
      "Incorrect order in #sorted xlat: V4L2_CID_IRIS_ABSOLUTE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+18))
      > (unsigned long long) ((((0x009a0000 | 0x900)+17))),
      "Incorrect order in #sorted xlat: V4L2_CID_IRIS_RELATIVE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+19))
      > (unsigned long long) ((((0x009a0000 | 0x900)+18))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_EXPOSURE_BIAS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+20))
      > (unsigned long long) ((((0x009a0000 | 0x900)+19))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+21))
      > (unsigned long long) ((((0x009a0000 | 0x900)+20))),
      "Incorrect order in #sorted xlat: V4L2_CID_WIDE_DYNAMIC_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+22))
      > (unsigned long long) ((((0x009a0000 | 0x900)+21))),
      "Incorrect order in #sorted xlat: V4L2_CID_IMAGE_STABILIZATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+23))
      > (unsigned long long) ((((0x009a0000 | 0x900)+22))),
      "Incorrect order in #sorted xlat: V4L2_CID_ISO_SENSITIVITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+24))
      > (unsigned long long) ((((0x009a0000 | 0x900)+23))),
      "Incorrect order in #sorted xlat: V4L2_CID_ISO_SENSITIVITY_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+25))
      > (unsigned long long) ((((0x009a0000 | 0x900)+24))),
      "Incorrect order in #sorted xlat: V4L2_CID_EXPOSURE_METERING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+26))
      > (unsigned long long) ((((0x009a0000 | 0x900)+25))),
      "Incorrect order in #sorted xlat: V4L2_CID_SCENE_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+27))
      > (unsigned long long) ((((0x009a0000 | 0x900)+26))),
      "Incorrect order in #sorted xlat: V4L2_CID_3A_LOCK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+28))
      > (unsigned long long) ((((0x009a0000 | 0x900)+27))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_FOCUS_START"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+29))
      > (unsigned long long) ((((0x009a0000 | 0x900)+28))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_FOCUS_STOP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+30))
      > (unsigned long long) ((((0x009a0000 | 0x900)+29))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_FOCUS_STATUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+31))
      > (unsigned long long) ((((0x009a0000 | 0x900)+30))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUTO_FOCUS_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+32))
      > (unsigned long long) ((((0x009a0000 | 0x900)+31))),
      "Incorrect order in #sorted xlat: V4L2_CID_PAN_SPEED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009a0000 | 0x900)+33))
      > (unsigned long long) ((((0x009a0000 | 0x900)+32))),
      "Incorrect order in #sorted xlat: V4L2_CID_TILT_SPEED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 1))
      > (unsigned long long) ((((0x009a0000 | 0x900)+33))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_DEVIATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 2))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_PI"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 3))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_PTY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 5))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_PS_NAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 6))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_RADIO_TEXT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 7))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 6))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_MONO_STEREO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 8))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 7))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_ARTIFICIAL_HEAD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 9))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 8))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_COMPRESSED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 10))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 9))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_DYNAMIC_PTY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 11))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 10))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_TRAFFIC_ANNOUNCEMENT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 12))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 11))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_TRAFFIC_PROGRAM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 13))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 12))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_MUSIC_SPEECH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 14))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 13))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_ALT_FREQS_ENABLE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 15))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 14))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_TX_ALT_FREQS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 64))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 15))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_LIMITER_ENABLED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 65))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 64))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_LIMITER_RELEASE_TIME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 66))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 65))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_LIMITER_DEVIATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 80))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 66))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_COMPRESSION_ENABLED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 81))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 80))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_COMPRESSION_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 82))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 81))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_COMPRESSION_THRESHOLD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 83))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 82))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_COMPRESSION_ATTACK_TIME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 84))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 83))),
      "Incorrect order in #sorted xlat: V4L2_CID_AUDIO_COMPRESSION_RELEASE_TIME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 96))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 84))),
      "Incorrect order in #sorted xlat: V4L2_CID_PILOT_TONE_ENABLED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 97))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 96))),
      "Incorrect order in #sorted xlat: V4L2_CID_PILOT_TONE_DEVIATION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 98))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 97))),
      "Incorrect order in #sorted xlat: V4L2_CID_PILOT_TONE_FREQUENCY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 112))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 98))),
      "Incorrect order in #sorted xlat: V4L2_CID_TUNE_PREEMPHASIS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 113))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 112))),
      "Incorrect order in #sorted xlat: V4L2_CID_TUNE_POWER_LEVEL"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009b0000 | 0x900) + 114))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 113))),
      "Incorrect order in #sorted xlat: V4L2_CID_TUNE_ANTENNA_CAPACITOR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 1))
      > (unsigned long long) ((((0x009b0000 | 0x900) + 114))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_LED_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 2))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_STROBE_SOURCE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 3))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_STROBE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 4))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_STROBE_STOP"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 5))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 4))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_STROBE_STATUS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 6))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_TIMEOUT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 7))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 6))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_INTENSITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 8))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 7))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_TORCH_INTENSITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 9))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 8))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_INDICATOR_INTENSITY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 10))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 9))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_FAULT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 11))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 10))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_CHARGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009c0000 | 0x900) + 12))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 11))),
      "Incorrect order in #sorted xlat: V4L2_CID_FLASH_READY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 1))
      > (unsigned long long) ((((0x009c0000 | 0x900) + 12))),
      "Incorrect order in #sorted xlat: V4L2_CID_VBLANK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 2))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_HBLANK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 3))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_ANALOGUE_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 4))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_TEST_PATTERN_RED"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 5))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 4))),
      "Incorrect order in #sorted xlat: V4L2_CID_TEST_PATTERN_GREENR"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 6))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_TEST_PATTERN_BLUE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 7))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 6))),
      "Incorrect order in #sorted xlat: V4L2_CID_TEST_PATTERN_GREENB"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 8))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 7))),
      "Incorrect order in #sorted xlat: V4L2_CID_UNIT_CELL_SIZE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009e0000 | 0x900) + 9))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 8))),
      "Incorrect order in #sorted xlat: V4L2_CID_NOTIFY_GAINS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009f0000 | 0x900) + 1))
      > (unsigned long long) ((((0x009e0000 | 0x900) + 9))),
      "Incorrect order in #sorted xlat: V4L2_CID_LINK_FREQ"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009f0000 | 0x900) + 2))
      > (unsigned long long) ((((0x009f0000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_PIXEL_RATE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009f0000 | 0x900) + 3))
      > (unsigned long long) ((((0x009f0000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_TEST_PATTERN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009f0000 | 0x900) + 4))
      > (unsigned long long) ((((0x009f0000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_DEINTERLACING_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x009f0000 | 0x900) + 5))
      > (unsigned long long) ((((0x009f0000 | 0x900) + 4))),
      "Incorrect order in #sorted xlat: V4L2_CID_DIGITAL_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a00000 | 0x900) + 5))
      > (unsigned long long) ((((0x009f0000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_DV_TX_RGB_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a00000 | 0x900) + 6))
      > (unsigned long long) ((((0x00a00000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_DV_TX_IT_CONTENT_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a00000 | 0x900) + 101))
      > (unsigned long long) ((((0x00a00000 | 0x900) + 6))),
      "Incorrect order in #sorted xlat: V4L2_CID_DV_RX_RGB_RANGE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a00000 | 0x900) + 102))
      > (unsigned long long) ((((0x00a00000 | 0x900) + 101))),
      "Incorrect order in #sorted xlat: V4L2_CID_DV_RX_IT_CONTENT_TYPE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 1))
      > (unsigned long long) ((((0x00a00000 | 0x900) + 102))),
      "Incorrect order in #sorted xlat: V4L2_CID_TUNE_DEEMPHASIS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 2))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RECEPTION"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 3))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_PTY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 4))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_PS_NAME"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 5))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 4))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_RADIO_TEXT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 6))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 5))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_TRAFFIC_ANNOUNCEMENT"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 7))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 6))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_TRAFFIC_PROGRAM"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a10000 | 0x900) + 8))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 7))),
      "Incorrect order in #sorted xlat: V4L2_CID_RDS_RX_MUSIC_SPEECH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 11))
      > (unsigned long long) ((((0x00a10000 | 0x900) + 8))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_BANDWIDTH_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 12))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 11))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_BANDWIDTH"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 32))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 12))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_RF_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 41))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 32))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_LNA_GAIN_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 42))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 41))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_LNA_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 51))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 42))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_MIXER_GAIN_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 52))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 51))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_MIXER_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 61))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 52))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_IF_GAIN_AUTO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 62))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 61))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_IF_GAIN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a20000 | 0x900) + 91))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 62))),
      "Incorrect order in #sorted xlat: V4L2_CID_RF_TUNER_PLL_LOCK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a30000 | 0x900) + 1))
      > (unsigned long long) ((((0x00a20000 | 0x900) + 91))),
      "Incorrect order in #sorted xlat: V4L2_CID_DETECT_MD_MODE"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a30000 | 0x900) + 2))
      > (unsigned long long) ((((0x00a30000 | 0x900) + 1))),
      "Incorrect order in #sorted xlat: V4L2_CID_DETECT_MD_GLOBAL_THRESHOLD"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a30000 | 0x900) + 3))
      > (unsigned long long) ((((0x00a30000 | 0x900) + 2))),
      "Incorrect order in #sorted xlat: V4L2_CID_DETECT_MD_THRESHOLD_GRID"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (((0x00a30000 | 0x900) + 4))
      > (unsigned long long) ((((0x00a30000 | 0x900) + 3))),
      "Incorrect order in #sorted xlat: V4L2_CID_DETECT_MD_REGION_GRID"
      " is not larger than the previous value");

static const struct xlat_data v4l2_control_ids_xdata[] = {
 { (unsigned)(((0x00980000 | 0x900)+0)), "V4L2_CID_BRIGHTNESS" },
 { (unsigned)(((0x00980000 | 0x900)+1)), "V4L2_CID_CONTRAST" },
 { (unsigned)(((0x00980000 | 0x900)+2)), "V4L2_CID_SATURATION" },
 { (unsigned)(((0x00980000 | 0x900)+3)), "V4L2_CID_HUE" },
 { (unsigned)(((0x00980000 | 0x900)+5)), "V4L2_CID_AUDIO_VOLUME" },
 { (unsigned)(((0x00980000 | 0x900)+6)), "V4L2_CID_AUDIO_BALANCE" },
 { (unsigned)(((0x00980000 | 0x900)+7)), "V4L2_CID_AUDIO_BASS" },
 { (unsigned)(((0x00980000 | 0x900)+8)), "V4L2_CID_AUDIO_TREBLE" },
 { (unsigned)(((0x00980000 | 0x900)+9)), "V4L2_CID_AUDIO_MUTE" },
 { (unsigned)(((0x00980000 | 0x900)+10)), "V4L2_CID_AUDIO_LOUDNESS" },
 { (unsigned)(((0x00980000 | 0x900)+11)), "V4L2_CID_BLACK_LEVEL" },
 { (unsigned)(((0x00980000 | 0x900)+12)), "V4L2_CID_AUTO_WHITE_BALANCE" },
 { (unsigned)(((0x00980000 | 0x900)+13)), "V4L2_CID_DO_WHITE_BALANCE" },
 { (unsigned)(((0x00980000 | 0x900)+14)), "V4L2_CID_RED_BALANCE" },
 { (unsigned)(((0x00980000 | 0x900)+15)), "V4L2_CID_BLUE_BALANCE" },
 { (unsigned)(((0x00980000 | 0x900)+16)), "V4L2_CID_GAMMA" },
 { (unsigned)(((0x00980000 | 0x900)+17)), "V4L2_CID_EXPOSURE" },
 { (unsigned)(((0x00980000 | 0x900)+18)), "V4L2_CID_AUTOGAIN" },
 { (unsigned)(((0x00980000 | 0x900)+19)), "V4L2_CID_GAIN" },
 { (unsigned)(((0x00980000 | 0x900)+20)), "V4L2_CID_HFLIP" },
 { (unsigned)(((0x00980000 | 0x900)+21)), "V4L2_CID_VFLIP" },
 { (unsigned)(((0x00980000 | 0x900)+22)), "V4L2_CID_HCENTER" },
 { (unsigned)(((0x00980000 | 0x900)+23)), "V4L2_CID_VCENTER" },
 { (unsigned)(((0x00980000 | 0x900)+24)), "V4L2_CID_POWER_LINE_FREQUENCY" },
 { (unsigned)(((0x00980000 | 0x900)+25)), "V4L2_CID_HUE_AUTO" },
 { (unsigned)(((0x00980000 | 0x900)+26)), "V4L2_CID_WHITE_BALANCE_TEMPERATURE" },
 { (unsigned)(((0x00980000 | 0x900)+27)), "V4L2_CID_SHARPNESS" },
 { (unsigned)(((0x00980000 | 0x900)+28)), "V4L2_CID_BACKLIGHT_COMPENSATION" },
 { (unsigned)(((0x00980000 | 0x900)+29)), "V4L2_CID_CHROMA_AGC" },
 { (unsigned)(((0x00980000 | 0x900)+30)), "V4L2_CID_COLOR_KILLER" },
 { (unsigned)(((0x00980000 | 0x900)+31)), "V4L2_CID_COLORFX" },
 { (unsigned)(((0x00980000 | 0x900)+32)), "V4L2_CID_AUTOBRIGHTNESS" },
 { (unsigned)(((0x00980000 | 0x900)+33)), "V4L2_CID_BAND_STOP_FILTER" },
 { (unsigned)(((0x00980000 | 0x900)+34)), "V4L2_CID_ROTATE" },
 { (unsigned)(((0x00980000 | 0x900)+35)), "V4L2_CID_BG_COLOR" },
 { (unsigned)(((0x00980000 | 0x900)+36)), "V4L2_CID_CHROMA_GAIN" },
 { (unsigned)(((0x00980000 | 0x900)+37)), "V4L2_CID_ILLUMINATORS_1" },
 { (unsigned)(((0x00980000 | 0x900)+38)), "V4L2_CID_ILLUMINATORS_2" },
 { (unsigned)(((0x00980000 | 0x900)+39)), "V4L2_CID_MIN_BUFFERS_FOR_CAPTURE" },
 { (unsigned)(((0x00980000 | 0x900)+40)), "V4L2_CID_MIN_BUFFERS_FOR_OUTPUT" },
 { (unsigned)(((0x00980000 | 0x900)+41)), "V4L2_CID_ALPHA_COMPONENT" },
 { (unsigned)(((0x00980000 | 0x900)+42)), "V4L2_CID_COLORFX_CBCR" },
 { (unsigned)(((0x00990000 | 0x900)+0)), "V4L2_CID_MPEG_STREAM_TYPE" },
 { (unsigned)(((0x00990000 | 0x900)+1)), "V4L2_CID_MPEG_STREAM_PID_PMT" },
 { (unsigned)(((0x00990000 | 0x900)+2)), "V4L2_CID_MPEG_STREAM_PID_AUDIO" },
 { (unsigned)(((0x00990000 | 0x900)+3)), "V4L2_CID_MPEG_STREAM_PID_VIDEO" },
 { (unsigned)(((0x00990000 | 0x900)+4)), "V4L2_CID_MPEG_STREAM_PID_PCR" },
 { (unsigned)(((0x00990000 | 0x900)+5)), "V4L2_CID_MPEG_STREAM_PES_ID_AUDIO" },
 { (unsigned)(((0x00990000 | 0x900)+6)), "V4L2_CID_MPEG_STREAM_PES_ID_VIDEO" },
 { (unsigned)(((0x00990000 | 0x900)+7)), "V4L2_CID_MPEG_STREAM_VBI_FMT" },
 { (unsigned)(((0x00990000 | 0x900)+100)), "V4L2_CID_MPEG_AUDIO_SAMPLING_FREQ" },
 { (unsigned)(((0x00990000 | 0x900)+101)), "V4L2_CID_MPEG_AUDIO_ENCODING" },
 { (unsigned)(((0x00990000 | 0x900)+102)), "V4L2_CID_MPEG_AUDIO_L1_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+103)), "V4L2_CID_MPEG_AUDIO_L2_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+104)), "V4L2_CID_MPEG_AUDIO_L3_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+105)), "V4L2_CID_MPEG_AUDIO_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+106)), "V4L2_CID_MPEG_AUDIO_MODE_EXTENSION" },
 { (unsigned)(((0x00990000 | 0x900)+107)), "V4L2_CID_MPEG_AUDIO_EMPHASIS" },
 { (unsigned)(((0x00990000 | 0x900)+108)), "V4L2_CID_MPEG_AUDIO_CRC" },
 { (unsigned)(((0x00990000 | 0x900)+109)), "V4L2_CID_MPEG_AUDIO_MUTE" },
 { (unsigned)(((0x00990000 | 0x900)+110)), "V4L2_CID_MPEG_AUDIO_AAC_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+111)), "V4L2_CID_MPEG_AUDIO_AC3_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+112)), "V4L2_CID_MPEG_AUDIO_DEC_PLAYBACK" },
 { (unsigned)(((0x00990000 | 0x900)+113)), "V4L2_CID_MPEG_AUDIO_DEC_MULTILINGUAL_PLAYBACK" },
 { (unsigned)(((0x00990000 | 0x900)+200)), "V4L2_CID_MPEG_VIDEO_ENCODING" },
 { (unsigned)(((0x00990000 | 0x900)+201)), "V4L2_CID_MPEG_VIDEO_ASPECT" },
 { (unsigned)(((0x00990000 | 0x900)+202)), "V4L2_CID_MPEG_VIDEO_B_FRAMES" },
 { (unsigned)(((0x00990000 | 0x900)+203)), "V4L2_CID_MPEG_VIDEO_GOP_SIZE" },
 { (unsigned)(((0x00990000 | 0x900)+204)), "V4L2_CID_MPEG_VIDEO_GOP_CLOSURE" },
 { (unsigned)(((0x00990000 | 0x900)+205)), "V4L2_CID_MPEG_VIDEO_PULLDOWN" },
 { (unsigned)(((0x00990000 | 0x900)+206)), "V4L2_CID_MPEG_VIDEO_BITRATE_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+207)), "V4L2_CID_MPEG_VIDEO_BITRATE" },
 { (unsigned)(((0x00990000 | 0x900)+208)), "V4L2_CID_MPEG_VIDEO_BITRATE_PEAK" },
 { (unsigned)(((0x00990000 | 0x900)+209)), "V4L2_CID_MPEG_VIDEO_TEMPORAL_DECIMATION" },
 { (unsigned)(((0x00990000 | 0x900)+210)), "V4L2_CID_MPEG_VIDEO_MUTE" },
 { (unsigned)(((0x00990000 | 0x900)+211)), "V4L2_CID_MPEG_VIDEO_MUTE_YUV" },
 { (unsigned)(((0x00990000 | 0x900)+212)), "V4L2_CID_MPEG_VIDEO_DECODER_SLICE_INTERFACE" },
 { (unsigned)(((0x00990000 | 0x900)+213)), "V4L2_CID_MPEG_VIDEO_DECODER_MPEG4_DEBLOCK_FILTER" },
 { (unsigned)(((0x00990000 | 0x900)+214)), "V4L2_CID_MPEG_VIDEO_CYCLIC_INTRA_REFRESH_MB" },
 { (unsigned)(((0x00990000 | 0x900)+215)), "V4L2_CID_MPEG_VIDEO_FRAME_RC_ENABLE" },
 { (unsigned)(((0x00990000 | 0x900)+216)), "V4L2_CID_MPEG_VIDEO_HEADER_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+217)), "V4L2_CID_MPEG_VIDEO_MAX_REF_PIC" },
 { (unsigned)(((0x00990000 | 0x900)+218)), "V4L2_CID_MPEG_VIDEO_MB_RC_ENABLE" },
 { (unsigned)(((0x00990000 | 0x900)+219)), "V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_BYTES" },
 { (unsigned)(((0x00990000 | 0x900)+220)), "V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_MB" },
 { (unsigned)(((0x00990000 | 0x900)+221)), "V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+222)), "V4L2_CID_MPEG_VIDEO_VBV_SIZE" },
 { (unsigned)(((0x00990000 | 0x900)+223)), "V4L2_CID_MPEG_VIDEO_DEC_PTS" },
 { (unsigned)(((0x00990000 | 0x900)+224)), "V4L2_CID_MPEG_VIDEO_DEC_FRAME" },
 { (unsigned)(((0x00990000 | 0x900)+225)), "V4L2_CID_MPEG_VIDEO_VBV_DELAY" },
 { (unsigned)(((0x00990000 | 0x900)+226)), "V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER" },
 { (unsigned)(((0x00990000 | 0x900)+227)), "V4L2_CID_MPEG_VIDEO_MV_H_SEARCH_RANGE" },
 { (unsigned)(((0x00990000 | 0x900)+228)), "V4L2_CID_MPEG_VIDEO_MV_V_SEARCH_RANGE" },
 { (unsigned)(((0x00990000 | 0x900)+229)), "V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME" },
 { (unsigned)(((0x00990000 | 0x900)+230)), "V4L2_CID_MPEG_VIDEO_BASELAYER_PRIORITY_ID" },
 { (unsigned)(((0x00990000 | 0x900)+231)), "V4L2_CID_MPEG_VIDEO_AU_DELIMITER" },
 { (unsigned)(((0x00990000 | 0x900)+232)), "V4L2_CID_MPEG_VIDEO_LTR_COUNT" },
 { (unsigned)(((0x00990000 | 0x900)+233)), "V4L2_CID_MPEG_VIDEO_FRAME_LTR_INDEX" },
 { (unsigned)(((0x00990000 | 0x900)+234)), "V4L2_CID_MPEG_VIDEO_USE_LTR_FRAMES" },
 { (unsigned)(((0x00990000 | 0x900)+235)), "V4L2_CID_MPEG_VIDEO_DEC_CONCEAL_COLOR" },
 { (unsigned)(((0x00990000 | 0x900)+236)), "V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD" },
 { (unsigned)(((0x00990000 | 0x900)+237)), "V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE" },
 { (unsigned)(((0x00990000 | 0x900) + 250)), "V4L2_CID_MPEG_VIDEO_MPEG2_SLICE_PARAMS" },
 { (unsigned)(((0x00990000 | 0x900) + 251)), "V4L2_CID_MPEG_VIDEO_MPEG2_QUANTIZATION" },
 { (unsigned)(((0x00990000 | 0x900) + 290)), "V4L2_CID_FWHT_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 291)), "V4L2_CID_FWHT_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+300)), "V4L2_CID_MPEG_VIDEO_H263_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+301)), "V4L2_CID_MPEG_VIDEO_H263_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+302)), "V4L2_CID_MPEG_VIDEO_H263_B_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+303)), "V4L2_CID_MPEG_VIDEO_H263_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+304)), "V4L2_CID_MPEG_VIDEO_H263_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+350)), "V4L2_CID_MPEG_VIDEO_H264_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+351)), "V4L2_CID_MPEG_VIDEO_H264_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+352)), "V4L2_CID_MPEG_VIDEO_H264_B_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+353)), "V4L2_CID_MPEG_VIDEO_H264_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+354)), "V4L2_CID_MPEG_VIDEO_H264_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+355)), "V4L2_CID_MPEG_VIDEO_H264_8X8_TRANSFORM" },
 { (unsigned)(((0x00990000 | 0x900)+356)), "V4L2_CID_MPEG_VIDEO_H264_CPB_SIZE" },
 { (unsigned)(((0x00990000 | 0x900)+357)), "V4L2_CID_MPEG_VIDEO_H264_ENTROPY_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+358)), "V4L2_CID_MPEG_VIDEO_H264_I_PERIOD" },
 { (unsigned)(((0x00990000 | 0x900)+359)), "V4L2_CID_MPEG_VIDEO_H264_LEVEL" },
 { (unsigned)(((0x00990000 | 0x900)+360)), "V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_ALPHA" },
 { (unsigned)(((0x00990000 | 0x900)+361)), "V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_BETA" },
 { (unsigned)(((0x00990000 | 0x900)+362)), "V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_MODE" },
 { (unsigned)(((0x00990000 | 0x900)+363)), "V4L2_CID_MPEG_VIDEO_H264_PROFILE" },
 { (unsigned)(((0x00990000 | 0x900)+364)), "V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_HEIGHT" },
 { (unsigned)(((0x00990000 | 0x900)+365)), "V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_WIDTH" },
 { (unsigned)(((0x00990000 | 0x900)+366)), "V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_ENABLE" },
 { (unsigned)(((0x00990000 | 0x900)+367)), "V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_IDC" },
 { (unsigned)(((0x00990000 | 0x900)+368)), "V4L2_CID_MPEG_VIDEO_H264_SEI_FRAME_PACKING" },
 { (unsigned)(((0x00990000 | 0x900)+369)), "V4L2_CID_MPEG_VIDEO_H264_SEI_FP_CURRENT_FRAME_0" },
 { (unsigned)(((0x00990000 | 0x900)+370)), "V4L2_CID_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE" },
 { (unsigned)(((0x00990000 | 0x900)+371)), "V4L2_CID_MPEG_VIDEO_H264_FMO" },
 { (unsigned)(((0x00990000 | 0x900)+372)), "V4L2_CID_MPEG_VIDEO_H264_FMO_MAP_TYPE" },
 { (unsigned)(((0x00990000 | 0x900)+373)), "V4L2_CID_MPEG_VIDEO_H264_FMO_SLICE_GROUP" },
 { (unsigned)(((0x00990000 | 0x900)+374)), "V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_DIRECTION" },
 { (unsigned)(((0x00990000 | 0x900)+375)), "V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_RATE" },
 { (unsigned)(((0x00990000 | 0x900)+376)), "V4L2_CID_MPEG_VIDEO_H264_FMO_RUN_LENGTH" },
 { (unsigned)(((0x00990000 | 0x900)+377)), "V4L2_CID_MPEG_VIDEO_H264_ASO" },
 { (unsigned)(((0x00990000 | 0x900)+378)), "V4L2_CID_MPEG_VIDEO_H264_ASO_SLICE_ORDER" },
 { (unsigned)(((0x00990000 | 0x900)+379)), "V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING" },
 { (unsigned)(((0x00990000 | 0x900)+380)), "V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_TYPE" },
 { (unsigned)(((0x00990000 | 0x900)+381)), "V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER" },
 { (unsigned)(((0x00990000 | 0x900)+382)), "V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER_QP" },
 { (unsigned)(((0x00990000 | 0x900)+383)), "V4L2_CID_MPEG_VIDEO_H264_CONSTRAINED_INTRA_PREDICTION" },
 { (unsigned)(((0x00990000 | 0x900)+384)), "V4L2_CID_MPEG_VIDEO_H264_CHROMA_QP_INDEX_OFFSET" },
 { (unsigned)(((0x00990000 | 0x900)+385)), "V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+386)), "V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+387)), "V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+388)), "V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+389)), "V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+390)), "V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+391)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L0_BR" },
 { (unsigned)(((0x00990000 | 0x900)+392)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L1_BR" },
 { (unsigned)(((0x00990000 | 0x900)+393)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L2_BR" },
 { (unsigned)(((0x00990000 | 0x900)+394)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L3_BR" },
 { (unsigned)(((0x00990000 | 0x900)+395)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L4_BR" },
 { (unsigned)(((0x00990000 | 0x900)+396)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L5_BR" },
 { (unsigned)(((0x00990000 | 0x900)+397)), "V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L6_BR" },
 { (unsigned)(((0x00990000 | 0x900)+400)), "V4L2_CID_MPEG_VIDEO_MPEG4_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+401)), "V4L2_CID_MPEG_VIDEO_MPEG4_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+402)), "V4L2_CID_MPEG_VIDEO_MPEG4_B_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+403)), "V4L2_CID_MPEG_VIDEO_MPEG4_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+404)), "V4L2_CID_MPEG_VIDEO_MPEG4_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+405)), "V4L2_CID_MPEG_VIDEO_MPEG4_LEVEL" },
 { (unsigned)(((0x00990000 | 0x900)+406)), "V4L2_CID_MPEG_VIDEO_MPEG4_PROFILE" },
 { (unsigned)(((0x00990000 | 0x900)+407)), "V4L2_CID_MPEG_VIDEO_MPEG4_QPEL" },
 { (unsigned)(((0x00990000 | 0x900)+500)), "V4L2_CID_MPEG_VIDEO_VPX_NUM_PARTITIONS" },
 { (unsigned)(((0x00990000 | 0x900)+501)), "V4L2_CID_MPEG_VIDEO_VPX_IMD_DISABLE_4X4" },
 { (unsigned)(((0x00990000 | 0x900)+502)), "V4L2_CID_MPEG_VIDEO_VPX_NUM_REF_FRAMES" },
 { (unsigned)(((0x00990000 | 0x900)+503)), "V4L2_CID_MPEG_VIDEO_VPX_FILTER_LEVEL" },
 { (unsigned)(((0x00990000 | 0x900)+504)), "V4L2_CID_MPEG_VIDEO_VPX_FILTER_SHARPNESS" },
 { (unsigned)(((0x00990000 | 0x900)+505)), "V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_REF_PERIOD" },
 { (unsigned)(((0x00990000 | 0x900)+506)), "V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_SEL" },
 { (unsigned)(((0x00990000 | 0x900)+507)), "V4L2_CID_MPEG_VIDEO_VPX_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900)+508)), "V4L2_CID_MPEG_VIDEO_VPX_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900)+509)), "V4L2_CID_MPEG_VIDEO_VPX_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+510)), "V4L2_CID_MPEG_VIDEO_VPX_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900)+511)), "V4L2_CID_MPEG_VIDEO_VP8_PROFILE" },
 { (unsigned)(((0x00990000 | 0x900)+512)), "V4L2_CID_MPEG_VIDEO_VP9_PROFILE" },
 { (unsigned)(((0x00990000 | 0x900) + 600)), "V4L2_CID_MPEG_VIDEO_HEVC_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 601)), "V4L2_CID_MPEG_VIDEO_HEVC_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 602)), "V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 603)), "V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 604)), "V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 605)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 606)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_TYPE" },
 { (unsigned)(((0x00990000 | 0x900) + 607)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_LAYER" },
 { (unsigned)(((0x00990000 | 0x900) + 608)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 609)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 610)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 611)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 612)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 613)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 614)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 615)), "V4L2_CID_MPEG_VIDEO_HEVC_PROFILE" },
 { (unsigned)(((0x00990000 | 0x900) + 616)), "V4L2_CID_MPEG_VIDEO_HEVC_LEVEL" },
 { (unsigned)(((0x00990000 | 0x900) + 617)), "V4L2_CID_MPEG_VIDEO_HEVC_FRAME_RATE_RESOLUTION" },
 { (unsigned)(((0x00990000 | 0x900) + 618)), "V4L2_CID_MPEG_VIDEO_HEVC_TIER" },
 { (unsigned)(((0x00990000 | 0x900) + 619)), "V4L2_CID_MPEG_VIDEO_HEVC_MAX_PARTITION_DEPTH" },
 { (unsigned)(((0x00990000 | 0x900) + 620)), "V4L2_CID_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE" },
 { (unsigned)(((0x00990000 | 0x900) + 621)), "V4L2_CID_MPEG_VIDEO_HEVC_LF_BETA_OFFSET_DIV2" },
 { (unsigned)(((0x00990000 | 0x900) + 622)), "V4L2_CID_MPEG_VIDEO_HEVC_LF_TC_OFFSET_DIV2" },
 { (unsigned)(((0x00990000 | 0x900) + 623)), "V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_TYPE" },
 { (unsigned)(((0x00990000 | 0x900) + 624)), "V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_PERIOD" },
 { (unsigned)(((0x00990000 | 0x900) + 625)), "V4L2_CID_MPEG_VIDEO_HEVC_LOSSLESS_CU" },
 { (unsigned)(((0x00990000 | 0x900) + 626)), "V4L2_CID_MPEG_VIDEO_HEVC_CONST_INTRA_PRED" },
 { (unsigned)(((0x00990000 | 0x900) + 627)), "V4L2_CID_MPEG_VIDEO_HEVC_WAVEFRONT" },
 { (unsigned)(((0x00990000 | 0x900) + 628)), "V4L2_CID_MPEG_VIDEO_HEVC_GENERAL_PB" },
 { (unsigned)(((0x00990000 | 0x900) + 629)), "V4L2_CID_MPEG_VIDEO_HEVC_TEMPORAL_ID" },
 { (unsigned)(((0x00990000 | 0x900) + 630)), "V4L2_CID_MPEG_VIDEO_HEVC_STRONG_SMOOTHING" },
 { (unsigned)(((0x00990000 | 0x900) + 631)), "V4L2_CID_MPEG_VIDEO_HEVC_MAX_NUM_MERGE_MV_MINUS1" },
 { (unsigned)(((0x00990000 | 0x900) + 632)), "V4L2_CID_MPEG_VIDEO_HEVC_INTRA_PU_SPLIT" },
 { (unsigned)(((0x00990000 | 0x900) + 633)), "V4L2_CID_MPEG_VIDEO_HEVC_TMV_PREDICTION" },
 { (unsigned)(((0x00990000 | 0x900) + 634)), "V4L2_CID_MPEG_VIDEO_HEVC_WITHOUT_STARTCODE" },
 { (unsigned)(((0x00990000 | 0x900) + 635)), "V4L2_CID_MPEG_VIDEO_HEVC_SIZE_OF_LENGTH_FIELD" },
 { (unsigned)(((0x00990000 | 0x900) + 636)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 637)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 638)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 639)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 640)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 641)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 642)), "V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_BR" },
 { (unsigned)(((0x00990000 | 0x900) + 643)), "V4L2_CID_MPEG_VIDEO_REF_NUMBER_FOR_PFRAMES" },
 { (unsigned)(((0x00990000 | 0x900) + 644)), "V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR" },
 { (unsigned)(((0x00990000 | 0x900) + 645)), "V4L2_CID_MPEG_VIDEO_CONSTANT_QUALITY" },
 { (unsigned)(((0x00990000 | 0x900) + 646)), "V4L2_CID_MPEG_VIDEO_FRAME_SKIP_MODE" },
 { (unsigned)(((0x00990000 | 0x900) + 647)), "V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 648)), "V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 649)), "V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 650)), "V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 651)), "V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MIN_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 652)), "V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MAX_QP" },
 { (unsigned)(((0x00990000 | 0x900) + 653)), "V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY" },
 { (unsigned)(((0x00990000 | 0x900) + 654)), "V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY_ENABLE" },
 { (unsigned)(((0x00990000 | 0x1000)+0)), "V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE" },
 { (unsigned)(((0x00990000 | 0x1000)+1)), "V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER" },
 { (unsigned)(((0x00990000 | 0x1000)+2)), "V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE" },
 { (unsigned)(((0x00990000 | 0x1000)+3)), "V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE" },
 { (unsigned)(((0x00990000 | 0x1000)+4)), "V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE" },
 { (unsigned)(((0x00990000 | 0x1000)+5)), "V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER" },
 { (unsigned)(((0x00990000 | 0x1000)+6)), "V4L2_CID_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE" },
 { (unsigned)(((0x00990000 | 0x1000)+7)), "V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_BOTTOM" },
 { (unsigned)(((0x00990000 | 0x1000)+8)), "V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_TOP" },
 { (unsigned)(((0x00990000 | 0x1000)+9)), "V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_BOTTOM" },
 { (unsigned)(((0x00990000 | 0x1000)+10)), "V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_TOP" },
 { (unsigned)(((0x00990000 | 0x1000)+11)), "V4L2_CID_MPEG_CX2341X_STREAM_INSERT_NAV_PACKETS" },
 { (unsigned)(((0x00990000 | 0x1100)+0)), "V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY" },
 { (unsigned)(((0x00990000 | 0x1100)+1)), "V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY_ENABLE" },
 { (unsigned)(((0x00990000 | 0x1100)+2)), "V4L2_CID_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE" },
 { (unsigned)(((0x00990000 | 0x1100)+3)), "V4L2_CID_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE" },
 { (unsigned)(((0x00990000 | 0x1100)+4)), "V4L2_CID_MPEG_MFC51_VIDEO_PADDING" },
 { (unsigned)(((0x00990000 | 0x1100)+5)), "V4L2_CID_MPEG_MFC51_VIDEO_PADDING_YUV" },
 { (unsigned)(((0x00990000 | 0x1100)+6)), "V4L2_CID_MPEG_MFC51_VIDEO_RC_FIXED_TARGET_BIT" },
 { (unsigned)(((0x00990000 | 0x1100)+7)), "V4L2_CID_MPEG_MFC51_VIDEO_RC_REACTION_COEFF" },
 { (unsigned)(((0x00990000 | 0x1100)+50)), "V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_ACTIVITY" },
 { (unsigned)(((0x00990000 | 0x1100)+51)), "V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_DARK" },
 { (unsigned)(((0x00990000 | 0x1100)+52)), "V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_SMOOTH" },
 { (unsigned)(((0x00990000 | 0x1100)+53)), "V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_STATIC" },
 { (unsigned)(((0x00990000 | 0x1100)+54)), "V4L2_CID_MPEG_MFC51_VIDEO_H264_NUM_REF_PIC_FOR_P" },
 { (unsigned)(((0x009a0000 | 0x900)+1)), "V4L2_CID_EXPOSURE_AUTO" },
 { (unsigned)(((0x009a0000 | 0x900)+2)), "V4L2_CID_EXPOSURE_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+3)), "V4L2_CID_EXPOSURE_AUTO_PRIORITY" },
 { (unsigned)(((0x009a0000 | 0x900)+4)), "V4L2_CID_PAN_RELATIVE" },
 { (unsigned)(((0x009a0000 | 0x900)+5)), "V4L2_CID_TILT_RELATIVE" },
 { (unsigned)(((0x009a0000 | 0x900)+6)), "V4L2_CID_PAN_RESET" },
 { (unsigned)(((0x009a0000 | 0x900)+7)), "V4L2_CID_TILT_RESET" },
 { (unsigned)(((0x009a0000 | 0x900)+8)), "V4L2_CID_PAN_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+9)), "V4L2_CID_TILT_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+10)), "V4L2_CID_FOCUS_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+11)), "V4L2_CID_FOCUS_RELATIVE" },
 { (unsigned)(((0x009a0000 | 0x900)+12)), "V4L2_CID_FOCUS_AUTO" },
 { (unsigned)(((0x009a0000 | 0x900)+13)), "V4L2_CID_ZOOM_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+14)), "V4L2_CID_ZOOM_RELATIVE" },
 { (unsigned)(((0x009a0000 | 0x900)+15)), "V4L2_CID_ZOOM_CONTINUOUS" },
 { (unsigned)(((0x009a0000 | 0x900)+16)), "V4L2_CID_PRIVACY" },
 { (unsigned)(((0x009a0000 | 0x900)+17)), "V4L2_CID_IRIS_ABSOLUTE" },
 { (unsigned)(((0x009a0000 | 0x900)+18)), "V4L2_CID_IRIS_RELATIVE" },
 { (unsigned)(((0x009a0000 | 0x900)+19)), "V4L2_CID_AUTO_EXPOSURE_BIAS" },
 { (unsigned)(((0x009a0000 | 0x900)+20)), "V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE" },
 { (unsigned)(((0x009a0000 | 0x900)+21)), "V4L2_CID_WIDE_DYNAMIC_RANGE" },
 { (unsigned)(((0x009a0000 | 0x900)+22)), "V4L2_CID_IMAGE_STABILIZATION" },
 { (unsigned)(((0x009a0000 | 0x900)+23)), "V4L2_CID_ISO_SENSITIVITY" },
 { (unsigned)(((0x009a0000 | 0x900)+24)), "V4L2_CID_ISO_SENSITIVITY_AUTO" },
 { (unsigned)(((0x009a0000 | 0x900)+25)), "V4L2_CID_EXPOSURE_METERING" },
 { (unsigned)(((0x009a0000 | 0x900)+26)), "V4L2_CID_SCENE_MODE" },
 { (unsigned)(((0x009a0000 | 0x900)+27)), "V4L2_CID_3A_LOCK" },
 { (unsigned)(((0x009a0000 | 0x900)+28)), "V4L2_CID_AUTO_FOCUS_START" },
 { (unsigned)(((0x009a0000 | 0x900)+29)), "V4L2_CID_AUTO_FOCUS_STOP" },
 { (unsigned)(((0x009a0000 | 0x900)+30)), "V4L2_CID_AUTO_FOCUS_STATUS" },
 { (unsigned)(((0x009a0000 | 0x900)+31)), "V4L2_CID_AUTO_FOCUS_RANGE" },
 { (unsigned)(((0x009a0000 | 0x900)+32)), "V4L2_CID_PAN_SPEED" },
 { (unsigned)(((0x009a0000 | 0x900)+33)), "V4L2_CID_TILT_SPEED" },
 { (unsigned)(((0x009b0000 | 0x900) + 1)), "V4L2_CID_RDS_TX_DEVIATION" },
 { (unsigned)(((0x009b0000 | 0x900) + 2)), "V4L2_CID_RDS_TX_PI" },
 { (unsigned)(((0x009b0000 | 0x900) + 3)), "V4L2_CID_RDS_TX_PTY" },
 { (unsigned)(((0x009b0000 | 0x900) + 5)), "V4L2_CID_RDS_TX_PS_NAME" },
 { (unsigned)(((0x009b0000 | 0x900) + 6)), "V4L2_CID_RDS_TX_RADIO_TEXT" },
 { (unsigned)(((0x009b0000 | 0x900) + 7)), "V4L2_CID_RDS_TX_MONO_STEREO" },
 { (unsigned)(((0x009b0000 | 0x900) + 8)), "V4L2_CID_RDS_TX_ARTIFICIAL_HEAD" },
 { (unsigned)(((0x009b0000 | 0x900) + 9)), "V4L2_CID_RDS_TX_COMPRESSED" },
 { (unsigned)(((0x009b0000 | 0x900) + 10)), "V4L2_CID_RDS_TX_DYNAMIC_PTY" },
 { (unsigned)(((0x009b0000 | 0x900) + 11)), "V4L2_CID_RDS_TX_TRAFFIC_ANNOUNCEMENT" },
 { (unsigned)(((0x009b0000 | 0x900) + 12)), "V4L2_CID_RDS_TX_TRAFFIC_PROGRAM" },
 { (unsigned)(((0x009b0000 | 0x900) + 13)), "V4L2_CID_RDS_TX_MUSIC_SPEECH" },
 { (unsigned)(((0x009b0000 | 0x900) + 14)), "V4L2_CID_RDS_TX_ALT_FREQS_ENABLE" },
 { (unsigned)(((0x009b0000 | 0x900) + 15)), "V4L2_CID_RDS_TX_ALT_FREQS" },
 { (unsigned)(((0x009b0000 | 0x900) + 64)), "V4L2_CID_AUDIO_LIMITER_ENABLED" },
 { (unsigned)(((0x009b0000 | 0x900) + 65)), "V4L2_CID_AUDIO_LIMITER_RELEASE_TIME" },
 { (unsigned)(((0x009b0000 | 0x900) + 66)), "V4L2_CID_AUDIO_LIMITER_DEVIATION" },
 { (unsigned)(((0x009b0000 | 0x900) + 80)), "V4L2_CID_AUDIO_COMPRESSION_ENABLED" },
 { (unsigned)(((0x009b0000 | 0x900) + 81)), "V4L2_CID_AUDIO_COMPRESSION_GAIN" },
 { (unsigned)(((0x009b0000 | 0x900) + 82)), "V4L2_CID_AUDIO_COMPRESSION_THRESHOLD" },
 { (unsigned)(((0x009b0000 | 0x900) + 83)), "V4L2_CID_AUDIO_COMPRESSION_ATTACK_TIME" },
 { (unsigned)(((0x009b0000 | 0x900) + 84)), "V4L2_CID_AUDIO_COMPRESSION_RELEASE_TIME" },
 { (unsigned)(((0x009b0000 | 0x900) + 96)), "V4L2_CID_PILOT_TONE_ENABLED" },
 { (unsigned)(((0x009b0000 | 0x900) + 97)), "V4L2_CID_PILOT_TONE_DEVIATION" },
 { (unsigned)(((0x009b0000 | 0x900) + 98)), "V4L2_CID_PILOT_TONE_FREQUENCY" },
 { (unsigned)(((0x009b0000 | 0x900) + 112)), "V4L2_CID_TUNE_PREEMPHASIS" },
 { (unsigned)(((0x009b0000 | 0x900) + 113)), "V4L2_CID_TUNE_POWER_LEVEL" },
 { (unsigned)(((0x009b0000 | 0x900) + 114)), "V4L2_CID_TUNE_ANTENNA_CAPACITOR" },
 { (unsigned)(((0x009c0000 | 0x900) + 1)), "V4L2_CID_FLASH_LED_MODE" },
 { (unsigned)(((0x009c0000 | 0x900) + 2)), "V4L2_CID_FLASH_STROBE_SOURCE" },
 { (unsigned)(((0x009c0000 | 0x900) + 3)), "V4L2_CID_FLASH_STROBE" },
 { (unsigned)(((0x009c0000 | 0x900) + 4)), "V4L2_CID_FLASH_STROBE_STOP" },
 { (unsigned)(((0x009c0000 | 0x900) + 5)), "V4L2_CID_FLASH_STROBE_STATUS" },
 { (unsigned)(((0x009c0000 | 0x900) + 6)), "V4L2_CID_FLASH_TIMEOUT" },
 { (unsigned)(((0x009c0000 | 0x900) + 7)), "V4L2_CID_FLASH_INTENSITY" },
 { (unsigned)(((0x009c0000 | 0x900) + 8)), "V4L2_CID_FLASH_TORCH_INTENSITY" },
 { (unsigned)(((0x009c0000 | 0x900) + 9)), "V4L2_CID_FLASH_INDICATOR_INTENSITY" },
 { (unsigned)(((0x009c0000 | 0x900) + 10)), "V4L2_CID_FLASH_FAULT" },
 { (unsigned)(((0x009c0000 | 0x900) + 11)), "V4L2_CID_FLASH_CHARGE" },
 { (unsigned)(((0x009c0000 | 0x900) + 12)), "V4L2_CID_FLASH_READY" },
 { (unsigned)(((0x009e0000 | 0x900) + 1)), "V4L2_CID_VBLANK" },
 { (unsigned)(((0x009e0000 | 0x900) + 2)), "V4L2_CID_HBLANK" },
 { (unsigned)(((0x009e0000 | 0x900) + 3)), "V4L2_CID_ANALOGUE_GAIN" },
 { (unsigned)(((0x009e0000 | 0x900) + 4)), "V4L2_CID_TEST_PATTERN_RED" },
 { (unsigned)(((0x009e0000 | 0x900) + 5)), "V4L2_CID_TEST_PATTERN_GREENR" },
 { (unsigned)(((0x009e0000 | 0x900) + 6)), "V4L2_CID_TEST_PATTERN_BLUE" },
 { (unsigned)(((0x009e0000 | 0x900) + 7)), "V4L2_CID_TEST_PATTERN_GREENB" },
 { (unsigned)(((0x009e0000 | 0x900) + 8)), "V4L2_CID_UNIT_CELL_SIZE" },
 { (unsigned)(((0x009e0000 | 0x900) + 9)), "V4L2_CID_NOTIFY_GAINS" },
 { (unsigned)(((0x009f0000 | 0x900) + 1)), "V4L2_CID_LINK_FREQ" },
 { (unsigned)(((0x009f0000 | 0x900) + 2)), "V4L2_CID_PIXEL_RATE" },
 { (unsigned)(((0x009f0000 | 0x900) + 3)), "V4L2_CID_TEST_PATTERN" },
 { (unsigned)(((0x009f0000 | 0x900) + 4)), "V4L2_CID_DEINTERLACING_MODE" },
 { (unsigned)(((0x009f0000 | 0x900) + 5)), "V4L2_CID_DIGITAL_GAIN" },
 { (unsigned)(((0x00a00000 | 0x900) + 5)), "V4L2_CID_DV_TX_RGB_RANGE" },
 { (unsigned)(((0x00a00000 | 0x900) + 6)), "V4L2_CID_DV_TX_IT_CONTENT_TYPE" },
 { (unsigned)(((0x00a00000 | 0x900) + 101)), "V4L2_CID_DV_RX_RGB_RANGE" },
 { (unsigned)(((0x00a00000 | 0x900) + 102)), "V4L2_CID_DV_RX_IT_CONTENT_TYPE" },
 { (unsigned)(((0x00a10000 | 0x900) + 1)), "V4L2_CID_TUNE_DEEMPHASIS" },
 { (unsigned)(((0x00a10000 | 0x900) + 2)), "V4L2_CID_RDS_RECEPTION" },
 { (unsigned)(((0x00a10000 | 0x900) + 3)), "V4L2_CID_RDS_RX_PTY" },
 { (unsigned)(((0x00a10000 | 0x900) + 4)), "V4L2_CID_RDS_RX_PS_NAME" },
 { (unsigned)(((0x00a10000 | 0x900) + 5)), "V4L2_CID_RDS_RX_RADIO_TEXT" },
 { (unsigned)(((0x00a10000 | 0x900) + 6)), "V4L2_CID_RDS_RX_TRAFFIC_ANNOUNCEMENT" },
 { (unsigned)(((0x00a10000 | 0x900) + 7)), "V4L2_CID_RDS_RX_TRAFFIC_PROGRAM" },
 { (unsigned)(((0x00a10000 | 0x900) + 8)), "V4L2_CID_RDS_RX_MUSIC_SPEECH" },
 { (unsigned)(((0x00a20000 | 0x900) + 11)), "V4L2_CID_RF_TUNER_BANDWIDTH_AUTO" },
 { (unsigned)(((0x00a20000 | 0x900) + 12)), "V4L2_CID_RF_TUNER_BANDWIDTH" },
 { (unsigned)(((0x00a20000 | 0x900) + 32)), "V4L2_CID_RF_TUNER_RF_GAIN" },
 { (unsigned)(((0x00a20000 | 0x900) + 41)), "V4L2_CID_RF_TUNER_LNA_GAIN_AUTO" },
 { (unsigned)(((0x00a20000 | 0x900) + 42)), "V4L2_CID_RF_TUNER_LNA_GAIN" },
 { (unsigned)(((0x00a20000 | 0x900) + 51)), "V4L2_CID_RF_TUNER_MIXER_GAIN_AUTO" },
 { (unsigned)(((0x00a20000 | 0x900) + 52)), "V4L2_CID_RF_TUNER_MIXER_GAIN" },
 { (unsigned)(((0x00a20000 | 0x900) + 61)), "V4L2_CID_RF_TUNER_IF_GAIN_AUTO" },
 { (unsigned)(((0x00a20000 | 0x900) + 62)), "V4L2_CID_RF_TUNER_IF_GAIN" },
 { (unsigned)(((0x00a20000 | 0x900) + 91)), "V4L2_CID_RF_TUNER_PLL_LOCK" },
 { (unsigned)(((0x00a30000 | 0x900) + 1)), "V4L2_CID_DETECT_MD_MODE" },
 { (unsigned)(((0x00a30000 | 0x900) + 2)), "V4L2_CID_DETECT_MD_GLOBAL_THRESHOLD" },
 { (unsigned)(((0x00a30000 | 0x900) + 3)), "V4L2_CID_DETECT_MD_THRESHOLD_GRID" },
 { (unsigned)(((0x00a30000 | 0x900) + 4)), "V4L2_CID_DETECT_MD_REGION_GRID" },
};
const struct xlat v4l2_control_ids[1] = { {
 .data = v4l2_control_ids_xdata,
 .size = (sizeof(v4l2_control_ids_xdata) / sizeof((v4l2_control_ids_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_ids_xdata)), __typeof__(&(v4l2_control_ids_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (((0x00980000 | 0x900)+0)))
  | ((unsigned) (((0x00980000 | 0x900)+1)))
  | ((unsigned) (((0x00980000 | 0x900)+2)))
  | ((unsigned) (((0x00980000 | 0x900)+3)))
  | ((unsigned) (((0x00980000 | 0x900)+5)))
  | ((unsigned) (((0x00980000 | 0x900)+6)))
  | ((unsigned) (((0x00980000 | 0x900)+7)))
  | ((unsigned) (((0x00980000 | 0x900)+8)))
  | ((unsigned) (((0x00980000 | 0x900)+9)))
  | ((unsigned) (((0x00980000 | 0x900)+10)))
  | ((unsigned) (((0x00980000 | 0x900)+11)))
  | ((unsigned) (((0x00980000 | 0x900)+12)))
  | ((unsigned) (((0x00980000 | 0x900)+13)))
  | ((unsigned) (((0x00980000 | 0x900)+14)))
  | ((unsigned) (((0x00980000 | 0x900)+15)))
  | ((unsigned) (((0x00980000 | 0x900)+16)))
  | ((unsigned) (((0x00980000 | 0x900)+17)))
  | ((unsigned) (((0x00980000 | 0x900)+18)))
  | ((unsigned) (((0x00980000 | 0x900)+19)))
  | ((unsigned) (((0x00980000 | 0x900)+20)))
  | ((unsigned) (((0x00980000 | 0x900)+21)))
  | ((unsigned) (((0x00980000 | 0x900)+22)))
  | ((unsigned) (((0x00980000 | 0x900)+23)))
  | ((unsigned) (((0x00980000 | 0x900)+24)))
  | ((unsigned) (((0x00980000 | 0x900)+25)))
  | ((unsigned) (((0x00980000 | 0x900)+26)))
  | ((unsigned) (((0x00980000 | 0x900)+27)))
  | ((unsigned) (((0x00980000 | 0x900)+28)))
  | ((unsigned) (((0x00980000 | 0x900)+29)))
  | ((unsigned) (((0x00980000 | 0x900)+30)))
  | ((unsigned) (((0x00980000 | 0x900)+31)))
  | ((unsigned) (((0x00980000 | 0x900)+32)))
  | ((unsigned) (((0x00980000 | 0x900)+33)))
  | ((unsigned) (((0x00980000 | 0x900)+34)))
  | ((unsigned) (((0x00980000 | 0x900)+35)))
  | ((unsigned) (((0x00980000 | 0x900)+36)))
  | ((unsigned) (((0x00980000 | 0x900)+37)))
  | ((unsigned) (((0x00980000 | 0x900)+38)))
  | ((unsigned) (((0x00980000 | 0x900)+39)))
  | ((unsigned) (((0x00980000 | 0x900)+40)))
  | ((unsigned) (((0x00980000 | 0x900)+41)))
  | ((unsigned) (((0x00980000 | 0x900)+42)))
  | ((unsigned) (((0x00990000 | 0x900)+0)))
  | ((unsigned) (((0x00990000 | 0x900)+1)))
  | ((unsigned) (((0x00990000 | 0x900)+2)))
  | ((unsigned) (((0x00990000 | 0x900)+3)))
  | ((unsigned) (((0x00990000 | 0x900)+4)))
  | ((unsigned) (((0x00990000 | 0x900)+5)))
  | ((unsigned) (((0x00990000 | 0x900)+6)))
  | ((unsigned) (((0x00990000 | 0x900)+7)))
  | ((unsigned) (((0x00990000 | 0x900)+100)))
  | ((unsigned) (((0x00990000 | 0x900)+101)))
  | ((unsigned) (((0x00990000 | 0x900)+102)))
  | ((unsigned) (((0x00990000 | 0x900)+103)))
  | ((unsigned) (((0x00990000 | 0x900)+104)))
  | ((unsigned) (((0x00990000 | 0x900)+105)))
  | ((unsigned) (((0x00990000 | 0x900)+106)))
  | ((unsigned) (((0x00990000 | 0x900)+107)))
  | ((unsigned) (((0x00990000 | 0x900)+108)))
  | ((unsigned) (((0x00990000 | 0x900)+109)))
  | ((unsigned) (((0x00990000 | 0x900)+110)))
  | ((unsigned) (((0x00990000 | 0x900)+111)))
  | ((unsigned) (((0x00990000 | 0x900)+112)))
  | ((unsigned) (((0x00990000 | 0x900)+113)))
  | ((unsigned) (((0x00990000 | 0x900)+200)))
  | ((unsigned) (((0x00990000 | 0x900)+201)))
  | ((unsigned) (((0x00990000 | 0x900)+202)))
  | ((unsigned) (((0x00990000 | 0x900)+203)))
  | ((unsigned) (((0x00990000 | 0x900)+204)))
  | ((unsigned) (((0x00990000 | 0x900)+205)))
  | ((unsigned) (((0x00990000 | 0x900)+206)))
  | ((unsigned) (((0x00990000 | 0x900)+207)))
  | ((unsigned) (((0x00990000 | 0x900)+208)))
  | ((unsigned) (((0x00990000 | 0x900)+209)))
  | ((unsigned) (((0x00990000 | 0x900)+210)))
  | ((unsigned) (((0x00990000 | 0x900)+211)))
  | ((unsigned) (((0x00990000 | 0x900)+212)))
  | ((unsigned) (((0x00990000 | 0x900)+213)))
  | ((unsigned) (((0x00990000 | 0x900)+214)))
  | ((unsigned) (((0x00990000 | 0x900)+215)))
  | ((unsigned) (((0x00990000 | 0x900)+216)))
  | ((unsigned) (((0x00990000 | 0x900)+217)))
  | ((unsigned) (((0x00990000 | 0x900)+218)))
  | ((unsigned) (((0x00990000 | 0x900)+219)))
  | ((unsigned) (((0x00990000 | 0x900)+220)))
  | ((unsigned) (((0x00990000 | 0x900)+221)))
  | ((unsigned) (((0x00990000 | 0x900)+222)))
  | ((unsigned) (((0x00990000 | 0x900)+223)))
  | ((unsigned) (((0x00990000 | 0x900)+224)))
  | ((unsigned) (((0x00990000 | 0x900)+225)))
  | ((unsigned) (((0x00990000 | 0x900)+226)))
  | ((unsigned) (((0x00990000 | 0x900)+227)))
  | ((unsigned) (((0x00990000 | 0x900)+228)))
  | ((unsigned) (((0x00990000 | 0x900)+229)))
  | ((unsigned) (((0x00990000 | 0x900)+230)))
  | ((unsigned) (((0x00990000 | 0x900)+231)))
  | ((unsigned) (((0x00990000 | 0x900)+232)))
  | ((unsigned) (((0x00990000 | 0x900)+233)))
  | ((unsigned) (((0x00990000 | 0x900)+234)))
  | ((unsigned) (((0x00990000 | 0x900)+235)))
  | ((unsigned) (((0x00990000 | 0x900)+236)))
  | ((unsigned) (((0x00990000 | 0x900)+237)))
  | ((unsigned) (((0x00990000 | 0x900) + 250)))
  | ((unsigned) (((0x00990000 | 0x900) + 251)))
  | ((unsigned) (((0x00990000 | 0x900) + 290)))
  | ((unsigned) (((0x00990000 | 0x900) + 291)))
  | ((unsigned) (((0x00990000 | 0x900)+300)))
  | ((unsigned) (((0x00990000 | 0x900)+301)))
  | ((unsigned) (((0x00990000 | 0x900)+302)))
  | ((unsigned) (((0x00990000 | 0x900)+303)))
  | ((unsigned) (((0x00990000 | 0x900)+304)))
  | ((unsigned) (((0x00990000 | 0x900)+350)))
  | ((unsigned) (((0x00990000 | 0x900)+351)))
  | ((unsigned) (((0x00990000 | 0x900)+352)))
  | ((unsigned) (((0x00990000 | 0x900)+353)))
  | ((unsigned) (((0x00990000 | 0x900)+354)))
  | ((unsigned) (((0x00990000 | 0x900)+355)))
  | ((unsigned) (((0x00990000 | 0x900)+356)))
  | ((unsigned) (((0x00990000 | 0x900)+357)))
  | ((unsigned) (((0x00990000 | 0x900)+358)))
  | ((unsigned) (((0x00990000 | 0x900)+359)))
  | ((unsigned) (((0x00990000 | 0x900)+360)))
  | ((unsigned) (((0x00990000 | 0x900)+361)))
  | ((unsigned) (((0x00990000 | 0x900)+362)))
  | ((unsigned) (((0x00990000 | 0x900)+363)))
  | ((unsigned) (((0x00990000 | 0x900)+364)))
  | ((unsigned) (((0x00990000 | 0x900)+365)))
  | ((unsigned) (((0x00990000 | 0x900)+366)))
  | ((unsigned) (((0x00990000 | 0x900)+367)))
  | ((unsigned) (((0x00990000 | 0x900)+368)))
  | ((unsigned) (((0x00990000 | 0x900)+369)))
  | ((unsigned) (((0x00990000 | 0x900)+370)))
  | ((unsigned) (((0x00990000 | 0x900)+371)))
  | ((unsigned) (((0x00990000 | 0x900)+372)))
  | ((unsigned) (((0x00990000 | 0x900)+373)))
  | ((unsigned) (((0x00990000 | 0x900)+374)))
  | ((unsigned) (((0x00990000 | 0x900)+375)))
  | ((unsigned) (((0x00990000 | 0x900)+376)))
  | ((unsigned) (((0x00990000 | 0x900)+377)))
  | ((unsigned) (((0x00990000 | 0x900)+378)))
  | ((unsigned) (((0x00990000 | 0x900)+379)))
  | ((unsigned) (((0x00990000 | 0x900)+380)))
  | ((unsigned) (((0x00990000 | 0x900)+381)))
  | ((unsigned) (((0x00990000 | 0x900)+382)))
  | ((unsigned) (((0x00990000 | 0x900)+383)))
  | ((unsigned) (((0x00990000 | 0x900)+384)))
  | ((unsigned) (((0x00990000 | 0x900)+385)))
  | ((unsigned) (((0x00990000 | 0x900)+386)))
  | ((unsigned) (((0x00990000 | 0x900)+387)))
  | ((unsigned) (((0x00990000 | 0x900)+388)))
  | ((unsigned) (((0x00990000 | 0x900)+389)))
  | ((unsigned) (((0x00990000 | 0x900)+390)))
  | ((unsigned) (((0x00990000 | 0x900)+391)))
  | ((unsigned) (((0x00990000 | 0x900)+392)))
  | ((unsigned) (((0x00990000 | 0x900)+393)))
  | ((unsigned) (((0x00990000 | 0x900)+394)))
  | ((unsigned) (((0x00990000 | 0x900)+395)))
  | ((unsigned) (((0x00990000 | 0x900)+396)))
  | ((unsigned) (((0x00990000 | 0x900)+397)))
  | ((unsigned) (((0x00990000 | 0x900)+400)))
  | ((unsigned) (((0x00990000 | 0x900)+401)))
  | ((unsigned) (((0x00990000 | 0x900)+402)))
  | ((unsigned) (((0x00990000 | 0x900)+403)))
  | ((unsigned) (((0x00990000 | 0x900)+404)))
  | ((unsigned) (((0x00990000 | 0x900)+405)))
  | ((unsigned) (((0x00990000 | 0x900)+406)))
  | ((unsigned) (((0x00990000 | 0x900)+407)))
  | ((unsigned) (((0x00990000 | 0x900)+500)))
  | ((unsigned) (((0x00990000 | 0x900)+501)))
  | ((unsigned) (((0x00990000 | 0x900)+502)))
  | ((unsigned) (((0x00990000 | 0x900)+503)))
  | ((unsigned) (((0x00990000 | 0x900)+504)))
  | ((unsigned) (((0x00990000 | 0x900)+505)))
  | ((unsigned) (((0x00990000 | 0x900)+506)))
  | ((unsigned) (((0x00990000 | 0x900)+507)))
  | ((unsigned) (((0x00990000 | 0x900)+508)))
  | ((unsigned) (((0x00990000 | 0x900)+509)))
  | ((unsigned) (((0x00990000 | 0x900)+510)))
  | ((unsigned) (((0x00990000 | 0x900)+511)))
  | ((unsigned) (((0x00990000 | 0x900)+512)))
  | ((unsigned) (((0x00990000 | 0x900) + 600)))
  | ((unsigned) (((0x00990000 | 0x900) + 601)))
  | ((unsigned) (((0x00990000 | 0x900) + 602)))
  | ((unsigned) (((0x00990000 | 0x900) + 603)))
  | ((unsigned) (((0x00990000 | 0x900) + 604)))
  | ((unsigned) (((0x00990000 | 0x900) + 605)))
  | ((unsigned) (((0x00990000 | 0x900) + 606)))
  | ((unsigned) (((0x00990000 | 0x900) + 607)))
  | ((unsigned) (((0x00990000 | 0x900) + 608)))
  | ((unsigned) (((0x00990000 | 0x900) + 609)))
  | ((unsigned) (((0x00990000 | 0x900) + 610)))
  | ((unsigned) (((0x00990000 | 0x900) + 611)))
  | ((unsigned) (((0x00990000 | 0x900) + 612)))
  | ((unsigned) (((0x00990000 | 0x900) + 613)))
  | ((unsigned) (((0x00990000 | 0x900) + 614)))
  | ((unsigned) (((0x00990000 | 0x900) + 615)))
  | ((unsigned) (((0x00990000 | 0x900) + 616)))
  | ((unsigned) (((0x00990000 | 0x900) + 617)))
  | ((unsigned) (((0x00990000 | 0x900) + 618)))
  | ((unsigned) (((0x00990000 | 0x900) + 619)))
  | ((unsigned) (((0x00990000 | 0x900) + 620)))
  | ((unsigned) (((0x00990000 | 0x900) + 621)))
  | ((unsigned) (((0x00990000 | 0x900) + 622)))
  | ((unsigned) (((0x00990000 | 0x900) + 623)))
  | ((unsigned) (((0x00990000 | 0x900) + 624)))
  | ((unsigned) (((0x00990000 | 0x900) + 625)))
  | ((unsigned) (((0x00990000 | 0x900) + 626)))
  | ((unsigned) (((0x00990000 | 0x900) + 627)))
  | ((unsigned) (((0x00990000 | 0x900) + 628)))
  | ((unsigned) (((0x00990000 | 0x900) + 629)))
  | ((unsigned) (((0x00990000 | 0x900) + 630)))
  | ((unsigned) (((0x00990000 | 0x900) + 631)))
  | ((unsigned) (((0x00990000 | 0x900) + 632)))
  | ((unsigned) (((0x00990000 | 0x900) + 633)))
  | ((unsigned) (((0x00990000 | 0x900) + 634)))
  | ((unsigned) (((0x00990000 | 0x900) + 635)))
  | ((unsigned) (((0x00990000 | 0x900) + 636)))
  | ((unsigned) (((0x00990000 | 0x900) + 637)))
  | ((unsigned) (((0x00990000 | 0x900) + 638)))
  | ((unsigned) (((0x00990000 | 0x900) + 639)))
  | ((unsigned) (((0x00990000 | 0x900) + 640)))
  | ((unsigned) (((0x00990000 | 0x900) + 641)))
  | ((unsigned) (((0x00990000 | 0x900) + 642)))
  | ((unsigned) (((0x00990000 | 0x900) + 643)))
  | ((unsigned) (((0x00990000 | 0x900) + 644)))
  | ((unsigned) (((0x00990000 | 0x900) + 645)))
  | ((unsigned) (((0x00990000 | 0x900) + 646)))
  | ((unsigned) (((0x00990000 | 0x900) + 647)))
  | ((unsigned) (((0x00990000 | 0x900) + 648)))
  | ((unsigned) (((0x00990000 | 0x900) + 649)))
  | ((unsigned) (((0x00990000 | 0x900) + 650)))
  | ((unsigned) (((0x00990000 | 0x900) + 651)))
  | ((unsigned) (((0x00990000 | 0x900) + 652)))
  | ((unsigned) (((0x00990000 | 0x900) + 653)))
  | ((unsigned) (((0x00990000 | 0x900) + 654)))
  | ((unsigned) (((0x00990000 | 0x1000)+0)))
  | ((unsigned) (((0x00990000 | 0x1000)+1)))
  | ((unsigned) (((0x00990000 | 0x1000)+2)))
  | ((unsigned) (((0x00990000 | 0x1000)+3)))
  | ((unsigned) (((0x00990000 | 0x1000)+4)))
  | ((unsigned) (((0x00990000 | 0x1000)+5)))
  | ((unsigned) (((0x00990000 | 0x1000)+6)))
  | ((unsigned) (((0x00990000 | 0x1000)+7)))
  | ((unsigned) (((0x00990000 | 0x1000)+8)))
  | ((unsigned) (((0x00990000 | 0x1000)+9)))
  | ((unsigned) (((0x00990000 | 0x1000)+10)))
  | ((unsigned) (((0x00990000 | 0x1000)+11)))
  | ((unsigned) (((0x00990000 | 0x1100)+0)))
  | ((unsigned) (((0x00990000 | 0x1100)+1)))
  | ((unsigned) (((0x00990000 | 0x1100)+2)))
  | ((unsigned) (((0x00990000 | 0x1100)+3)))
  | ((unsigned) (((0x00990000 | 0x1100)+4)))
  | ((unsigned) (((0x00990000 | 0x1100)+5)))
  | ((unsigned) (((0x00990000 | 0x1100)+6)))
  | ((unsigned) (((0x00990000 | 0x1100)+7)))
  | ((unsigned) (((0x00990000 | 0x1100)+50)))
  | ((unsigned) (((0x00990000 | 0x1100)+51)))
  | ((unsigned) (((0x00990000 | 0x1100)+52)))
  | ((unsigned) (((0x00990000 | 0x1100)+53)))
  | ((unsigned) (((0x00990000 | 0x1100)+54)))
  | ((unsigned) (((0x009a0000 | 0x900)+1)))
  | ((unsigned) (((0x009a0000 | 0x900)+2)))
  | ((unsigned) (((0x009a0000 | 0x900)+3)))
  | ((unsigned) (((0x009a0000 | 0x900)+4)))
  | ((unsigned) (((0x009a0000 | 0x900)+5)))
  | ((unsigned) (((0x009a0000 | 0x900)+6)))
  | ((unsigned) (((0x009a0000 | 0x900)+7)))
  | ((unsigned) (((0x009a0000 | 0x900)+8)))
  | ((unsigned) (((0x009a0000 | 0x900)+9)))
  | ((unsigned) (((0x009a0000 | 0x900)+10)))
  | ((unsigned) (((0x009a0000 | 0x900)+11)))
  | ((unsigned) (((0x009a0000 | 0x900)+12)))
  | ((unsigned) (((0x009a0000 | 0x900)+13)))
  | ((unsigned) (((0x009a0000 | 0x900)+14)))
  | ((unsigned) (((0x009a0000 | 0x900)+15)))
  | ((unsigned) (((0x009a0000 | 0x900)+16)))
  | ((unsigned) (((0x009a0000 | 0x900)+17)))
  | ((unsigned) (((0x009a0000 | 0x900)+18)))
  | ((unsigned) (((0x009a0000 | 0x900)+19)))
  | ((unsigned) (((0x009a0000 | 0x900)+20)))
  | ((unsigned) (((0x009a0000 | 0x900)+21)))
  | ((unsigned) (((0x009a0000 | 0x900)+22)))
  | ((unsigned) (((0x009a0000 | 0x900)+23)))
  | ((unsigned) (((0x009a0000 | 0x900)+24)))
  | ((unsigned) (((0x009a0000 | 0x900)+25)))
  | ((unsigned) (((0x009a0000 | 0x900)+26)))
  | ((unsigned) (((0x009a0000 | 0x900)+27)))
  | ((unsigned) (((0x009a0000 | 0x900)+28)))
  | ((unsigned) (((0x009a0000 | 0x900)+29)))
  | ((unsigned) (((0x009a0000 | 0x900)+30)))
  | ((unsigned) (((0x009a0000 | 0x900)+31)))
  | ((unsigned) (((0x009a0000 | 0x900)+32)))
  | ((unsigned) (((0x009a0000 | 0x900)+33)))
  | ((unsigned) (((0x009b0000 | 0x900) + 1)))
  | ((unsigned) (((0x009b0000 | 0x900) + 2)))
  | ((unsigned) (((0x009b0000 | 0x900) + 3)))
  | ((unsigned) (((0x009b0000 | 0x900) + 5)))
  | ((unsigned) (((0x009b0000 | 0x900) + 6)))
  | ((unsigned) (((0x009b0000 | 0x900) + 7)))
  | ((unsigned) (((0x009b0000 | 0x900) + 8)))
  | ((unsigned) (((0x009b0000 | 0x900) + 9)))
  | ((unsigned) (((0x009b0000 | 0x900) + 10)))
  | ((unsigned) (((0x009b0000 | 0x900) + 11)))
  | ((unsigned) (((0x009b0000 | 0x900) + 12)))
  | ((unsigned) (((0x009b0000 | 0x900) + 13)))
  | ((unsigned) (((0x009b0000 | 0x900) + 14)))
  | ((unsigned) (((0x009b0000 | 0x900) + 15)))
  | ((unsigned) (((0x009b0000 | 0x900) + 64)))
  | ((unsigned) (((0x009b0000 | 0x900) + 65)))
  | ((unsigned) (((0x009b0000 | 0x900) + 66)))
  | ((unsigned) (((0x009b0000 | 0x900) + 80)))
  | ((unsigned) (((0x009b0000 | 0x900) + 81)))
  | ((unsigned) (((0x009b0000 | 0x900) + 82)))
  | ((unsigned) (((0x009b0000 | 0x900) + 83)))
  | ((unsigned) (((0x009b0000 | 0x900) + 84)))
  | ((unsigned) (((0x009b0000 | 0x900) + 96)))
  | ((unsigned) (((0x009b0000 | 0x900) + 97)))
  | ((unsigned) (((0x009b0000 | 0x900) + 98)))
  | ((unsigned) (((0x009b0000 | 0x900) + 112)))
  | ((unsigned) (((0x009b0000 | 0x900) + 113)))
  | ((unsigned) (((0x009b0000 | 0x900) + 114)))
  | ((unsigned) (((0x009c0000 | 0x900) + 1)))
  | ((unsigned) (((0x009c0000 | 0x900) + 2)))
  | ((unsigned) (((0x009c0000 | 0x900) + 3)))
  | ((unsigned) (((0x009c0000 | 0x900) + 4)))
  | ((unsigned) (((0x009c0000 | 0x900) + 5)))
  | ((unsigned) (((0x009c0000 | 0x900) + 6)))
  | ((unsigned) (((0x009c0000 | 0x900) + 7)))
  | ((unsigned) (((0x009c0000 | 0x900) + 8)))
  | ((unsigned) (((0x009c0000 | 0x900) + 9)))
  | ((unsigned) (((0x009c0000 | 0x900) + 10)))
  | ((unsigned) (((0x009c0000 | 0x900) + 11)))
  | ((unsigned) (((0x009c0000 | 0x900) + 12)))
  | ((unsigned) (((0x009e0000 | 0x900) + 1)))
  | ((unsigned) (((0x009e0000 | 0x900) + 2)))
  | ((unsigned) (((0x009e0000 | 0x900) + 3)))
  | ((unsigned) (((0x009e0000 | 0x900) + 4)))
  | ((unsigned) (((0x009e0000 | 0x900) + 5)))
  | ((unsigned) (((0x009e0000 | 0x900) + 6)))
  | ((unsigned) (((0x009e0000 | 0x900) + 7)))
  | ((unsigned) (((0x009e0000 | 0x900) + 8)))
  | ((unsigned) (((0x009e0000 | 0x900) + 9)))
  | ((unsigned) (((0x009f0000 | 0x900) + 1)))
  | ((unsigned) (((0x009f0000 | 0x900) + 2)))
  | ((unsigned) (((0x009f0000 | 0x900) + 3)))
  | ((unsigned) (((0x009f0000 | 0x900) + 4)))
  | ((unsigned) (((0x009f0000 | 0x900) + 5)))
  | ((unsigned) (((0x00a00000 | 0x900) + 5)))
  | ((unsigned) (((0x00a00000 | 0x900) + 6)))
  | ((unsigned) (((0x00a00000 | 0x900) + 101)))
  | ((unsigned) (((0x00a00000 | 0x900) + 102)))
  | ((unsigned) (((0x00a10000 | 0x900) + 1)))
  | ((unsigned) (((0x00a10000 | 0x900) + 2)))
  | ((unsigned) (((0x00a10000 | 0x900) + 3)))
  | ((unsigned) (((0x00a10000 | 0x900) + 4)))
  | ((unsigned) (((0x00a10000 | 0x900) + 5)))
  | ((unsigned) (((0x00a10000 | 0x900) + 6)))
  | ((unsigned) (((0x00a10000 | 0x900) + 7)))
  | ((unsigned) (((0x00a10000 | 0x900) + 8)))
  | ((unsigned) (((0x00a20000 | 0x900) + 11)))
  | ((unsigned) (((0x00a20000 | 0x900) + 12)))
  | ((unsigned) (((0x00a20000 | 0x900) + 32)))
  | ((unsigned) (((0x00a20000 | 0x900) + 41)))
  | ((unsigned) (((0x00a20000 | 0x900) + 42)))
  | ((unsigned) (((0x00a20000 | 0x900) + 51)))
  | ((unsigned) (((0x00a20000 | 0x900) + 52)))
  | ((unsigned) (((0x00a20000 | 0x900) + 61)))
  | ((unsigned) (((0x00a20000 | 0x900) + 62)))
  | ((unsigned) (((0x00a20000 | 0x900) + 91)))
  | ((unsigned) (((0x00a30000 | 0x900) + 1)))
  | ((unsigned) (((0x00a30000 | 0x900) + 2)))
  | ((unsigned) (((0x00a30000 | 0x900) + 3)))
  | ((unsigned) (((0x00a30000 | 0x900) + 4)))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CID_BRIGHTNESS")
  + sizeof("V4L2_CID_CONTRAST")
  + sizeof("V4L2_CID_SATURATION")
  + sizeof("V4L2_CID_HUE")
  + sizeof("V4L2_CID_AUDIO_VOLUME")
  + sizeof("V4L2_CID_AUDIO_BALANCE")
  + sizeof("V4L2_CID_AUDIO_BASS")
  + sizeof("V4L2_CID_AUDIO_TREBLE")
  + sizeof("V4L2_CID_AUDIO_MUTE")
  + sizeof("V4L2_CID_AUDIO_LOUDNESS")
  + sizeof("V4L2_CID_BLACK_LEVEL")
  + sizeof("V4L2_CID_AUTO_WHITE_BALANCE")
  + sizeof("V4L2_CID_DO_WHITE_BALANCE")
  + sizeof("V4L2_CID_RED_BALANCE")
  + sizeof("V4L2_CID_BLUE_BALANCE")
  + sizeof("V4L2_CID_GAMMA")
  + sizeof("V4L2_CID_EXPOSURE")
  + sizeof("V4L2_CID_AUTOGAIN")
  + sizeof("V4L2_CID_GAIN")
  + sizeof("V4L2_CID_HFLIP")
  + sizeof("V4L2_CID_VFLIP")
  + sizeof("V4L2_CID_HCENTER")
  + sizeof("V4L2_CID_VCENTER")
  + sizeof("V4L2_CID_POWER_LINE_FREQUENCY")
  + sizeof("V4L2_CID_HUE_AUTO")
  + sizeof("V4L2_CID_WHITE_BALANCE_TEMPERATURE")
  + sizeof("V4L2_CID_SHARPNESS")
  + sizeof("V4L2_CID_BACKLIGHT_COMPENSATION")
  + sizeof("V4L2_CID_CHROMA_AGC")
  + sizeof("V4L2_CID_COLOR_KILLER")
  + sizeof("V4L2_CID_COLORFX")
  + sizeof("V4L2_CID_AUTOBRIGHTNESS")
  + sizeof("V4L2_CID_BAND_STOP_FILTER")
  + sizeof("V4L2_CID_ROTATE")
  + sizeof("V4L2_CID_BG_COLOR")
  + sizeof("V4L2_CID_CHROMA_GAIN")
  + sizeof("V4L2_CID_ILLUMINATORS_1")
  + sizeof("V4L2_CID_ILLUMINATORS_2")
  + sizeof("V4L2_CID_MIN_BUFFERS_FOR_CAPTURE")
  + sizeof("V4L2_CID_MIN_BUFFERS_FOR_OUTPUT")
  + sizeof("V4L2_CID_ALPHA_COMPONENT")
  + sizeof("V4L2_CID_COLORFX_CBCR")
  + sizeof("V4L2_CID_MPEG_STREAM_TYPE")
  + sizeof("V4L2_CID_MPEG_STREAM_PID_PMT")
  + sizeof("V4L2_CID_MPEG_STREAM_PID_AUDIO")
  + sizeof("V4L2_CID_MPEG_STREAM_PID_VIDEO")
  + sizeof("V4L2_CID_MPEG_STREAM_PID_PCR")
  + sizeof("V4L2_CID_MPEG_STREAM_PES_ID_AUDIO")
  + sizeof("V4L2_CID_MPEG_STREAM_PES_ID_VIDEO")
  + sizeof("V4L2_CID_MPEG_STREAM_VBI_FMT")
  + sizeof("V4L2_CID_MPEG_AUDIO_SAMPLING_FREQ")
  + sizeof("V4L2_CID_MPEG_AUDIO_ENCODING")
  + sizeof("V4L2_CID_MPEG_AUDIO_L1_BITRATE")
  + sizeof("V4L2_CID_MPEG_AUDIO_L2_BITRATE")
  + sizeof("V4L2_CID_MPEG_AUDIO_L3_BITRATE")
  + sizeof("V4L2_CID_MPEG_AUDIO_MODE")
  + sizeof("V4L2_CID_MPEG_AUDIO_MODE_EXTENSION")
  + sizeof("V4L2_CID_MPEG_AUDIO_EMPHASIS")
  + sizeof("V4L2_CID_MPEG_AUDIO_CRC")
  + sizeof("V4L2_CID_MPEG_AUDIO_MUTE")
  + sizeof("V4L2_CID_MPEG_AUDIO_AAC_BITRATE")
  + sizeof("V4L2_CID_MPEG_AUDIO_AC3_BITRATE")
  + sizeof("V4L2_CID_MPEG_AUDIO_DEC_PLAYBACK")
  + sizeof("V4L2_CID_MPEG_AUDIO_DEC_MULTILINGUAL_PLAYBACK")
  + sizeof("V4L2_CID_MPEG_VIDEO_ENCODING")
  + sizeof("V4L2_CID_MPEG_VIDEO_ASPECT")
  + sizeof("V4L2_CID_MPEG_VIDEO_B_FRAMES")
  + sizeof("V4L2_CID_MPEG_VIDEO_GOP_SIZE")
  + sizeof("V4L2_CID_MPEG_VIDEO_GOP_CLOSURE")
  + sizeof("V4L2_CID_MPEG_VIDEO_PULLDOWN")
  + sizeof("V4L2_CID_MPEG_VIDEO_BITRATE_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_BITRATE")
  + sizeof("V4L2_CID_MPEG_VIDEO_BITRATE_PEAK")
  + sizeof("V4L2_CID_MPEG_VIDEO_TEMPORAL_DECIMATION")
  + sizeof("V4L2_CID_MPEG_VIDEO_MUTE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MUTE_YUV")
  + sizeof("V4L2_CID_MPEG_VIDEO_DECODER_SLICE_INTERFACE")
  + sizeof("V4L2_CID_MPEG_VIDEO_DECODER_MPEG4_DEBLOCK_FILTER")
  + sizeof("V4L2_CID_MPEG_VIDEO_CYCLIC_INTRA_REFRESH_MB")
  + sizeof("V4L2_CID_MPEG_VIDEO_FRAME_RC_ENABLE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEADER_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MAX_REF_PIC")
  + sizeof("V4L2_CID_MPEG_VIDEO_MB_RC_ENABLE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_BYTES")
  + sizeof("V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MAX_MB")
  + sizeof("V4L2_CID_MPEG_VIDEO_MULTI_SLICE_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_VBV_SIZE")
  + sizeof("V4L2_CID_MPEG_VIDEO_DEC_PTS")
  + sizeof("V4L2_CID_MPEG_VIDEO_DEC_FRAME")
  + sizeof("V4L2_CID_MPEG_VIDEO_VBV_DELAY")
  + sizeof("V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER")
  + sizeof("V4L2_CID_MPEG_VIDEO_MV_H_SEARCH_RANGE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MV_V_SEARCH_RANGE")
  + sizeof("V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME")
  + sizeof("V4L2_CID_MPEG_VIDEO_BASELAYER_PRIORITY_ID")
  + sizeof("V4L2_CID_MPEG_VIDEO_AU_DELIMITER")
  + sizeof("V4L2_CID_MPEG_VIDEO_LTR_COUNT")
  + sizeof("V4L2_CID_MPEG_VIDEO_FRAME_LTR_INDEX")
  + sizeof("V4L2_CID_MPEG_VIDEO_USE_LTR_FRAMES")
  + sizeof("V4L2_CID_MPEG_VIDEO_DEC_CONCEAL_COLOR")
  + sizeof("V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD")
  + sizeof("V4L2_CID_MPEG_VIDEO_INTRA_REFRESH_PERIOD_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG2_SLICE_PARAMS")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG2_QUANTIZATION")
  + sizeof("V4L2_CID_FWHT_I_FRAME_QP")
  + sizeof("V4L2_CID_FWHT_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H263_I_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H263_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H263_B_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H263_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H263_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_I_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_B_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_8X8_TRANSFORM")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_CPB_SIZE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_ENTROPY_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_I_PERIOD")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_LEVEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_ALPHA")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_BETA")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_LOOP_FILTER_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_PROFILE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_HEIGHT")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_VUI_EXT_SAR_WIDTH")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_ENABLE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_VUI_SAR_IDC")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_SEI_FRAME_PACKING")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_SEI_FP_CURRENT_FRAME_0")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_SEI_FP_ARRANGEMENT_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO_MAP_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO_SLICE_GROUP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_DIRECTION")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO_CHANGE_RATE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_FMO_RUN_LENGTH")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_ASO")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_ASO_SLICE_ORDER")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIERARCHICAL_CODING_LAYER_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_CONSTRAINED_INTRA_PREDICTION")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_CHROMA_QP_INDEX_OFFSET")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_I_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_P_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_B_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L0_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L1_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L2_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L3_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L4_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L5_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_H264_HIER_CODING_L6_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_I_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_B_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_LEVEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_PROFILE")
  + sizeof("V4L2_CID_MPEG_VIDEO_MPEG4_QPEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_NUM_PARTITIONS")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_IMD_DISABLE_4X4")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_NUM_REF_FRAMES")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_FILTER_LEVEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_FILTER_SHARPNESS")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_REF_PERIOD")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_GOLDEN_FRAME_SEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_I_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_VPX_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_VP8_PROFILE")
  + sizeof("V4L2_CID_MPEG_VIDEO_VP9_PROFILE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_LAYER")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_PROFILE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_LEVEL")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_FRAME_RATE_RESOLUTION")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_TIER")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_MAX_PARTITION_DEPTH")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_LOOP_FILTER_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_LF_BETA_OFFSET_DIV2")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_LF_TC_OFFSET_DIV2")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_TYPE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_REFRESH_PERIOD")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_LOSSLESS_CU")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_CONST_INTRA_PRED")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_WAVEFRONT")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_GENERAL_PB")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_TEMPORAL_ID")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_STRONG_SMOOTHING")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_MAX_NUM_MERGE_MV_MINUS1")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_INTRA_PU_SPLIT")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_TMV_PREDICTION")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_WITHOUT_STARTCODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_SIZE_OF_LENGTH_FIELD")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L0_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L1_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L2_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L3_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L4_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L5_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_HIER_CODING_L6_BR")
  + sizeof("V4L2_CID_MPEG_VIDEO_REF_NUMBER_FOR_PFRAMES")
  + sizeof("V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR")
  + sizeof("V4L2_CID_MPEG_VIDEO_CONSTANT_QUALITY")
  + sizeof("V4L2_CID_MPEG_VIDEO_FRAME_SKIP_MODE")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_I_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_P_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MIN_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_HEVC_B_FRAME_MAX_QP")
  + sizeof("V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY")
  + sizeof("V4L2_CID_MPEG_VIDEO_DEC_DISPLAY_DELAY_ENABLE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_BOTTOM")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_TOP")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_BOTTOM")
  + sizeof("V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_TOP")
  + sizeof("V4L2_CID_MPEG_CX2341X_STREAM_INSERT_NAV_PACKETS")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_DECODER_H264_DISPLAY_DELAY_ENABLE")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_FRAME_SKIP_MODE")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_FORCE_FRAME_TYPE")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_PADDING")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_PADDING_YUV")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_RC_FIXED_TARGET_BIT")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_RC_REACTION_COEFF")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_ACTIVITY")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_DARK")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_SMOOTH")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_H264_ADAPTIVE_RC_STATIC")
  + sizeof("V4L2_CID_MPEG_MFC51_VIDEO_H264_NUM_REF_PIC_FOR_P")
  + sizeof("V4L2_CID_EXPOSURE_AUTO")
  + sizeof("V4L2_CID_EXPOSURE_ABSOLUTE")
  + sizeof("V4L2_CID_EXPOSURE_AUTO_PRIORITY")
  + sizeof("V4L2_CID_PAN_RELATIVE")
  + sizeof("V4L2_CID_TILT_RELATIVE")
  + sizeof("V4L2_CID_PAN_RESET")
  + sizeof("V4L2_CID_TILT_RESET")
  + sizeof("V4L2_CID_PAN_ABSOLUTE")
  + sizeof("V4L2_CID_TILT_ABSOLUTE")
  + sizeof("V4L2_CID_FOCUS_ABSOLUTE")
  + sizeof("V4L2_CID_FOCUS_RELATIVE")
  + sizeof("V4L2_CID_FOCUS_AUTO")
  + sizeof("V4L2_CID_ZOOM_ABSOLUTE")
  + sizeof("V4L2_CID_ZOOM_RELATIVE")
  + sizeof("V4L2_CID_ZOOM_CONTINUOUS")
  + sizeof("V4L2_CID_PRIVACY")
  + sizeof("V4L2_CID_IRIS_ABSOLUTE")
  + sizeof("V4L2_CID_IRIS_RELATIVE")
  + sizeof("V4L2_CID_AUTO_EXPOSURE_BIAS")
  + sizeof("V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE")
  + sizeof("V4L2_CID_WIDE_DYNAMIC_RANGE")
  + sizeof("V4L2_CID_IMAGE_STABILIZATION")
  + sizeof("V4L2_CID_ISO_SENSITIVITY")
  + sizeof("V4L2_CID_ISO_SENSITIVITY_AUTO")
  + sizeof("V4L2_CID_EXPOSURE_METERING")
  + sizeof("V4L2_CID_SCENE_MODE")
  + sizeof("V4L2_CID_3A_LOCK")
  + sizeof("V4L2_CID_AUTO_FOCUS_START")
  + sizeof("V4L2_CID_AUTO_FOCUS_STOP")
  + sizeof("V4L2_CID_AUTO_FOCUS_STATUS")
  + sizeof("V4L2_CID_AUTO_FOCUS_RANGE")
  + sizeof("V4L2_CID_PAN_SPEED")
  + sizeof("V4L2_CID_TILT_SPEED")
  + sizeof("V4L2_CID_RDS_TX_DEVIATION")
  + sizeof("V4L2_CID_RDS_TX_PI")
  + sizeof("V4L2_CID_RDS_TX_PTY")
  + sizeof("V4L2_CID_RDS_TX_PS_NAME")
  + sizeof("V4L2_CID_RDS_TX_RADIO_TEXT")
  + sizeof("V4L2_CID_RDS_TX_MONO_STEREO")
  + sizeof("V4L2_CID_RDS_TX_ARTIFICIAL_HEAD")
  + sizeof("V4L2_CID_RDS_TX_COMPRESSED")
  + sizeof("V4L2_CID_RDS_TX_DYNAMIC_PTY")
  + sizeof("V4L2_CID_RDS_TX_TRAFFIC_ANNOUNCEMENT")
  + sizeof("V4L2_CID_RDS_TX_TRAFFIC_PROGRAM")
  + sizeof("V4L2_CID_RDS_TX_MUSIC_SPEECH")
  + sizeof("V4L2_CID_RDS_TX_ALT_FREQS_ENABLE")
  + sizeof("V4L2_CID_RDS_TX_ALT_FREQS")
  + sizeof("V4L2_CID_AUDIO_LIMITER_ENABLED")
  + sizeof("V4L2_CID_AUDIO_LIMITER_RELEASE_TIME")
  + sizeof("V4L2_CID_AUDIO_LIMITER_DEVIATION")
  + sizeof("V4L2_CID_AUDIO_COMPRESSION_ENABLED")
  + sizeof("V4L2_CID_AUDIO_COMPRESSION_GAIN")
  + sizeof("V4L2_CID_AUDIO_COMPRESSION_THRESHOLD")
  + sizeof("V4L2_CID_AUDIO_COMPRESSION_ATTACK_TIME")
  + sizeof("V4L2_CID_AUDIO_COMPRESSION_RELEASE_TIME")
  + sizeof("V4L2_CID_PILOT_TONE_ENABLED")
  + sizeof("V4L2_CID_PILOT_TONE_DEVIATION")
  + sizeof("V4L2_CID_PILOT_TONE_FREQUENCY")
  + sizeof("V4L2_CID_TUNE_PREEMPHASIS")
  + sizeof("V4L2_CID_TUNE_POWER_LEVEL")
  + sizeof("V4L2_CID_TUNE_ANTENNA_CAPACITOR")
  + sizeof("V4L2_CID_FLASH_LED_MODE")
  + sizeof("V4L2_CID_FLASH_STROBE_SOURCE")
  + sizeof("V4L2_CID_FLASH_STROBE")
  + sizeof("V4L2_CID_FLASH_STROBE_STOP")
  + sizeof("V4L2_CID_FLASH_STROBE_STATUS")
  + sizeof("V4L2_CID_FLASH_TIMEOUT")
  + sizeof("V4L2_CID_FLASH_INTENSITY")
  + sizeof("V4L2_CID_FLASH_TORCH_INTENSITY")
  + sizeof("V4L2_CID_FLASH_INDICATOR_INTENSITY")
  + sizeof("V4L2_CID_FLASH_FAULT")
  + sizeof("V4L2_CID_FLASH_CHARGE")
  + sizeof("V4L2_CID_FLASH_READY")
  + sizeof("V4L2_CID_VBLANK")
  + sizeof("V4L2_CID_HBLANK")
  + sizeof("V4L2_CID_ANALOGUE_GAIN")
  + sizeof("V4L2_CID_TEST_PATTERN_RED")
  + sizeof("V4L2_CID_TEST_PATTERN_GREENR")
  + sizeof("V4L2_CID_TEST_PATTERN_BLUE")
  + sizeof("V4L2_CID_TEST_PATTERN_GREENB")
  + sizeof("V4L2_CID_UNIT_CELL_SIZE")
  + sizeof("V4L2_CID_NOTIFY_GAINS")
  + sizeof("V4L2_CID_LINK_FREQ")
  + sizeof("V4L2_CID_PIXEL_RATE")
  + sizeof("V4L2_CID_TEST_PATTERN")
  + sizeof("V4L2_CID_DEINTERLACING_MODE")
  + sizeof("V4L2_CID_DIGITAL_GAIN")
  + sizeof("V4L2_CID_DV_TX_RGB_RANGE")
  + sizeof("V4L2_CID_DV_TX_IT_CONTENT_TYPE")
  + sizeof("V4L2_CID_DV_RX_RGB_RANGE")
  + sizeof("V4L2_CID_DV_RX_IT_CONTENT_TYPE")
  + sizeof("V4L2_CID_TUNE_DEEMPHASIS")
  + sizeof("V4L2_CID_RDS_RECEPTION")
  + sizeof("V4L2_CID_RDS_RX_PTY")
  + sizeof("V4L2_CID_RDS_RX_PS_NAME")
  + sizeof("V4L2_CID_RDS_RX_RADIO_TEXT")
  + sizeof("V4L2_CID_RDS_RX_TRAFFIC_ANNOUNCEMENT")
  + sizeof("V4L2_CID_RDS_RX_TRAFFIC_PROGRAM")
  + sizeof("V4L2_CID_RDS_RX_MUSIC_SPEECH")
  + sizeof("V4L2_CID_RF_TUNER_BANDWIDTH_AUTO")
  + sizeof("V4L2_CID_RF_TUNER_BANDWIDTH")
  + sizeof("V4L2_CID_RF_TUNER_RF_GAIN")
  + sizeof("V4L2_CID_RF_TUNER_LNA_GAIN_AUTO")
  + sizeof("V4L2_CID_RF_TUNER_LNA_GAIN")
  + sizeof("V4L2_CID_RF_TUNER_MIXER_GAIN_AUTO")
  + sizeof("V4L2_CID_RF_TUNER_MIXER_GAIN")
  + sizeof("V4L2_CID_RF_TUNER_IF_GAIN_AUTO")
  + sizeof("V4L2_CID_RF_TUNER_IF_GAIN")
  + sizeof("V4L2_CID_RF_TUNER_PLL_LOCK")
  + sizeof("V4L2_CID_DETECT_MD_MODE")
  + sizeof("V4L2_CID_DETECT_MD_GLOBAL_THRESHOLD")
  + sizeof("V4L2_CID_DETECT_MD_THRESHOLD_GRID")
  + sizeof("V4L2_CID_DETECT_MD_REGION_GRID")
  ,
} };


static const struct xlat_data v4l2_control_query_flags_xdata[] = {
 { (unsigned)(0x80000000), "V4L2_CTRL_FLAG_NEXT_CTRL" },
 { (unsigned)(0x40000000), "V4L2_CTRL_FLAG_NEXT_COMPOUND" },
};
const struct xlat v4l2_control_query_flags[1] = { {
 .data = v4l2_control_query_flags_xdata,
 .size = (sizeof(v4l2_control_query_flags_xdata) / sizeof((v4l2_control_query_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_query_flags_xdata)), __typeof__(&(v4l2_control_query_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x80000000))
  | ((unsigned) (0x40000000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CTRL_FLAG_NEXT_CTRL")
  + sizeof("V4L2_CTRL_FLAG_NEXT_COMPOUND")
  ,
} };

static void
print_v4l2_cid(uint32_t cid, _Bool next_flags)
{
 if (((xlat_verbosity) & ((1 << 2) - 1)) == XLAT_STYLE_RAW) {
  tprintf_string("%#llx", (sizeof(cid) == sizeof(char) ? (unsigned long long) (unsigned char) (cid) : sizeof(cid) == sizeof(short) ? (unsigned long long) (unsigned short) (cid) : sizeof(cid) == sizeof(int) ? (unsigned long long) (unsigned int) (cid) : sizeof(cid) == sizeof(long) ? (unsigned long long) (unsigned long) (cid) : (unsigned long long) (cid)));
  return;
 }
 tprint_flags_begin();
 if (next_flags) {
  uint32_t flags = cid & v4l2_control_query_flags->flags_mask;
  if (flags) {
   printflags_in(v4l2_control_query_flags, flags,
          "V4L2_CTRL_FLAG_NEXT_???");
   tprint_flags_or();
   cid &= ~flags;
  }
 }
 const char *id_name = xlookup(v4l2_control_ids, cid);
 if (id_name) {
  print_xlat_ex(cid, id_name, XLAT_STYLE_DEFAULT);
  tprint_flags_end();
  return;
 }
 uint64_t class_id = cid;
 const char *class_str = xlookup_le(v4l2_control_classes, &class_id);
 if (!class_str || (cid - class_id) >= 0x10000) {
  print_xlat_ex(cid, "V4L2_CID_???", PXF_DEFAULT_STR);
  tprint_flags_end();
  return;
 }
 char tmp_str[64 + sizeof("+%#") + sizeof(class_id) * 2];
 xsnprintf_(((tmp_str)), (sizeof(tmp_str) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((tmp_str)), __typeof__(&(tmp_str)[0])))]) * 0)), __func__, "(\"%s+%#\" \"l\" \"x\")" ", " "class_str, cid - class_id", (("%s+%#" "l" "x")), class_str, cid - class_id);
 print_xlat_ex(cid, tmp_str, XLAT_STYLE_DEFAULT);
 tprint_flags_end();
}
static int
print_v4l2_control(struct tcb *const tcp, const kernel_ulong_t arg,
     const _Bool is_get)
{
 struct v4l2_control c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("id"); print_v4l2_cid((c).id, (0)); } while (0);
  if (!is_get) {
   tprint_struct_next();
   do { tprints_field_name("value"); tprintf_string("%lld", (sizeof((c).value) == sizeof(char) ? (long long) (char) ((c).value) : sizeof((c).value) == sizeof(short) ? (long long) (short) ((c).value) : sizeof((c).value) == sizeof(int) ? (long long) (int) ((c).value) : sizeof((c).value) == sizeof(long) ? (long long) (long) ((c).value) : (long long) ((c).value))); } while (0);
  }
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c))) {
  if (is_get) {
   tprint_struct_next();
   do { tprints_field_name("value"); tprintf_string("%lld", (sizeof((c).value) == sizeof(char) ? (long long) (char) ((c).value) : sizeof((c).value) == sizeof(short) ? (long long) (short) ((c).value) : sizeof((c).value) == sizeof(int) ? (long long) (int) ((c).value) : sizeof((c).value) == sizeof(long) ? (long long) (long) ((c).value) : (long long) ((c).value))); } while (0);
  } else {
   tprint_value_changed();
   tprintf_string("%lld", (sizeof(c.value) == sizeof(char) ? (long long) (char) (c.value) : sizeof(c.value) == sizeof(short) ? (long long) (short) (c.value) : sizeof(c.value) == sizeof(int) ? (long long) (int) (c.value) : sizeof(c.value) == sizeof(long) ? (long long) (long) (c.value) : (long long) (c.value)));
  }
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_tuner_types_xdata[] = {
 [V4L2_TUNER_RADIO] = { (unsigned)(V4L2_TUNER_RADIO), "V4L2_TUNER_RADIO" },
 [V4L2_TUNER_ANALOG_TV] = { (unsigned)(V4L2_TUNER_ANALOG_TV), "V4L2_TUNER_ANALOG_TV" },
 [V4L2_TUNER_DIGITAL_TV] = { (unsigned)(V4L2_TUNER_DIGITAL_TV), "V4L2_TUNER_DIGITAL_TV" },
 [V4L2_TUNER_SDR] = { (unsigned)(V4L2_TUNER_SDR), "V4L2_TUNER_SDR" },
 [V4L2_TUNER_RF] = { (unsigned)(V4L2_TUNER_RF), "V4L2_TUNER_RF" },
};
const struct xlat v4l2_tuner_types[1] = { {
 .data = v4l2_tuner_types_xdata,
 .size = (sizeof(v4l2_tuner_types_xdata) / sizeof((v4l2_tuner_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_tuner_types_xdata)), __typeof__(&(v4l2_tuner_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_TUNER_RADIO))
  | ((unsigned) (V4L2_TUNER_ANALOG_TV))
  | ((unsigned) (V4L2_TUNER_DIGITAL_TV))
  | ((unsigned) (V4L2_TUNER_SDR))
  | ((unsigned) (V4L2_TUNER_RF))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_TUNER_RADIO")
  + sizeof("V4L2_TUNER_ANALOG_TV")
  + sizeof("V4L2_TUNER_DIGITAL_TV")
  + sizeof("V4L2_TUNER_SDR")
  + sizeof("V4L2_TUNER_RF")
  ,
} };


static const struct xlat_data v4l2_tuner_capabilities_xdata[] = {
 { (unsigned)(0x0001), "V4L2_TUNER_CAP_LOW" },
 { (unsigned)(0x0002), "V4L2_TUNER_CAP_NORM" },
 { (unsigned)(0x0004), "V4L2_TUNER_CAP_HWSEEK_BOUNDED" },
 { (unsigned)(0x0008), "V4L2_TUNER_CAP_HWSEEK_WRAP" },
 { (unsigned)(0x0010), "V4L2_TUNER_CAP_STEREO" },
 { (unsigned)(0x0020), "V4L2_TUNER_CAP_LANG2" },
 { (unsigned)(0x0040), "V4L2_TUNER_CAP_LANG1" },
 { (unsigned)(0x0080), "V4L2_TUNER_CAP_RDS" },
 { (unsigned)(0x0100), "V4L2_TUNER_CAP_RDS_BLOCK_IO" },
 { (unsigned)(0x0200), "V4L2_TUNER_CAP_RDS_CONTROLS" },
 { (unsigned)(0x0400), "V4L2_TUNER_CAP_FREQ_BANDS" },
 { (unsigned)(0x0800), "V4L2_TUNER_CAP_HWSEEK_PROG_LIM" },
 { (unsigned)(0x1000), "V4L2_TUNER_CAP_1HZ" },
};
const struct xlat v4l2_tuner_capabilities[1] = { {
 .data = v4l2_tuner_capabilities_xdata,
 .size = (sizeof(v4l2_tuner_capabilities_xdata) / sizeof((v4l2_tuner_capabilities_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_tuner_capabilities_xdata)), __typeof__(&(v4l2_tuner_capabilities_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x0001))
  | ((unsigned) (0x0002))
  | ((unsigned) (0x0004))
  | ((unsigned) (0x0008))
  | ((unsigned) (0x0010))
  | ((unsigned) (0x0020))
  | ((unsigned) (0x0040))
  | ((unsigned) (0x0080))
  | ((unsigned) (0x0100))
  | ((unsigned) (0x0200))
  | ((unsigned) (0x0400))
  | ((unsigned) (0x0800))
  | ((unsigned) (0x1000))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_TUNER_CAP_LOW")
  + sizeof("V4L2_TUNER_CAP_NORM")
  + sizeof("V4L2_TUNER_CAP_HWSEEK_BOUNDED")
  + sizeof("V4L2_TUNER_CAP_HWSEEK_WRAP")
  + sizeof("V4L2_TUNER_CAP_STEREO")
  + sizeof("V4L2_TUNER_CAP_LANG2")
  + sizeof("V4L2_TUNER_CAP_LANG1")
  + sizeof("V4L2_TUNER_CAP_RDS")
  + sizeof("V4L2_TUNER_CAP_RDS_BLOCK_IO")
  + sizeof("V4L2_TUNER_CAP_RDS_CONTROLS")
  + sizeof("V4L2_TUNER_CAP_FREQ_BANDS")
  + sizeof("V4L2_TUNER_CAP_HWSEEK_PROG_LIM")
  + sizeof("V4L2_TUNER_CAP_1HZ")
  ,
} };


static const struct xlat_data v4l2_tuner_rxsubchanses_xdata[] = {
 { (unsigned)(0x0001), "V4L2_TUNER_SUB_MONO" },
 { (unsigned)(0x0002), "V4L2_TUNER_SUB_STEREO" },
 { (unsigned)(0x0004), "V4L2_TUNER_SUB_LANG2" },
 { (unsigned)(0x0008), "V4L2_TUNER_SUB_LANG1" },
 { (unsigned)(0x0010), "V4L2_TUNER_SUB_RDS" },
};
const struct xlat v4l2_tuner_rxsubchanses[1] = { {
 .data = v4l2_tuner_rxsubchanses_xdata,
 .size = (sizeof(v4l2_tuner_rxsubchanses_xdata) / sizeof((v4l2_tuner_rxsubchanses_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_tuner_rxsubchanses_xdata)), __typeof__(&(v4l2_tuner_rxsubchanses_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x0001))
  | ((unsigned) (0x0002))
  | ((unsigned) (0x0004))
  | ((unsigned) (0x0008))
  | ((unsigned) (0x0010))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_TUNER_SUB_MONO")
  + sizeof("V4L2_TUNER_SUB_STEREO")
  + sizeof("V4L2_TUNER_SUB_LANG2")
  + sizeof("V4L2_TUNER_SUB_LANG1")
  + sizeof("V4L2_TUNER_SUB_RDS")
  ,
} };


static const struct xlat_data v4l2_tuner_audmodes_xdata[] = {
 [0x0000] = { (unsigned)(0x0000), "V4L2_TUNER_MODE_MONO" },
 [0x0001] = { (unsigned)(0x0001), "V4L2_TUNER_MODE_STEREO" },
 [0x0002] = { (unsigned)(0x0002), "V4L2_TUNER_MODE_LANG2" },
 [0x0003] = { (unsigned)(0x0003), "V4L2_TUNER_MODE_LANG1" },
 [0x0004] = { (unsigned)(0x0004), "V4L2_TUNER_MODE_LANG1_LANG2" },
};
const struct xlat v4l2_tuner_audmodes[1] = { {
 .data = v4l2_tuner_audmodes_xdata,
 .size = (sizeof(v4l2_tuner_audmodes_xdata) / sizeof((v4l2_tuner_audmodes_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_tuner_audmodes_xdata)), __typeof__(&(v4l2_tuner_audmodes_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (0x0000))
  | ((unsigned) (0x0001))
  | ((unsigned) (0x0002))
  | ((unsigned) (0x0003))
  | ((unsigned) (0x0004))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_TUNER_MODE_MONO")
  + sizeof("V4L2_TUNER_MODE_STEREO")
  + sizeof("V4L2_TUNER_MODE_LANG2")
  + sizeof("V4L2_TUNER_MODE_LANG1")
  + sizeof("V4L2_TUNER_MODE_LANG1_LANG2")
  ,
} };

static int
print_v4l2_tuner(struct tcb *const tcp, const kernel_ulong_t arg,
   const _Bool is_get)
{
 struct v4l2_tuner c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((c).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).index) : sizeof((c).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).index) : sizeof((c).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).index) : sizeof((c).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).index) : (unsigned long long) ((c).index))); } while (0);
  if (is_get)
   return 0;
  tprint_struct_next();
 } else {
  if (((tcp)->u_error != 0) || umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c)) < 0) {
   tprint_struct_end();
   return 0200;
  }
  if (is_get) {
   tprint_struct_next();
  } else {
   tprint_struct_end();
   tprint_value_changed();
   tprint_struct_begin();
  }
 }
 do { tprints_field_name("name"); print_quoted_cstring((const char *) (c).name, sizeof((c).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).name)), __typeof__(&((c).name)[0])))]) * 0)); } while (0);
 tprint_struct_next();
 do { tprints_field_name("type"); printxval64((v4l2_tuner_types), (sizeof((c).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).type) : sizeof((c).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).type) : sizeof((c).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).type) : sizeof((c).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).type) : (unsigned long long) ((c).type)), ("V4L2_TUNER_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("capability"); printflags64((v4l2_tuner_capabilities), (sizeof((c).capability) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).capability) : sizeof((c).capability) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).capability) : sizeof((c).capability) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).capability) : sizeof((c).capability) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).capability) : (unsigned long long) ((c).capability)), ("V4L2_TUNER_CAP_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("rangelow"); tprintf_string("%llu", (sizeof((c).rangelow) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).rangelow) : sizeof((c).rangelow) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).rangelow) : sizeof((c).rangelow) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).rangelow) : sizeof((c).rangelow) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).rangelow) : (unsigned long long) ((c).rangelow))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("rangehigh"); tprintf_string("%llu", (sizeof((c).rangehigh) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).rangehigh) : sizeof((c).rangehigh) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).rangehigh) : sizeof((c).rangehigh) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).rangehigh) : sizeof((c).rangehigh) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).rangehigh) : (unsigned long long) ((c).rangehigh))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("rxsubchans"); printflags64((v4l2_tuner_rxsubchanses), (sizeof((c).rxsubchans) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).rxsubchans) : sizeof((c).rxsubchans) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).rxsubchans) : sizeof((c).rxsubchans) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).rxsubchans) : sizeof((c).rxsubchans) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).rxsubchans) : (unsigned long long) ((c).rxsubchans)), ("V4L2_TUNER_SUB_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("audmode"); printxval64((v4l2_tuner_audmodes), (sizeof((c).audmode) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).audmode) : sizeof((c).audmode) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).audmode) : sizeof((c).audmode) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).audmode) : sizeof((c).audmode) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).audmode) : (unsigned long long) ((c).audmode)), ("V4L2_TUNER_MODE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("signal"); tprintf_string("%lld", (sizeof((c).signal) == sizeof(char) ? (long long) (char) ((c).signal) : sizeof((c).signal) == sizeof(short) ? (long long) (short) ((c).signal) : sizeof((c).signal) == sizeof(int) ? (long long) (int) ((c).signal) : sizeof((c).signal) == sizeof(long) ? (long long) (long) ((c).signal) : (long long) ((c).signal))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("afc"); tprintf_string("%lld", (sizeof((c).afc) == sizeof(char) ? (long long) (char) ((c).afc) : sizeof((c).afc) == sizeof(short) ? (long long) (short) ((c).afc) : sizeof((c).afc) == sizeof(int) ? (long long) (int) ((c).afc) : sizeof((c).afc) == sizeof(long) ? (long long) (long) ((c).afc) : (long long) ((c).afc))); } while (0);
 if ((!((tcp)->flags & 0x04))) {
  return 0;
 } else {
  tprint_struct_end();
  return 0200;
 }
}
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_BOOLEAN)
      > (unsigned long long) ((V4L2_CTRL_TYPE_INTEGER)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_BOOLEAN"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_MENU)
      > (unsigned long long) ((V4L2_CTRL_TYPE_BOOLEAN)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_MENU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_BUTTON)
      > (unsigned long long) ((V4L2_CTRL_TYPE_MENU)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_BUTTON"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_INTEGER64)
      > (unsigned long long) ((V4L2_CTRL_TYPE_BUTTON)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_INTEGER64"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_CTRL_CLASS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_INTEGER64)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_CTRL_CLASS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_STRING)
      > (unsigned long long) ((V4L2_CTRL_TYPE_CTRL_CLASS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_STRING"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_BITMASK)
      > (unsigned long long) ((V4L2_CTRL_TYPE_STRING)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_BITMASK"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_INTEGER_MENU)
      > (unsigned long long) ((V4L2_CTRL_TYPE_BITMASK)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_INTEGER_MENU"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_U8)
      > (unsigned long long) ((V4L2_CTRL_TYPE_INTEGER_MENU)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_U8"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_U16)
      > (unsigned long long) ((V4L2_CTRL_TYPE_U8)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_U16"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_U32)
      > (unsigned long long) ((V4L2_CTRL_TYPE_U16)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_U32"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_AREA)
      > (unsigned long long) ((V4L2_CTRL_TYPE_U32)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_AREA"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_HDR10_CLL_INFO)
      > (unsigned long long) ((V4L2_CTRL_TYPE_AREA)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_HDR10_CLL_INFO"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY)
      > (unsigned long long) ((V4L2_CTRL_TYPE_HDR10_CLL_INFO)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_SPS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_SPS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_PPS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_SPS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_PPS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_SCALING_MATRIX)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_PPS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_SCALING_MATRIX"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_SLICE_PARAMS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_SCALING_MATRIX)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_SLICE_PARAMS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_DECODE_PARAMS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_SLICE_PARAMS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_DECODE_PARAMS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_H264_PRED_WEIGHTS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_DECODE_PARAMS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_H264_PRED_WEIGHTS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_FWHT_PARAMS)
      > (unsigned long long) ((V4L2_CTRL_TYPE_H264_PRED_WEIGHTS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_FWHT_PARAMS"
      " is not larger than the previous value");
_Static_assert((unsigned long long) (V4L2_CTRL_TYPE_VP8_FRAME)
      > (unsigned long long) ((V4L2_CTRL_TYPE_FWHT_PARAMS)),
      "Incorrect order in #sorted xlat: V4L2_CTRL_TYPE_VP8_FRAME"
      " is not larger than the previous value");

static const struct xlat_data v4l2_control_types_xdata[] = {
 { (unsigned)(V4L2_CTRL_TYPE_INTEGER), "V4L2_CTRL_TYPE_INTEGER" },
 { (unsigned)(V4L2_CTRL_TYPE_BOOLEAN), "V4L2_CTRL_TYPE_BOOLEAN" },
 { (unsigned)(V4L2_CTRL_TYPE_MENU), "V4L2_CTRL_TYPE_MENU" },
 { (unsigned)(V4L2_CTRL_TYPE_BUTTON), "V4L2_CTRL_TYPE_BUTTON" },
 { (unsigned)(V4L2_CTRL_TYPE_INTEGER64), "V4L2_CTRL_TYPE_INTEGER64" },
 { (unsigned)(V4L2_CTRL_TYPE_CTRL_CLASS), "V4L2_CTRL_TYPE_CTRL_CLASS" },
 { (unsigned)(V4L2_CTRL_TYPE_STRING), "V4L2_CTRL_TYPE_STRING" },
 { (unsigned)(V4L2_CTRL_TYPE_BITMASK), "V4L2_CTRL_TYPE_BITMASK" },
 { (unsigned)(V4L2_CTRL_TYPE_INTEGER_MENU), "V4L2_CTRL_TYPE_INTEGER_MENU" },
 { (unsigned)(V4L2_CTRL_TYPE_U8), "V4L2_CTRL_TYPE_U8" },
 { (unsigned)(V4L2_CTRL_TYPE_U16), "V4L2_CTRL_TYPE_U16" },
 { (unsigned)(V4L2_CTRL_TYPE_U32), "V4L2_CTRL_TYPE_U32" },
 { (unsigned)(V4L2_CTRL_TYPE_AREA), "V4L2_CTRL_TYPE_AREA" },
 { (unsigned)(V4L2_CTRL_TYPE_HDR10_CLL_INFO), "V4L2_CTRL_TYPE_HDR10_CLL_INFO" },
 { (unsigned)(V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY), "V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_SPS), "V4L2_CTRL_TYPE_H264_SPS" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_PPS), "V4L2_CTRL_TYPE_H264_PPS" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_SCALING_MATRIX), "V4L2_CTRL_TYPE_H264_SCALING_MATRIX" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_SLICE_PARAMS), "V4L2_CTRL_TYPE_H264_SLICE_PARAMS" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_DECODE_PARAMS), "V4L2_CTRL_TYPE_H264_DECODE_PARAMS" },
 { (unsigned)(V4L2_CTRL_TYPE_H264_PRED_WEIGHTS), "V4L2_CTRL_TYPE_H264_PRED_WEIGHTS" },
 { (unsigned)(V4L2_CTRL_TYPE_FWHT_PARAMS), "V4L2_CTRL_TYPE_FWHT_PARAMS" },
 { (unsigned)(V4L2_CTRL_TYPE_VP8_FRAME), "V4L2_CTRL_TYPE_VP8_FRAME" },
};
const struct xlat v4l2_control_types[1] = { {
 .data = v4l2_control_types_xdata,
 .size = (sizeof(v4l2_control_types_xdata) / sizeof((v4l2_control_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_types_xdata)), __typeof__(&(v4l2_control_types_xdata)[0])))]) * 0)),
 .type = XT_SORTED,
 .flags_mask = 0
  | ((unsigned) (V4L2_CTRL_TYPE_INTEGER))
  | ((unsigned) (V4L2_CTRL_TYPE_BOOLEAN))
  | ((unsigned) (V4L2_CTRL_TYPE_MENU))
  | ((unsigned) (V4L2_CTRL_TYPE_BUTTON))
  | ((unsigned) (V4L2_CTRL_TYPE_INTEGER64))
  | ((unsigned) (V4L2_CTRL_TYPE_CTRL_CLASS))
  | ((unsigned) (V4L2_CTRL_TYPE_STRING))
  | ((unsigned) (V4L2_CTRL_TYPE_BITMASK))
  | ((unsigned) (V4L2_CTRL_TYPE_INTEGER_MENU))
  | ((unsigned) (V4L2_CTRL_TYPE_U8))
  | ((unsigned) (V4L2_CTRL_TYPE_U16))
  | ((unsigned) (V4L2_CTRL_TYPE_U32))
  | ((unsigned) (V4L2_CTRL_TYPE_AREA))
  | ((unsigned) (V4L2_CTRL_TYPE_HDR10_CLL_INFO))
  | ((unsigned) (V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_SPS))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_PPS))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_SCALING_MATRIX))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_SLICE_PARAMS))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_DECODE_PARAMS))
  | ((unsigned) (V4L2_CTRL_TYPE_H264_PRED_WEIGHTS))
  | ((unsigned) (V4L2_CTRL_TYPE_FWHT_PARAMS))
  | ((unsigned) (V4L2_CTRL_TYPE_VP8_FRAME))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CTRL_TYPE_INTEGER")
  + sizeof("V4L2_CTRL_TYPE_BOOLEAN")
  + sizeof("V4L2_CTRL_TYPE_MENU")
  + sizeof("V4L2_CTRL_TYPE_BUTTON")
  + sizeof("V4L2_CTRL_TYPE_INTEGER64")
  + sizeof("V4L2_CTRL_TYPE_CTRL_CLASS")
  + sizeof("V4L2_CTRL_TYPE_STRING")
  + sizeof("V4L2_CTRL_TYPE_BITMASK")
  + sizeof("V4L2_CTRL_TYPE_INTEGER_MENU")
  + sizeof("V4L2_CTRL_TYPE_U8")
  + sizeof("V4L2_CTRL_TYPE_U16")
  + sizeof("V4L2_CTRL_TYPE_U32")
  + sizeof("V4L2_CTRL_TYPE_AREA")
  + sizeof("V4L2_CTRL_TYPE_HDR10_CLL_INFO")
  + sizeof("V4L2_CTRL_TYPE_HDR10_MASTERING_DISPLAY")
  + sizeof("V4L2_CTRL_TYPE_H264_SPS")
  + sizeof("V4L2_CTRL_TYPE_H264_PPS")
  + sizeof("V4L2_CTRL_TYPE_H264_SCALING_MATRIX")
  + sizeof("V4L2_CTRL_TYPE_H264_SLICE_PARAMS")
  + sizeof("V4L2_CTRL_TYPE_H264_DECODE_PARAMS")
  + sizeof("V4L2_CTRL_TYPE_H264_PRED_WEIGHTS")
  + sizeof("V4L2_CTRL_TYPE_FWHT_PARAMS")
  + sizeof("V4L2_CTRL_TYPE_VP8_FRAME")
  ,
} };


static const struct xlat_data v4l2_control_flags_xdata[] = {
 { (unsigned)(0x0001), "V4L2_CTRL_FLAG_DISABLED" },
 { (unsigned)(0x0002), "V4L2_CTRL_FLAG_GRABBED" },
 { (unsigned)(0x0004), "V4L2_CTRL_FLAG_READ_ONLY" },
 { (unsigned)(0x0008), "V4L2_CTRL_FLAG_UPDATE" },
 { (unsigned)(0x0010), "V4L2_CTRL_FLAG_INACTIVE" },
 { (unsigned)(0x0020), "V4L2_CTRL_FLAG_SLIDER" },
 { (unsigned)(0x0040), "V4L2_CTRL_FLAG_WRITE_ONLY" },
 { (unsigned)(0x0080), "V4L2_CTRL_FLAG_VOLATILE" },
 { (unsigned)(0x0100), "V4L2_CTRL_FLAG_HAS_PAYLOAD" },
 { (unsigned)(0x0200), "V4L2_CTRL_FLAG_EXECUTE_ON_WRITE" },
 { (unsigned)(0x0400), "V4L2_CTRL_FLAG_MODIFY_LAYOUT" },
};
const struct xlat v4l2_control_flags[1] = { {
 .data = v4l2_control_flags_xdata,
 .size = (sizeof(v4l2_control_flags_xdata) / sizeof((v4l2_control_flags_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_control_flags_xdata)), __typeof__(&(v4l2_control_flags_xdata)[0])))]) * 0)),
 .type = XT_NORMAL,
 .flags_mask = 0
  | ((unsigned) (0x0001))
  | ((unsigned) (0x0002))
  | ((unsigned) (0x0004))
  | ((unsigned) (0x0008))
  | ((unsigned) (0x0010))
  | ((unsigned) (0x0020))
  | ((unsigned) (0x0040))
  | ((unsigned) (0x0080))
  | ((unsigned) (0x0100))
  | ((unsigned) (0x0200))
  | ((unsigned) (0x0400))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_CTRL_FLAG_DISABLED")
  + sizeof("V4L2_CTRL_FLAG_GRABBED")
  + sizeof("V4L2_CTRL_FLAG_READ_ONLY")
  + sizeof("V4L2_CTRL_FLAG_UPDATE")
  + sizeof("V4L2_CTRL_FLAG_INACTIVE")
  + sizeof("V4L2_CTRL_FLAG_SLIDER")
  + sizeof("V4L2_CTRL_FLAG_WRITE_ONLY")
  + sizeof("V4L2_CTRL_FLAG_VOLATILE")
  + sizeof("V4L2_CTRL_FLAG_HAS_PAYLOAD")
  + sizeof("V4L2_CTRL_FLAG_EXECUTE_ON_WRITE")
  + sizeof("V4L2_CTRL_FLAG_MODIFY_LAYOUT")
  ,
} };

static int
print_v4l2_queryctrl(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_queryctrl c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  set_tcb_priv_ulong(tcp, c.id);
  tprint_struct_begin();
  do { tprints_field_name("id"); print_v4l2_cid((c).id, (1)); } while (0);
  return 0;
 }
 if (((tcp)->u_error != 0) || umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c)) < 0) {
  tprint_struct_end();
  return 0200;
 }
 unsigned long entry_id = get_tcb_priv_ulong(tcp);
 if (c.id != entry_id) {
  tprint_value_changed();
  print_v4l2_cid(c.id, 0);
 }
 tprint_struct_next();
 do { tprints_field_name("type"); printxval64((v4l2_control_types), (sizeof((c).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).type) : sizeof((c).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).type) : sizeof((c).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).type) : sizeof((c).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).type) : (unsigned long long) ((c).type)), ("V4L2_CTRL_TYPE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("name"); print_quoted_cstring((const char *) (c).name, sizeof((c).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).name)), __typeof__(&((c).name)[0])))]) * 0)); } while (0);
 if (!((tcp)->qual_flg & 0x002)) {
  tprint_struct_next();
  do { tprints_field_name("minimum"); tprintf_string("%lld", (sizeof((c).minimum) == sizeof(char) ? (long long) (char) ((c).minimum) : sizeof((c).minimum) == sizeof(short) ? (long long) (short) ((c).minimum) : sizeof((c).minimum) == sizeof(int) ? (long long) (int) ((c).minimum) : sizeof((c).minimum) == sizeof(long) ? (long long) (long) ((c).minimum) : (long long) ((c).minimum))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("maximum"); tprintf_string("%lld", (sizeof((c).maximum) == sizeof(char) ? (long long) (char) ((c).maximum) : sizeof((c).maximum) == sizeof(short) ? (long long) (short) ((c).maximum) : sizeof((c).maximum) == sizeof(int) ? (long long) (int) ((c).maximum) : sizeof((c).maximum) == sizeof(long) ? (long long) (long) ((c).maximum) : (long long) ((c).maximum))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("step"); tprintf_string("%lld", (sizeof((c).step) == sizeof(char) ? (long long) (char) ((c).step) : sizeof((c).step) == sizeof(short) ? (long long) (short) ((c).step) : sizeof((c).step) == sizeof(int) ? (long long) (int) ((c).step) : sizeof((c).step) == sizeof(long) ? (long long) (long) ((c).step) : (long long) ((c).step))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("default_value"); tprintf_string("%lld", (sizeof((c).default_value) == sizeof(char) ? (long long) (char) ((c).default_value) : sizeof((c).default_value) == sizeof(short) ? (long long) (short) ((c).default_value) : sizeof((c).default_value) == sizeof(int) ? (long long) (int) ((c).default_value) : sizeof((c).default_value) == sizeof(long) ? (long long) (long) ((c).default_value) : (long long) ((c).default_value))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((v4l2_control_flags), (sizeof((c).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).flags) : sizeof((c).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).flags) : sizeof((c).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).flags) : sizeof((c).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).flags) : (unsigned long long) ((c).flags)), ("V4L2_CTRL_FLAG_???")); } while (0);
  if (!is_filled((const char *) (c.reserved), 0, sizeof(c.reserved) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((c.reserved)), __typeof__(&(c.reserved)[0])))]) * 0))) {
   tprint_struct_next();
   do { tprints_field_name("reserved"); print_local_array_ex(((tcp)), ((c).reserved), (sizeof((c).reserved) / sizeof(((c).reserved)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).reserved)), __typeof__(&((c).reserved)[0])))]) * 0)), sizeof(((c).reserved)[0]), ((print_xint_array_member)), ((void *)0), 0, ((void *)0), ((void *)0)); } while (0);
  }
 } else {
  tprint_struct_next();
  tprint_more_data_follows();
 }
 tprint_struct_end();
 return 0200;
}
static int
print_v4l2_query_ext_ctrl(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_query_ext_ctrl c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  set_tcb_priv_ulong(tcp, c.id);
  tprint_struct_begin();
  do { tprints_field_name("id"); print_v4l2_cid((c).id, (1)); } while (0);
  return 0;
 }
 if (((tcp)->u_error != 0) || umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c)) < 0) {
  tprint_struct_end();
  return 0200;
 }
 unsigned long entry_id = get_tcb_priv_ulong(tcp);
 if (c.id != entry_id) {
  tprint_value_changed();
  print_v4l2_cid(c.id, 0);
 }
 tprint_struct_next();
 do { tprints_field_name("type"); printxval64((v4l2_control_types), (sizeof((c).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).type) : sizeof((c).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).type) : sizeof((c).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).type) : sizeof((c).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).type) : (unsigned long long) ((c).type)), ("V4L2_CTRL_TYPE_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("name"); print_quoted_cstring((const char *) (c).name, sizeof((c).name) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).name)), __typeof__(&((c).name)[0])))]) * 0)); } while (0);
 if (!((tcp)->qual_flg & 0x002)) {
  tprint_struct_next();
  do { tprints_field_name("minimum"); tprintf_string("%lld", (sizeof((c).minimum) == sizeof(char) ? (long long) (char) ((c).minimum) : sizeof((c).minimum) == sizeof(short) ? (long long) (short) ((c).minimum) : sizeof((c).minimum) == sizeof(int) ? (long long) (int) ((c).minimum) : sizeof((c).minimum) == sizeof(long) ? (long long) (long) ((c).minimum) : (long long) ((c).minimum))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("maximum"); tprintf_string("%lld", (sizeof((c).maximum) == sizeof(char) ? (long long) (char) ((c).maximum) : sizeof((c).maximum) == sizeof(short) ? (long long) (short) ((c).maximum) : sizeof((c).maximum) == sizeof(int) ? (long long) (int) ((c).maximum) : sizeof((c).maximum) == sizeof(long) ? (long long) (long) ((c).maximum) : (long long) ((c).maximum))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("step"); tprintf_string("%llu", (sizeof((c).step) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).step) : sizeof((c).step) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).step) : sizeof((c).step) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).step) : sizeof((c).step) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).step) : (unsigned long long) ((c).step))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("default_value"); tprintf_string("%lld", (sizeof((c).default_value) == sizeof(char) ? (long long) (char) ((c).default_value) : sizeof((c).default_value) == sizeof(short) ? (long long) (short) ((c).default_value) : sizeof((c).default_value) == sizeof(int) ? (long long) (int) ((c).default_value) : sizeof((c).default_value) == sizeof(long) ? (long long) (long) ((c).default_value) : (long long) ((c).default_value))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("flags"); printflags64((v4l2_control_flags), (sizeof((c).flags) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).flags) : sizeof((c).flags) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).flags) : sizeof((c).flags) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).flags) : sizeof((c).flags) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).flags) : (unsigned long long) ((c).flags)), ("V4L2_CTRL_FLAG_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("elem_size"); tprintf_string("%llu", (sizeof((c).elem_size) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).elem_size) : sizeof((c).elem_size) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).elem_size) : sizeof((c).elem_size) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).elem_size) : sizeof((c).elem_size) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).elem_size) : (unsigned long long) ((c).elem_size))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("elems"); tprintf_string("%llu", (sizeof((c).elems) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).elems) : sizeof((c).elems) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).elems) : sizeof((c).elems) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).elems) : sizeof((c).elems) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).elems) : (unsigned long long) ((c).elems))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("nr_of_dims"); tprintf_string("%llu", (sizeof((c).nr_of_dims) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).nr_of_dims) : sizeof((c).nr_of_dims) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).nr_of_dims) : sizeof((c).nr_of_dims) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).nr_of_dims) : sizeof((c).nr_of_dims) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).nr_of_dims) : (unsigned long long) ((c).nr_of_dims))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("dims"); print_local_array_ex(((tcp)), ((c).dims), ((((((((c.nr_of_dims))) > (0)) ? (((c.nr_of_dims))) : (0))) < ((typeof((c.nr_of_dims))) (sizeof((c).dims) / sizeof(((c).dims)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).dims)), __typeof__(&((c).dims)[0])))]) * 0)))) ? ((((((c.nr_of_dims))) > (0)) ? (((c.nr_of_dims))) : (0))) : ((typeof((c.nr_of_dims))) (sizeof((c).dims) / sizeof(((c).dims)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).dims)), __typeof__(&((c).dims)[0])))]) * 0)))), sizeof(((c).dims)[0]), ((print_uint_array_member)), ((void *)0), 0, ((void *)0), ((void *)0)); } while (0);
  if (!is_filled((const char *) (c.reserved), 0, sizeof(c.reserved) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((c.reserved)), __typeof__(&(c.reserved)[0])))]) * 0))) {
   tprint_struct_next();
   do { tprints_field_name("reserved"); print_local_array_ex(((tcp)), ((c).reserved), (sizeof((c).reserved) / sizeof(((c).reserved)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__(((c).reserved)), __typeof__(&((c).reserved)[0])))]) * 0)), sizeof(((c).reserved)[0]), ((print_xint_array_member)), ((void *)0), 0, ((void *)0), ((void *)0)); } while (0);
  }
 } else {
  tprint_struct_next();
  tprint_more_data_follows();
 }
 tprint_struct_end();
 return 0200;
}
static int
print_v4l2_cropcap(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_cropcap c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((c).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).type) : sizeof((c).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).type) : sizeof((c).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).type) : sizeof((c).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).type) : (unsigned long long) ((c).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c))) {
  tprint_struct_next();
  do { tprints_field_name("bounds"); (print_v4l2_rect)(&((c).bounds)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("defrect"); (print_v4l2_rect)(&((c).defrect)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("pixelaspect"); tprintf_string("%u/%u", (c).pixelaspect.numerator, (c).pixelaspect.denominator); } while (0);
 }
 tprint_struct_end();
 return 0200;
}
static int
print_v4l2_crop(struct tcb *const tcp, const kernel_ulong_t arg,
  const _Bool is_get)
{
 struct v4l2_crop c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((c).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).type) : sizeof((c).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).type) : sizeof((c).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).type) : sizeof((c).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).type) : (unsigned long long) ((c).type)), ("V4L2_BUF_TYPE_???")); } while (0);
  if (is_get)
   return 0;
  tprint_struct_next();
  do { tprints_field_name("c"); (print_v4l2_rect)(&((c).c)); } while (0);
 } else {
  if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c))) {
   tprint_struct_next();
   do { tprints_field_name("c"); (print_v4l2_rect)(&((c).c)); } while (0);
  }
 }
 tprint_struct_end();
 return 0200;
}
static _Bool
print_v4l2_ext_control(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
 const struct_v4l2_ext_control *p = elem_buf;
 tprint_struct_begin();
 do { tprints_field_name("id"); printxval64((v4l2_control_ids), (sizeof((*p).id) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).id) : sizeof((*p).id) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).id) : sizeof((*p).id) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).id) : sizeof((*p).id) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).id) : (unsigned long long) ((*p).id)), ("V4L2_CID_???")); } while (0);
 tprint_struct_next();
 do { tprints_field_name("size"); tprintf_string("%llu", (sizeof((*p).size) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).size) : sizeof((*p).size) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).size) : sizeof((*p).size) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).size) : sizeof((*p).size) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).size) : (unsigned long long) ((*p).size))); } while (0);
 if (p->size > 0) {
  tprint_struct_next();
  tprints_field_name("string");
  printstrn(tcp, ((kernel_ulong_t) (unsigned long) (p->string)), p->size);
 } else {
  tprint_struct_next();
  do { tprints_field_name("value"); tprintf_string("%lld", (sizeof((*p).value) == sizeof(char) ? (long long) (char) ((*p).value) : sizeof((*p).value) == sizeof(short) ? (long long) (short) ((*p).value) : sizeof((*p).value) == sizeof(int) ? (long long) (int) ((*p).value) : sizeof((*p).value) == sizeof(long) ? (long long) (long) ((*p).value) : (long long) ((*p).value))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("value64"); tprintf_string("%lld", (sizeof((*p).value64) == sizeof(char) ? (long long) (char) ((*p).value64) : sizeof((*p).value64) == sizeof(short) ? (long long) (short) ((*p).value64) : sizeof((*p).value64) == sizeof(int) ? (long long) (int) ((*p).value64) : sizeof((*p).value64) == sizeof(long) ? (long long) (long) ((*p).value64) : (long long) ((*p).value64))); } while (0);
 }
 tprint_struct_end();
 return 1;
}
static int
print_v4l2_ext_controls(struct tcb *const tcp, const kernel_ulong_t arg,
   const _Bool is_get)
{
 struct_v4l2_ext_controls c;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&c)), (void *) (&c)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("ctrl_class"); printxval64((v4l2_control_classes), (sizeof((c).ctrl_class) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).ctrl_class) : sizeof((c).ctrl_class) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).ctrl_class) : sizeof((c).ctrl_class) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).ctrl_class) : sizeof((c).ctrl_class) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).ctrl_class) : (unsigned long long) ((c).ctrl_class)), ("V4L2_CTRL_CLASS_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("count"); tprintf_string("%llu", (sizeof((c).count) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).count) : sizeof((c).count) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).count) : sizeof((c).count) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).count) : sizeof((c).count) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).count) : (unsigned long long) ((c).count))); } while (0);
  if (!c.count) {
   tprint_struct_end();
   return 0200;
  }
  if (is_get)
   return 0;
  tprint_struct_next();
 } else {
  if (umoven((tcp), (arg), sizeof(*(&c)), (void *) (&c)) < 0) {
   tprint_struct_end();
   return 0200;
  }
  if (is_get) {
   tprint_struct_next();
  } else {
   tprint_struct_end();
   tprint_value_changed();
   tprint_struct_begin();
  }
 }
 tprints_field_name("controls");
 struct_v4l2_ext_control ctrl;
 _Bool fail = !print_array(tcp, ((kernel_ulong_t) (unsigned long) (c.controls)), c.count,
     &ctrl, sizeof(ctrl),
     tfetch_mem_ignore_syserror,
     print_v4l2_ext_control, 0);
 if (((tcp)->flags & 0x04) && ((tcp)->u_error != 0)) {
  tprint_struct_next();
  do { tprints_field_name("error_idx"); tprintf_string("%llu", (sizeof((c).error_idx) == sizeof(char) ? (unsigned long long) (unsigned char) ((c).error_idx) : sizeof((c).error_idx) == sizeof(short) ? (unsigned long long) (unsigned short) ((c).error_idx) : sizeof((c).error_idx) == sizeof(int) ? (unsigned long long) (unsigned int) ((c).error_idx) : sizeof((c).error_idx) == sizeof(long) ? (unsigned long long) (unsigned long) ((c).error_idx) : (unsigned long long) ((c).error_idx))); } while (0);
 }
 if (((tcp)->flags & 0x04) || fail) {
  tprint_struct_end();
  return 0200;
 }
 return 0;
}

static const struct xlat_data v4l2_framesize_types_xdata[] = {
 [V4L2_FRMSIZE_TYPE_DISCRETE] = { (unsigned)(V4L2_FRMSIZE_TYPE_DISCRETE), "V4L2_FRMSIZE_TYPE_DISCRETE" },
 [V4L2_FRMSIZE_TYPE_CONTINUOUS] = { (unsigned)(V4L2_FRMSIZE_TYPE_CONTINUOUS), "V4L2_FRMSIZE_TYPE_CONTINUOUS" },
 [V4L2_FRMSIZE_TYPE_STEPWISE] = { (unsigned)(V4L2_FRMSIZE_TYPE_STEPWISE), "V4L2_FRMSIZE_TYPE_STEPWISE" },
};
const struct xlat v4l2_framesize_types[1] = { {
 .data = v4l2_framesize_types_xdata,
 .size = (sizeof(v4l2_framesize_types_xdata) / sizeof((v4l2_framesize_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_framesize_types_xdata)), __typeof__(&(v4l2_framesize_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_FRMSIZE_TYPE_DISCRETE))
  | ((unsigned) (V4L2_FRMSIZE_TYPE_CONTINUOUS))
  | ((unsigned) (V4L2_FRMSIZE_TYPE_STEPWISE))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_FRMSIZE_TYPE_DISCRETE")
  + sizeof("V4L2_FRMSIZE_TYPE_CONTINUOUS")
  + sizeof("V4L2_FRMSIZE_TYPE_STEPWISE")
  ,
} };

static void
print_v4l2_frmsize_discrete(const struct v4l2_frmsize_discrete *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("width"); tprintf_string("%llu", (sizeof((*p).width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).width) : sizeof((*p).width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).width) : sizeof((*p).width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).width) : sizeof((*p).width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).width) : (unsigned long long) ((*p).width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("height"); tprintf_string("%llu", (sizeof((*p).height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).height) : sizeof((*p).height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).height) : sizeof((*p).height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).height) : sizeof((*p).height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).height) : (unsigned long long) ((*p).height))); } while (0);
 tprint_struct_end();
}
static void
print_v4l2_frmsize_stepwise(const struct v4l2_frmsize_stepwise *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("min_width"); tprintf_string("%llu", (sizeof((*p).min_width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).min_width) : sizeof((*p).min_width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).min_width) : sizeof((*p).min_width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).min_width) : sizeof((*p).min_width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).min_width) : (unsigned long long) ((*p).min_width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("max_width"); tprintf_string("%llu", (sizeof((*p).max_width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).max_width) : sizeof((*p).max_width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).max_width) : sizeof((*p).max_width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).max_width) : sizeof((*p).max_width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).max_width) : (unsigned long long) ((*p).max_width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("step_width"); tprintf_string("%llu", (sizeof((*p).step_width) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).step_width) : sizeof((*p).step_width) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).step_width) : sizeof((*p).step_width) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).step_width) : sizeof((*p).step_width) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).step_width) : (unsigned long long) ((*p).step_width))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("min_height"); tprintf_string("%llu", (sizeof((*p).min_height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).min_height) : sizeof((*p).min_height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).min_height) : sizeof((*p).min_height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).min_height) : sizeof((*p).min_height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).min_height) : (unsigned long long) ((*p).min_height))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("max_height"); tprintf_string("%llu", (sizeof((*p).max_height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).max_height) : sizeof((*p).max_height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).max_height) : sizeof((*p).max_height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).max_height) : sizeof((*p).max_height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).max_height) : (unsigned long long) ((*p).max_height))); } while (0);
 tprint_struct_next();
 do { tprints_field_name("step_height"); tprintf_string("%llu", (sizeof((*p).step_height) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).step_height) : sizeof((*p).step_height) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).step_height) : sizeof((*p).step_height) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).step_height) : sizeof((*p).step_height) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).step_height) : (unsigned long long) ((*p).step_height))); } while (0);
 tprint_struct_end();
}
static int
print_v4l2_frmsizeenum(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_frmsizeenum s;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&s)), (void *) (&s)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((s).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((s).index) : sizeof((s).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((s).index) : sizeof((s).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((s).index) : sizeof((s).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((s).index) : (unsigned long long) ((s).index))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("pixel_format"); print_pixelformat((s).pixel_format, (v4l2_pix_fmts)); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&s)), (void *) (&s))) {
  tprint_struct_next();
  do { tprints_field_name("type"); printxval64((v4l2_framesize_types), (sizeof((s).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((s).type) : sizeof((s).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((s).type) : sizeof((s).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((s).type) : sizeof((s).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((s).type) : (unsigned long long) ((s).type)), ("V4L2_FRMSIZE_TYPE_???")); } while (0);
  switch (s.type) {
  case V4L2_FRMSIZE_TYPE_DISCRETE:
   tprint_struct_next();
   do { tprints_field_name("discrete"); print_v4l2_frmsize_discrete(&((s).discrete)); } while (0);
   break;
  case V4L2_FRMSIZE_TYPE_STEPWISE:
   tprint_struct_next();
   do { tprints_field_name("stepwise"); print_v4l2_frmsize_stepwise(&((s).stepwise)); } while (0);
   break;
  }
 }
 tprint_struct_end();
 return 0200;
}

static const struct xlat_data v4l2_frameinterval_types_xdata[] = {
 [V4L2_FRMIVAL_TYPE_DISCRETE] = { (unsigned)(V4L2_FRMIVAL_TYPE_DISCRETE), "V4L2_FRMIVAL_TYPE_DISCRETE" },
 [V4L2_FRMIVAL_TYPE_CONTINUOUS] = { (unsigned)(V4L2_FRMIVAL_TYPE_CONTINUOUS), "V4L2_FRMIVAL_TYPE_CONTINUOUS" },
 [V4L2_FRMIVAL_TYPE_STEPWISE] = { (unsigned)(V4L2_FRMIVAL_TYPE_STEPWISE), "V4L2_FRMIVAL_TYPE_STEPWISE" },
};
const struct xlat v4l2_frameinterval_types[1] = { {
 .data = v4l2_frameinterval_types_xdata,
 .size = (sizeof(v4l2_frameinterval_types_xdata) / sizeof((v4l2_frameinterval_types_xdata)[0]) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((v4l2_frameinterval_types_xdata)), __typeof__(&(v4l2_frameinterval_types_xdata)[0])))]) * 0)),
 .type = XT_INDEXED,
 .flags_mask = 0
  | ((unsigned) (V4L2_FRMIVAL_TYPE_DISCRETE))
  | ((unsigned) (V4L2_FRMIVAL_TYPE_CONTINUOUS))
  | ((unsigned) (V4L2_FRMIVAL_TYPE_STEPWISE))
  ,
 .flags_strsz = 0
  + sizeof("V4L2_FRMIVAL_TYPE_DISCRETE")
  + sizeof("V4L2_FRMIVAL_TYPE_CONTINUOUS")
  + sizeof("V4L2_FRMIVAL_TYPE_STEPWISE")
  ,
} };

static void
print_v4l2_frmival_stepwise(const struct v4l2_frmival_stepwise *const p)
{
 tprint_struct_begin();
 do { tprints_field_name("min"); tprintf_string("%u/%u", (*p).min.numerator, (*p).min.denominator); } while (0);
 tprint_struct_next();
 do { tprints_field_name("max"); tprintf_string("%u/%u", (*p).max.numerator, (*p).max.denominator); } while (0);
 tprint_struct_next();
 do { tprints_field_name("step"); tprintf_string("%u/%u", (*p).step.numerator, (*p).step.denominator); } while (0);
 tprint_struct_end();
}
static int
print_v4l2_frmivalenum(struct tcb *const tcp, const kernel_ulong_t arg)
{
 struct v4l2_frmivalenum f;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&f)), (void *) (&f)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("index"); tprintf_string("%llu", (sizeof((f).index) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).index) : sizeof((f).index) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).index) : sizeof((f).index) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).index) : sizeof((f).index) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).index) : (unsigned long long) ((f).index))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("pixel_format"); print_pixelformat((f).pixel_format, (v4l2_pix_fmts)); } while (0);
  tprint_struct_next();
  do { tprints_field_name("width"); tprintf_string("%llu", (sizeof((f).width) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).width) : sizeof((f).width) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).width) : sizeof((f).width) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).width) : sizeof((f).width) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).width) : (unsigned long long) ((f).width))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("height"); tprintf_string("%llu", (sizeof((f).height) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).height) : sizeof((f).height) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).height) : sizeof((f).height) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).height) : sizeof((f).height) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).height) : (unsigned long long) ((f).height))); } while (0);
  return 0;
 }
 if (!((tcp)->u_error != 0) && !umoven((tcp), (arg), sizeof(*(&f)), (void *) (&f))) {
  tprint_struct_next();
  do { tprints_field_name("type"); printxval64((v4l2_frameinterval_types), (sizeof((f).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((f).type) : sizeof((f).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((f).type) : sizeof((f).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((f).type) : sizeof((f).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((f).type) : (unsigned long long) ((f).type)), ("V4L2_FRMIVAL_TYPE_???")); } while (0);
  switch (f.type) {
  case V4L2_FRMIVAL_TYPE_DISCRETE:
   tprint_struct_next();
   do { tprints_field_name("discrete"); tprintf_string("%u/%u", (f).discrete.numerator, (f).discrete.denominator); } while (0);
   break;
  case V4L2_FRMIVAL_TYPE_STEPWISE:
  case V4L2_FRMSIZE_TYPE_CONTINUOUS:
   tprint_struct_next();
   do { tprints_field_name("stepwise"); print_v4l2_frmival_stepwise(&((f).stepwise)); } while (0);
   break;
  }
 }
 tprint_struct_end();
 return 0200;
}
static void
print_v4l2_create_buffers_format(const typeof(((struct_v4l2_create_buffers *)0)->format) *const p,
     struct tcb *const tcp)
{
 tprint_struct_begin();
 do { tprints_field_name("type"); printxval64((v4l2_buf_types), (sizeof((*p).type) == sizeof(char) ? (unsigned long long) (unsigned char) ((*p).type) : sizeof((*p).type) == sizeof(short) ? (unsigned long long) (unsigned short) ((*p).type) : sizeof((*p).type) == sizeof(int) ? (unsigned long long) (unsigned int) ((*p).type) : sizeof((*p).type) == sizeof(long) ? (unsigned long long) (unsigned long) ((*p).type) : (unsigned long long) ((*p).type)), ("V4L2_BUF_TYPE_???")); } while (0);
 print_v4l2_format_fmt(tcp, tprint_struct_next,
         (const struct_v4l2_format *) p);
 tprint_struct_end();
}
static int
print_v4l2_create_buffers(struct tcb *const tcp, const kernel_ulong_t arg)
{
 static const char fmt[] = "{index=%u, count=%u}";
 static char outstr[sizeof(fmt) + sizeof(int) * 6];
 struct_v4l2_create_buffers b;
 if ((!((tcp)->flags & 0x04))) {
  tprint_arg_next();
  if (umoven_or_printaddr((tcp), (arg), sizeof(*(&b)), (void *) (&b)))
   return 0200;
  tprint_struct_begin();
  do { tprints_field_name("count"); tprintf_string("%llu", (sizeof((b).count) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).count) : sizeof((b).count) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).count) : sizeof((b).count) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).count) : sizeof((b).count) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).count) : (unsigned long long) ((b).count))); } while (0);
  tprint_struct_next();
  do { tprints_field_name("memory"); printxval64((v4l2_memories), (sizeof((b).memory) == sizeof(char) ? (unsigned long long) (unsigned char) ((b).memory) : sizeof((b).memory) == sizeof(short) ? (unsigned long long) (unsigned short) ((b).memory) : sizeof((b).memory) == sizeof(int) ? (unsigned long long) (unsigned int) ((b).memory) : sizeof((b).memory) == sizeof(long) ? (unsigned long long) (unsigned long) ((b).memory) : (unsigned long long) ((b).memory)), ("V4L2_MEMORY_???")); } while (0);
  tprint_struct_next();
  do { tprints_field_name("format"); (print_v4l2_create_buffers_format)(&((b).format), tcp); } while (0);
  tprint_struct_end();
  return 0;
 }
 if (((tcp)->u_error != 0) || umoven((tcp), (arg), sizeof(*(&b)), (void *) (&b)))
  return 0200;
 xsnprintf_(((outstr)), (sizeof(outstr) + (sizeof(int[-1 + 2 * !!(!__builtin_types_compatible_p(__typeof__((outstr)), __typeof__(&(outstr)[0])))]) * 0)), __func__, "(fmt)" ", " "b.index, b.count", ((fmt)), b.index, b.count);
 tcp->auxstr = outstr;
 return 0200 | 020;
}
MPERS_PRINTER_DECL(int, v4l2_ioctl, struct tcb *const tcp, const unsigned int code, const kernel_ulong_t arg)
{
 if (!((tcp)->qual_flg & 0x004))
  return 0100;
 switch (code) {
 case (((2U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((0)) << 0) | ((((sizeof(struct v4l2_capability)))) << ((0 +8)+8))):
  return print_v4l2_capability(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((2)) << 0) | ((((sizeof(struct v4l2_fmtdesc)))) << ((0 +8)+8))):
  return print_v4l2_fmtdesc(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((4)) << 0) | ((((sizeof(struct v4l2_format)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((5)) << 0) | ((((sizeof(struct v4l2_format)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((64)) << 0) | ((((sizeof(struct v4l2_format)))) << ((0 +8)+8))):
  return print_v4l2_format(tcp, arg, code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((4)) << 0) | ((((sizeof(struct v4l2_format)))) << ((0 +8)+8))));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((8)) << 0) | ((((sizeof(struct v4l2_requestbuffers)))) << ((0 +8)+8))):
  return print_v4l2_requestbuffers(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((9)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((15)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((17)) << 0) | ((((sizeof(kernel_v4l2_buffer_t)))) << ((0 +8)+8))):
  return print_v4l2_buffer(tcp, code, arg);
 case (((2U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((10)) << 0) | ((((sizeof(struct v4l2_framebuffer)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04)))
   return 0;
  __attribute__((__fallthrough__));
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((11)) << 0) | ((((sizeof(struct v4l2_framebuffer)))) << ((0 +8)+8))):
  return print_v4l2_framebuffer(tcp, arg);
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((18)) << 0) | ((((sizeof(int)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((19)) << 0) | ((((sizeof(int)))) << ((0 +8)+8))):
  return print_v4l2_buf_type(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((21)) << 0) | ((((sizeof(struct v4l2_streamparm)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((22)) << 0) | ((((sizeof(struct v4l2_streamparm)))) << ((0 +8)+8))):
  return print_v4l2_streamparm(tcp, arg, code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((21)) << 0) | ((((sizeof(struct v4l2_streamparm)))) << ((0 +8)+8))));
 case (((2U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((23)) << 0) | ((((sizeof(v4l2_std_id)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04)))
   return 0;
  __attribute__((__fallthrough__));
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((24)) << 0) | ((((sizeof(v4l2_std_id)))) << ((0 +8)+8))):
  tprint_arg_next();
  printnum_int64(tcp, arg, "%#" "l" "x");
  break;
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((25)) << 0) | ((((sizeof(struct v4l2_standard)))) << ((0 +8)+8))):
  return print_v4l2_standard(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((26)) << 0) | ((((sizeof(struct v4l2_input)))) << ((0 +8)+8))):
  return print_v4l2_input(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((27)) << 0) | ((((sizeof(struct v4l2_control)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((28)) << 0) | ((((sizeof(struct v4l2_control)))) << ((0 +8)+8))):
  return print_v4l2_control(tcp, arg, code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((27)) << 0) | ((((sizeof(struct v4l2_control)))) << ((0 +8)+8))));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((29)) << 0) | ((((sizeof(struct v4l2_tuner)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((30)) << 0) | ((((sizeof(struct v4l2_tuner)))) << ((0 +8)+8))):
  return print_v4l2_tuner(tcp, arg, code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((29)) << 0) | ((((sizeof(struct v4l2_tuner)))) << ((0 +8)+8))));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((36)) << 0) | ((((sizeof(struct v4l2_queryctrl)))) << ((0 +8)+8))):
  return print_v4l2_queryctrl(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((103)) << 0) | ((((sizeof(struct v4l2_query_ext_ctrl)))) << ((0 +8)+8))):
  return print_v4l2_query_ext_ctrl(tcp, arg);
 case (((2U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((38)) << 0) | ((((sizeof(int)))) << ((0 +8)+8))):
  if ((!((tcp)->flags & 0x04)))
   return 0;
  __attribute__((__fallthrough__));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((39)) << 0) | ((((sizeof(int)))) << ((0 +8)+8))):
  tprint_arg_next();
  printnum_int(tcp, arg, "%u");
  break;
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((58)) << 0) | ((((sizeof(struct v4l2_cropcap)))) << ((0 +8)+8))):
  return print_v4l2_cropcap(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((59)) << 0) | ((((sizeof(struct v4l2_crop)))) << ((0 +8)+8))):
 case (((1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((60)) << 0) | ((((sizeof(struct v4l2_crop)))) << ((0 +8)+8))):
  return print_v4l2_crop(tcp, arg, code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((59)) << 0) | ((((sizeof(struct v4l2_crop)))) << ((0 +8)+8))));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((72)) << 0) | ((((sizeof(struct v4l2_ext_controls)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((73)) << 0) | ((((sizeof(struct v4l2_ext_controls)))) << ((0 +8)+8))):
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((71)) << 0) | ((((sizeof(struct v4l2_ext_controls)))) << ((0 +8)+8))):
  return print_v4l2_ext_controls(tcp, arg,
            code == (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((71)) << 0) | ((((sizeof(struct v4l2_ext_controls)))) << ((0 +8)+8))));
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((74)) << 0) | ((((sizeof(struct v4l2_frmsizeenum)))) << ((0 +8)+8))):
  return print_v4l2_frmsizeenum(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((75)) << 0) | ((((sizeof(struct v4l2_frmivalenum)))) << ((0 +8)+8))):
  return print_v4l2_frmivalenum(tcp, arg);
 case (((2U|1U) << (((0 +8)+8)+14)) | ((('V')) << (0 +8)) | (((92)) << 0) | ((((sizeof(struct v4l2_create_buffers)))) << ((0 +8)+8))):
  return print_v4l2_create_buffers(tcp, arg);
 default:
  return 0100;
 }
 return 0200;
}

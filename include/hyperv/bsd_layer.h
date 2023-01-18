#ifndef __BSD_LAYER_H__
#define __BSD_LAYER_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <uk/arch/atomic.h>
#include <uk/assert.h>
#include <uk/errptr.h>
#include <uk/mutex.h>
#include <uk/wait.h>
#include <uk/wait_types.h>
#include <hyperv-x86/delay.h>

#define PAGE_SIZE __PAGE_SIZE
#define PAGE_SHIFT __PAGE_SHIFT
#define PAGE_MASK __PAGE_MASK

#define MAXCPU 1
#define curcpu 0
#define mp_ncpus 1

#define curcpu 0
#define bootverbose 1

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

//typedef bool boolean_t;

#define device_printf(dev, fmt, ...) uk_pr_info( "%p: " fmt, &dev, ##__VA_ARGS__ )
#define panic( ... ) UK_CRASH( __VA_ARGS__ )

#define __printflike( ... )

#define nitems(items) (int)(sizeof(items)/sizeof(items[0]))

#define __aligned __align

#define pause(wmesg, timo) uk_sched_thread_sleep(timo);

#define mtx_sleep(wq, condition, lock, priority, msg, deadline) \
    uk_waitq_wait_event_deadline_locked(wq, condition, ukplat_monotonic_clock() + deadline, \
					    uk_mutex_lock, uk_mutex_unlock, lock)

#define wakeup(wq) \
    uk_waitq_wake_up(wq)

#define mtx uk_mutex

#define mtx_init(lock, name, type, opts) uk_mutex_init(lock)
#define mtx_destroy(lock) do {} while(0)

#define mtx_lock(lock) \
    uk_mutex_lock(lock)

#define mtx_unlock(lock) \
    uk_mutex_unlock(lock)

#define mtx_lock_spin(lock) \
    uk_mutex_lock(lock)

#define mtx_unlock_spin(lock) \
    uk_mutex_unlock(lock)


// Check copyright
#ifndef	__DEVOLATILE
#define	__DEVOLATILE(type, var)	((type)(uintptr_t)(volatile void *)(var))
#endif

#ifndef KASSERT
#ifdef CONFIG_LIBUKDEBUG_ENABLE_ASSERT
#define KASSERT(x, msg)							\
	do {								\
		if (unlikely(!(x))) {					\
			uk_pr_crit("Assertion failure: %s\n",		\
				   STRINGIFY(x));			\
			uk_pr_crit msg;			\
			uk_pr_crit("\n");			\
			/* TODO: stack trace */				\
			ukplat_terminate(UKPLAT_CRASH);			\
		}							\
	} while (0)
#endif
#endif

#ifndef DELAY
#define DELAY(delay) udelay(delay)
#endif

struct iovec { void *iov_base; size_t iov_len; };

#define TAILQ_HEAD UK_TAILQ_HEAD
#define TAILQ_ENTRY UK_TAILQ_ENTRY
#define TAILQ_INIT UK_TAILQ_INIT
#define TAILQ_EMPTY UK_TAILQ_EMPTY
#define TAILQ_FOREACH UK_TAILQ_FOREACH
#define TAILQ_INSERT_TAIL UK_TAILQ_INSERT_TAIL
#define TAILQ_REMOVE UK_TAILQ_REMOVE

#define sx uk_mutex
#define sx_init(lock, name) uk_mutex_init(lock)

#define sx_lock(lock) uk_mutex_lock(lock)
#define sx_xlock(lock) uk_mutex_lock(lock)
#define sx_xunlock(lock) uk_mutex_unlock(lock)

#define sbintime_t int
#define boolean_t int
#define FALSE 0
#define TRUE 1

// #define atomic_add_int(src, val) 	__atomic_fetch_add(src, val, __ATOMIC_SEQ_CST)
// #define atomic_subtract_int(src, val) 	__atomic_fetch_sub(src, val, __ATOMIC_SEQ_CST)

// #define atomic_fetchadd_int(src, val) 	__atomic_fetch_add(src, val, __ATOMIC_SEQ_CST)

// Taken from freebsd-src/sys/amd64/include/atomic.h

/*
 * Atomic compare and set, used by the mutex functions.
 *
 * cmpset:
 *	if (*dst == expect)
 *		*dst = src
 *
 * fcmpset:
 *	if (*dst == *expect)
 *		*dst = src
 *	else
 *		*expect = *dst
 *
 * Returns 0 on failure, non-zero on success.
 */
#define	ATOMIC_CMPSET(TYPE)				\
static __inline int					\
atomic_cmpset_##TYPE(volatile u_##TYPE *dst, u_##TYPE expect, u_##TYPE src) \
{							\
	u_char res;					\
							\
	__asm __volatile(				\
	" lock; cmpxchg %3,%1 ;	"			\
	"# atomic_cmpset_" #TYPE "	"		\
	: "=@cce" (res),		/* 0 */		\
	  "+m" (*dst),			/* 1 */		\
	  "+a" (expect)			/* 2 */		\
	: "r" (src)			/* 3 */		\
	: "memory", "cc");				\
	return (res);					\
}							\
							\
static __inline int					\
atomic_fcmpset_##TYPE(volatile u_##TYPE *dst, u_##TYPE *expect, u_##TYPE src) \
{							\
	u_char res;					\
							\
	__asm __volatile(				\
	" lock; cmpxchg %3,%1 ;		"		\
	"# atomic_fcmpset_" #TYPE "	"		\
	: "=@cce" (res),		/* 0 */		\
	  "+m" (*dst),			/* 1 */		\
	  "+a" (*expect)		/* 2 */		\
	: "r" (src)			/* 3 */		\
	: "memory", "cc");				\
	return (res);					\
}

ATOMIC_CMPSET(char);
ATOMIC_CMPSET(short);
ATOMIC_CMPSET(int);
ATOMIC_CMPSET(long);

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_int
atomic_fetchadd_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	" lock; xaddl	%0,%1 ;		"
	"# atomic_fetchadd_int"
	: "+r" (v),			/* 0 */
	  "+m" (*p)			/* 1 */
	: : "cc");
	return (v);
}

/*
 * Atomically add the value of v to the long integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_long
atomic_fetchadd_long(volatile u_long *p, u_long v)
{

	__asm __volatile(
	" lock;	xaddq	%0,%1 ;		"
	"# atomic_fetchadd_long"
	: "+r" (v),			/* 0 */
	  "+m" (*p)			/* 1 */
	: : "cc");
	return (v);
}

static __inline int
atomic_testandset_int(volatile u_int *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btsl	%2,%1 ;		"
	"# atomic_testandset_int"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Ir" (v & 0x1f)		/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandset_long(volatile u_long *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btsq	%2,%1 ;		"
	"# atomic_testandset_long"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Jr" ((u_long)(v & 0x3f))	/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandclear_int(volatile u_int *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btrl	%2,%1 ;		"
	"# atomic_testandclear_int"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Ir" (v & 0x1f)		/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandclear_long(volatile u_long *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btrq	%2,%1 ;		"
	"# atomic_testandclear_long"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Jr" ((u_long)(v & 0x3f))	/* 2 */
	: "cc");
	return (res);
}

/* Read the current value and store a new value in the destination. */
static __inline u_int
atomic_swap_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	"	xchgl	%1,%0 ;		"
	"# atomic_swap_int"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

static __inline u_long
atomic_swap_long(volatile u_long *p, u_long v)
{

	__asm __volatile(
	"	xchgq	%1,%0 ;		"
	"# atomic_swap_long"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

/*
 * For userland, always use lock prefixes so that the binaries will run
 * on both SMP and !SMP systems.
 */
//#if defined(SMP) || !defined(_KERNEL)
//#define	MPLOCKED	"lock ; "
//#else
#define	MPLOCKED
//#endif

/*
 * The assembly is volatilized to avoid code chunk removal by the compiler.
 * GCC aggressively reorders operations and memory clobbering is necessary
 * in order to avoid that for memory barriers.
 */
#define	ATOMIC_ASM(NAME, TYPE, OP, CONS, V)		\
static __inline void					\
atomic_##NAME##_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(MPLOCKED OP			\
	: "+m" (*p)					\
	: CONS (V)					\
	: "cc");					\
}							\
							\
static __inline void					\
atomic_##NAME##_barr_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(MPLOCKED OP			\
	: "+m" (*p)					\
	: CONS (V)					\
	: "memory", "cc");				\
}							\
struct __hack

ATOMIC_ASM(set,	     char,  "orb %b1,%0",  "iq",  v);
ATOMIC_ASM(clear,    char,  "andb %b1,%0", "iq", ~v);
ATOMIC_ASM(add,	     char,  "addb %b1,%0", "iq",  v);
ATOMIC_ASM(subtract, char,  "subb %b1,%0", "iq",  v);

ATOMIC_ASM(set,	     short, "orw %w1,%0",  "ir",  v);
ATOMIC_ASM(clear,    short, "andw %w1,%0", "ir", ~v);
ATOMIC_ASM(add,	     short, "addw %w1,%0", "ir",  v);
ATOMIC_ASM(subtract, short, "subw %w1,%0", "ir",  v);

ATOMIC_ASM(set,	     int,   "orl %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    int,   "andl %1,%0",  "ir", ~v);
ATOMIC_ASM(add,	     int,   "addl %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, int,   "subl %1,%0",  "ir",  v);

ATOMIC_ASM(set,	     long,  "orq %1,%0",   "er",  v);
ATOMIC_ASM(clear,    long,  "andq %1,%0",  "er", ~v);
ATOMIC_ASM(add,	     long,  "addq %1,%0",  "er",  v);
ATOMIC_ASM(subtract, long,  "subq %1,%0",  "er",  v);

#define __predict_false unlikely

#define __compiler_membar() mb()

// Taken from freebsd-src/tools/build/cross-build/include/common/sys/param.h

#ifndef roundup2
#define roundup2(x, y) \
	(((x) + ((y)-1)) & (~((y)-1))) /* if y is powers of two */
#endif

#endif /* __BSD_LAYER_H__ */

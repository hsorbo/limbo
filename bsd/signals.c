/*
 * Copyright © 2026 Håvard Sørbø
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bsd/handler.h"
#include "bsd/kevent.h"
#include "bsd/signals.h"
#include "bsd/signo.h"
#include "bsd/xnu-errno.h"
#include "syscall.h"

#define DARWIN_NSIG 32

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

#define _SIG_DFL 0
#define _SIG_IGN 1
#define _SIG_HOLD 5

#define _SIGTRAP 5
#define _SIGKILL 9
#define _SIGBUS  10
#define _SIGSEGV 11
#define _SIGSTOP 17

#define _SA_ONSTACK   0x0001
#define _SA_RESTART   0x0002
#define _SA_RESETHAND 0x0004
#define _SA_NOCLDSTOP 0x0008
#define _SA_NODEFER   0x0010
#define _SA_NOCLDWAIT 0x0020
#define _SA_SIGINFO   0x0040

#define _SS_ONSTACK  0x0001
#define _SS_DISABLE  0x0004
#define _MINSIGSTKSZ 32768

#define _SIG_BLOCK   1
#define _SIG_UNBLOCK 2
#define _SIG_SETMASK 3

#define UC_TRAD            1
#define UC_FLAVOR          30
#define UC_SET_ALT_STACK   0x40000000
#define UC_RESET_ALT_STACK 0x80000000

#define _SI_QUEUE 0x10002
#define _SI_TIMER 0x10003
#define _SI_MESGQ 0x10005

#define C_64_REDZONE_LEN 128

#define ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH 0x1
#define PSTATE_NZCV                         0xf0000000u

struct darwin_sigaction_in {
	uint64_t handler;
	uint64_t tramp;
	uint32_t mask;
	int32_t flags;
};

struct darwin_sigaction_out {
	uint64_t handler;
	uint32_t mask;
	int32_t flags;
};

struct darwin_stack {
	uint64_t ss_sp;
	uint64_t ss_size;
	int32_t ss_flags;
	int32_t pad;
};

struct darwin_siginfo {
	int32_t signo;
	int32_t error;
	int32_t code;
	int32_t pid;
	uint32_t uid;
	int32_t status;
	uint64_t addr;
	uint64_t value;
	int64_t band;
	uint64_t pad[7];
};

struct darwin_ucontext {
	int32_t uc_onstack;
	uint32_t uc_sigmask;
	struct darwin_stack uc_stack;
	uint64_t uc_link;
	uint64_t uc_mcsize;
	uint64_t uc_mcontext;
};

struct darwin_mcontext {
	struct {
		uint64_t far;
		uint32_t esr;
		uint32_t exception;
	} es;
	struct {
		uint64_t x[29];
		uint64_t fp;
		uint64_t lr;
		uint64_t sp;
		uint64_t pc;
		uint32_t cpsr;
		uint32_t flags;
	} ss;
	struct {
		__uint128_t v[32];
		uint32_t fpsr;
		uint32_t fpcr;
	} __attribute__((aligned(16))) ns;
};

struct darwin_sigframe {
	struct darwin_siginfo sinfo;
	struct darwin_ucontext uctx;
	struct darwin_mcontext mctx;
};

_Static_assert(sizeof(struct darwin_siginfo) == 104, "siginfo");
_Static_assert(sizeof(struct darwin_ucontext) == 56, "ucontext");
_Static_assert(sizeof(struct darwin_mcontext) == 816, "mcontext");

#define FPSIMD_MAGIC 0x46508001
#define ESR_MAGIC    0x45535201

struct linux_ctx_head {
	uint32_t magic;
	uint32_t size;
};

struct linux_fpsimd {
	struct linux_ctx_head head;
	uint32_t fpsr;
	uint32_t fpcr;
	__uint128_t vregs[32];
};

struct linux_esr {
	struct linux_ctx_head head;
	uint64_t esr;
};

struct action {
	uint64_t handler;
	uint64_t tramp;
	uint32_t mask;
	int32_t flags;
};

#ifndef __x86_64__
static struct action actions[DARWIN_NSIG];
static pthread_mutex_t actions_lock = PTHREAD_MUTEX_INITIALIZER;

static atomic_bool catching;
static uint64_t token_key;

static _Atomic uint32_t process_pending;
static siginfo_t process_info[DARWIN_NSIG];

static uint32_t watch_counts[DARWIN_NSIG];
static _Atomic int64_t sent_counts[DARWIN_NSIG];
static int relay_fd = -1;

static __thread uint32_t thread_pending;
static __thread siginfo_t signal_info[DARWIN_NSIG];
static __thread struct darwin_stack guest_altstack = {.ss_flags = _SS_DISABLE};

static void install_host_action(int sig);
static bool default_ignores(int sig);
static void *relay_main(void *arg);
static bool deliver(ucontext_t *uc, int sig, const siginfo_t *info);
static void build_frame(struct darwin_sigframe *frame, const ucontext_t *uc,
		int sig, const siginfo_t *info, bool onstack);
static void restore_frame(ucontext_t *uc, const struct darwin_ucontext *duc);
static uint32_t guest_mask(const ucontext_t *uc);
static void set_guest_mask(sigset_t *set, uint32_t mask);
static struct linux_fpsimd *find_fpsimd(const ucontext_t *uc);
static uint64_t find_esr(const ucontext_t *uc);
static bool on_altstack(uint64_t sp);
static bool is_fault(int sig);
static int code_from_linux(int sig, int code);

static const uint32_t cantmask
		= (1u << (_SIGKILL - 1)) | (1u << (_SIGSTOP - 1));

void
signals_init(void)
{
	for (int sig = 1; sig < DARWIN_NSIG; sig++) {
		int host = signo_to_linux(sig);
		struct sigaction current;
		if (host != 0 && host != SIGPIPE
				&& sigaction(host, NULL, &current) == 0
				&& current.sa_handler == SIG_IGN) {
			actions[sig].handler = _SIG_IGN;
		}
	}
	getrandom(&token_key, sizeof(token_key), 0);
	install_host_action(_SIGTRAP);
	install_host_action(_SIGSEGV);
	install_host_action(_SIGBUS);
}

int
sys_sigaction(int signum, void *nsa, void *osa)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigaction(%p, %p, %p)\n", (void *)signum, (void *)nsa,
			(void *)osa);
#endif
	if (signum <= 0 || signum >= DARWIN_NSIG) {
		return _EINVAL;
	}
	const struct darwin_sigaction_in *in = nsa;
	if (in != NULL && (signum == _SIGKILL || signum == _SIGSTOP)
			&& in->handler != _SIG_DFL) {
		return _EINVAL;
	}

	pthread_mutex_lock(&actions_lock);
	if (osa != NULL) {
		struct darwin_sigaction_out *out = osa;
		out->handler = actions[signum].handler;
		out->mask = actions[signum].mask;
		out->flags = actions[signum].flags;
	}
	if (in != NULL) {
		actions[signum] = (struct action){
				.handler = in->handler,
				.tramp = in->tramp,
				.mask = in->mask & ~cantmask,
				.flags = in->flags,
		};
		if (in->handler > _SIG_HOLD) {
			atomic_store(&catching, true);
		} else if (in->handler == _SIG_IGN) {

			atomic_fetch_and(&process_pending, ~(1u << (signum - 1)));
			thread_pending &= ~(1u << (signum - 1));
		}
		install_host_action(signum);
	}
	pthread_mutex_unlock(&actions_lock);
	return 0;
}

static void
install_host_action(int sig)
{
	int host = signo_to_linux(sig);
	if (host == 0 || host == SIGSYS || host == SIGILL) {
		return;
	}

	const struct action *action = &actions[sig];

	bool watched = watch_counts[sig] != 0
			&& (action->handler == _SIG_IGN
					|| (action->handler == _SIG_DFL
							&& default_ignores(sig)));

	bool report = is_fault(host) && host != SIGFPE
			&& action->handler == _SIG_DFL;
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	if (action->handler > _SIG_HOLD || watched || report) {
		act.sa_sigaction = syscall_signal_handler;
		act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTORER;
		act.sa_restorer = limbo_rt_sigreturn;
		if (action->flags & _SA_RESTART) {
			act.sa_flags |= SA_RESTART;
		}
		sigfillset(&act.sa_mask);
		sigdelset(&act.sa_mask, SIGSYS);
		sigdelset(&act.sa_mask, SIGILL);
		sigdelset(&act.sa_mask, SIGSEGV);
		sigdelset(&act.sa_mask, SIGBUS);
		sigdelset(&act.sa_mask, SIGTRAP);
		sigdelset(&act.sa_mask, SIGFPE);
	} else if (action->handler == _SIG_IGN && !is_fault(host)) {
		act.sa_handler = SIG_IGN;
	} else if (host == SIGPIPE || host == SIGIO) {
		act.sa_handler = SIG_IGN;
	} else {
		act.sa_handler = SIG_DFL;
	}
	if (host == SIGCHLD) {
		if (action->flags & _SA_NOCLDSTOP) {
			act.sa_flags |= SA_NOCLDSTOP;
		}
		if (action->flags & _SA_NOCLDWAIT) {
			act.sa_flags |= SA_NOCLDWAIT;
		}
	}
	sigaction(host, &act, NULL);
}

static bool
default_ignores(int sig)
{
	switch (sig) {
	case 16:
	case 19:
	case 20:
	case 23:
	case 28:
	case 29:
		return true;
	default:
		return false;
	}
}

void
signals_watch(int sig, bool watch)
{
	if (sig <= 0 || sig >= DARWIN_NSIG) {
		return;
	}
	pthread_mutex_lock(&actions_lock);
	if (watch) {
		watch_counts[sig]++;
	} else if (watch_counts[sig] != 0) {
		watch_counts[sig]--;
	}
	if (watch && relay_fd == -1) {
		relay_fd = eventfd(0, EFD_CLOEXEC);
		sigset_t all, old;
		sigfillset(&all);
		pthread_sigmask(SIG_SETMASK, &all, &old);
		pthread_t thread;
		pthread_create(&thread, NULL, relay_main, NULL);
		pthread_detach(thread);
		pthread_sigmask(SIG_SETMASK, &old, NULL);
	}
	install_host_action(sig);
	pthread_mutex_unlock(&actions_lock);
}

static void *
relay_main(void *arg)
{
	for (;;) {
		eventfd_t value;
		if (eventfd_read(relay_fd, &value) != 0) {
			continue;
		}
		for (int sig = 1; sig < DARWIN_NSIG; sig++) {
			int64_t count = atomic_exchange(&sent_counts[sig], 0);
			if (count != 0) {
				kevent_signal(sig, count);
			}
		}
	}
	return NULL;
}

void
signals_handle(int sig, siginfo_t *info, ucontext_t *uc,
		enum signal_context context)
{
	int darwin = signo_from_linux(sig);
	if (darwin <= 0 || darwin >= DARWIN_NSIG) {
		return;
	}
	if (watch_counts[darwin] != 0 && relay_fd != -1) {
		atomic_fetch_add(&sent_counts[darwin], 1);
		eventfd_write(relay_fd, 1);
	}
	const struct action *action = &actions[darwin];
	bool caught = action->handler > _SIG_HOLD;

	if (is_fault(sig) && info->si_code > 0) {
		if (!caught || context != SIGNAL_IN_GUEST) {
			fprintf(stderr, "limbo: fatal signal %d (code %d) at %llx%s, "
					"address %p\n",
					sig, info->si_code,
					(unsigned long long)uc->uc_mcontext.pc,
					context == SIGNAL_IN_GUEST ? ""
								   : " in limbo",
					info->si_addr);
			if (context == SIGNAL_IN_GUEST) {
				syscall_print_guest_chain(&uc->uc_mcontext);
			}
			signal(sig, SIG_DFL);
			return;
		}
	}
	if (!caught) {
#ifdef ENABLE_STRACE

		if (is_fault(sig) && action->handler == _SIG_DFL) {
			signal(sig, SIG_DFL);
			syscall(SYS_tgkill, getpid(), gettid(), sig);
		}
#endif
		return;
	}

	uint32_t bit = 1u << (darwin - 1);
	switch (context) {
	case SIGNAL_IN_GUEST:
		deliver(uc, darwin, info);
		break;
	case SIGNAL_IN_LIMBO:
		if (syscall_trap_context() != NULL || info->si_code == SI_TKILL) {
			signal_info[darwin] = *info;
			thread_pending |= bit;
			break;
		}

	case SIGNAL_ON_LIMBO_THREAD:
		process_info[darwin] = *info;
		atomic_fetch_or(&process_pending, bit);
		break;
	}
}

void
signals_trap_exit(ucontext_t *uc)
{
	if (!atomic_load_explicit(&catching, memory_order_relaxed)) {
		return;
	}

	sigset_t all;
	sigfillset(&all);
	sigdelset(&all, SIGSYS);
	sigdelset(&all, SIGILL);
	sigdelset(&all, SIGSEGV);
	sigdelset(&all, SIGBUS);
	sigdelset(&all, SIGTRAP);
	sigdelset(&all, SIGFPE);
	pthread_sigmask(SIG_BLOCK, &all, NULL);

	uint32_t pending = thread_pending;
	thread_pending = 0;
	for (int sig = 1; pending != 0 && sig < DARWIN_NSIG; sig++) {
		if (pending & (1u << (sig - 1))) {
			pending &= ~(1u << (sig - 1));
			deliver(uc, sig, &signal_info[sig]);
		}
	}

	uint32_t waiting = atomic_load(&process_pending);
	for (int sig = 1; waiting != 0 && sig < DARWIN_NSIG; sig++) {
		uint32_t bit = 1u << (sig - 1);
		if (!(waiting & bit) || (guest_mask(uc) & bit)) {
			continue;
		}
		if (atomic_fetch_and(&process_pending, ~bit) & bit) {
			deliver(uc, sig, &process_info[sig]);
		}
	}
}

void
signals_fork_child(void)
{
	thread_pending = 0;
	atomic_store(&process_pending, 0);
}

static bool
deliver(ucontext_t *uc, int sig, const siginfo_t *info)
{
	struct action action = actions[sig];
	if (action.handler <= _SIG_HOLD || action.tramp == 0) {
		return false;
	}

	mcontext_t *mc = &uc->uc_mcontext;
	bool onstack = on_altstack(mc->sp);
	bool use_altstack = (action.flags & _SA_ONSTACK)
			&& !(guest_altstack.ss_flags & _SS_DISABLE) && !onstack;
	uint64_t sp = use_altstack
			? guest_altstack.ss_sp + guest_altstack.ss_size
			: mc->sp - C_64_REDZONE_LEN;
	sp = (sp - sizeof(struct darwin_sigframe)) & ~(uint64_t)15;

	struct darwin_sigframe *frame = (void *)sp;
	build_frame(frame, uc, sig, info, onstack);

	mc->pc = action.tramp;
	mc->sp = sp;
	mc->regs[0] = action.handler;
	mc->regs[1] = (action.flags & _SA_SIGINFO) ? UC_FLAVOR : UC_TRAD;
	mc->regs[2] = sig;
	mc->regs[3] = (uint64_t)&frame->sinfo;
	mc->regs[4] = (uint64_t)&frame->uctx;
	mc->regs[5] = (uint64_t)&frame->uctx ^ token_key;

	uint32_t mask = frame->uctx.uc_sigmask | action.mask;
	if (!(action.flags & _SA_NODEFER)) {
		mask |= 1u << (sig - 1);
	}
	set_guest_mask(&uc->uc_sigmask, mask);

	if ((action.flags & _SA_RESETHAND) && sig != 4 && sig != 5) {
		actions[sig].handler = _SIG_DFL;
		actions[sig].flags &= ~_SA_SIGINFO;
		install_host_action(sig);
	}
	return true;
}

static void
build_frame(struct darwin_sigframe *frame, const ucontext_t *uc, int sig,
		const siginfo_t *info, bool onstack)
{
	const mcontext_t *mc = &uc->uc_mcontext;
	memset(frame, 0, sizeof(*frame));

	struct darwin_siginfo *si = &frame->sinfo;
	si->signo = sig;
	si->error = info->si_errno;
	si->code = code_from_linux(info->si_signo, info->si_code);
	if (is_fault(info->si_signo)) {
		si->addr = (uint64_t)info->si_addr;
	} else {
		si->pid = info->si_pid;
		si->uid = info->si_uid;
		si->value = (uint64_t)info->si_value.sival_ptr;
	}
	if (info->si_signo == SIGCHLD) {
		si->status = info->si_status;
	}

	struct darwin_ucontext *duc = &frame->uctx;
	duc->uc_onstack = onstack;
	duc->uc_sigmask = guest_mask(uc);
	duc->uc_stack = guest_altstack;
	if (onstack) {
		duc->uc_stack.ss_flags |= _SS_ONSTACK;
	}
	duc->uc_mcsize = sizeof(struct darwin_mcontext);
	duc->uc_mcontext = (uint64_t)&frame->mctx;

	struct darwin_mcontext *dmc = &frame->mctx;
	dmc->es.far = mc->fault_address;
	dmc->es.esr = find_esr(uc);
	memcpy(dmc->ss.x, mc->regs, sizeof(dmc->ss.x));
	dmc->ss.fp = mc->regs[29];
	dmc->ss.lr = mc->regs[30];
	dmc->ss.sp = mc->sp;
	dmc->ss.pc = mc->pc;
	dmc->ss.cpsr = (uint32_t)mc->pstate;
	dmc->ss.flags = ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
	const struct linux_fpsimd *fp = find_fpsimd(uc);
	if (fp != NULL) {
		memcpy(dmc->ns.v, fp->vregs, sizeof(dmc->ns.v));
		dmc->ns.fpsr = fp->fpsr;
		dmc->ns.fpcr = fp->fpcr;
	}
}

static void
restore_frame(ucontext_t *uc, const struct darwin_ucontext *duc)
{
	mcontext_t *mc = &uc->uc_mcontext;
	const struct darwin_mcontext *dmc = (const void *)duc->uc_mcontext;
	memcpy(mc->regs, dmc->ss.x, sizeof(dmc->ss.x));
	mc->regs[29] = dmc->ss.fp;
	mc->regs[30] = dmc->ss.lr;
	mc->sp = dmc->ss.sp;
	mc->pc = dmc->ss.pc;
	mc->pstate = (mc->pstate & ~(uint64_t)PSTATE_NZCV)
			| (dmc->ss.cpsr & PSTATE_NZCV);
	struct linux_fpsimd *fp = find_fpsimd(uc);
	if (fp != NULL) {
		memcpy(fp->vregs, dmc->ns.v, sizeof(fp->vregs));
		fp->fpsr = dmc->ns.fpsr;
		fp->fpcr = dmc->ns.fpcr;
	}
	set_guest_mask(&uc->uc_sigmask, duc->uc_sigmask & ~cantmask);
}

int
sys_sigreturn(void *uctx, int infostyle, user_addr_t token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigreturn(%p, %p, %p)\n", (void *)uctx,
			(void *)infostyle, (void *)token);
#endif

	if ((uint32_t)infostyle == UC_SET_ALT_STACK
			|| (uint32_t)infostyle == UC_RESET_ALT_STACK) {
		return 0;
	}
	ucontext_t *trap = syscall_trap_context();
	if (uctx == NULL || trap == NULL) {
		return _EINVAL;
	}
	restore_frame(trap, uctx);
	syscall_keep_context();
	return 0;
}

int
sys_sigaltstack(void *nss, void *oss)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigaltstack(%p, %p)\n", (void *)nss, (void *)oss);
#endif
	ucontext_t *trap = syscall_trap_context();
	bool onstack = trap != NULL && on_altstack(trap->uc_mcontext.sp);
	struct darwin_stack old = guest_altstack;
	if (onstack) {
		old.ss_flags |= _SS_ONSTACK;
	}

	if (nss != NULL) {
		const struct darwin_stack *in = nss;
		if (onstack) {
			return _EPERM;
		}
		if (in->ss_flags & ~_SS_DISABLE) {
			return _EINVAL;
		}
		if (in->ss_flags & _SS_DISABLE) {
			guest_altstack = (struct darwin_stack){
					.ss_flags = _SS_DISABLE};
		} else {
			if (in->ss_size < _MINSIGSTKSZ) {
				return _ENOMEM;
			}
			guest_altstack = (struct darwin_stack){
					.ss_sp = in->ss_sp,
					.ss_size = in->ss_size,
			};
		}
	}
	if (oss != NULL) {
		memcpy(oss, &old, sizeof(old));
	}
	return 0;
}

int
sys_sigpending(void *osv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigpending(%p)\n", (void *)osv);
#endif
	sigset_t host;
	sigpending(&host);
	*(uint32_t *)osv = sigset_from_linux(&host) | thread_pending
			| atomic_load(&process_pending);
	return 0;
}

int
signals_mask(int how, const uint32_t *set, uint32_t *oset)
{
	ucontext_t *trap = syscall_trap_context();
	sigset_t current;
	pthread_sigmask(SIG_SETMASK, NULL, &current);
	uint32_t old = sigset_from_linux(trap != NULL ? &trap->uc_sigmask
						      : &current);
	if (set != NULL) {
		uint32_t mask;
		switch (how) {
		case _SIG_BLOCK:
			mask = old | *set;
			break;
		case _SIG_UNBLOCK:
			mask = old & ~*set;
			break;
		case _SIG_SETMASK:
			mask = *set;
			break;
		default:
			return _EINVAL;
		}
		mask &= ~cantmask;
		if (trap != NULL) {
			set_guest_mask(&trap->uc_sigmask, mask);
		}
		set_guest_mask(&current, mask);
		pthread_sigmask(SIG_SETMASK, &current, NULL);
	}
	if (oset != NULL) {
		*oset = old;
	}
	return 0;
}

static uint32_t
guest_mask(const ucontext_t *uc)
{
	return sigset_from_linux(&uc->uc_sigmask);
}

static void
set_guest_mask(sigset_t *set, uint32_t mask)
{
	for (int sig = 1; sig < DARWIN_NSIG; sig++) {
		int host = signo_to_linux(sig);
		if (host == 0) {
			continue;
		}
		if (mask & (1u << (sig - 1))) {
			sigaddset(set, host);
		} else {
			sigdelset(set, host);
		}
	}
	sigdelset(set, SIGSYS);
	sigdelset(set, SIGILL);
	sigdelset(set, SIGSEGV);
	sigdelset(set, SIGBUS);
}

static const struct linux_ctx_head *
find_record(const ucontext_t *uc, uint32_t magic)
{
	const uint8_t *p = (const uint8_t *)uc->uc_mcontext.__reserved;
	const uint8_t *end = p + sizeof(uc->uc_mcontext.__reserved);
	while (p + sizeof(struct linux_ctx_head) <= end) {
		const struct linux_ctx_head *head = (const void *)p;
		if (head->magic == 0 || head->size == 0) {
			break;
		}
		if (head->magic == magic) {
			return head;
		}
		p += head->size;
	}
	return NULL;
}

static struct linux_fpsimd *
find_fpsimd(const ucontext_t *uc)
{
	return (struct linux_fpsimd *)find_record(uc, FPSIMD_MAGIC);
}

static uint64_t
find_esr(const ucontext_t *uc)
{
	const struct linux_esr *esr = (const void *)find_record(uc, ESR_MAGIC);
	return (esr != NULL) ? esr->esr : 0;
}

static bool
on_altstack(uint64_t sp)
{
	return !(guest_altstack.ss_flags & _SS_DISABLE)
			&& sp > guest_altstack.ss_sp
			&& sp <= guest_altstack.ss_sp + guest_altstack.ss_size;
}

static bool
is_fault(int sig)
{
	return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE
			|| sig == SIGTRAP;
}

static int
code_from_linux(int sig, int code)
{
	switch (code) {

	case SI_USER:
	case SI_TKILL:
		return 0;
	case SI_QUEUE:
		return _SI_QUEUE;
	case SI_TIMER:
		return _SI_TIMER;
	case SI_MESGQ:
		return _SI_MESGQ;
	}
	if (code <= 0) {
		return code;
	}

	if (sig == SIGILL) {
		static const int ill[] = {0, 1, 4, 5, 2, 3, 6, 7, 8};
		return (code < 9) ? ill[code] : code;
	}
	if (sig == SIGFPE) {
		static const int fpe[] = {0, 7, 8, 1, 2, 3, 4, 5, 6};
		return (code < 9) ? fpe[code] : code;
	}
	return code;
}
#else
int
sys_sigaction(int signum, void *nsa, void *osa)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigaction(%p, %p, %p)\n", (void *)signum, (void *)nsa,
			(void *)osa);
#endif

	return 0;
}

int
sys_sigreturn(void *uctx, int infostyle, user_addr_t token)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigreturn(%p, %p, %p)\n", (void *)uctx,
			(void *)infostyle, (void *)token);
#endif

	return 0;
}

int
sys_sigaltstack(void *nss, void *oss)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigaltstack(%p, %p)\n", (void *)nss, (void *)oss);
#endif

	return 0;
}

int
sys_sigpending(void *osv)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sigpending(%p)\n", (void *)osv);
#endif
	unimplemented();
}

void
signals_fork_child(void)
{
}

void
signals_watch(int sig, bool watch)
{
}

int
signals_mask(int how, const uint32_t *set, uint32_t *oset)
{
	sigset_t linux_set, old;
	sigset_t *new_set = NULL;
	if (set != NULL) {
		if (how < _SIG_BLOCK || how > _SIG_SETMASK) {
			return _EINVAL;
		}
		sigset_to_linux(*set, &linux_set);
		sigdelset(&linux_set, SIGSYS);
		sigdelset(&linux_set, SIGILL);
		new_set = &linux_set;
	}

	int error = pthread_sigmask(
			how - _SIG_BLOCK + SIG_BLOCK, new_set, &old);
	if (error != 0) {
		return err_map(error);
	}
	if (oset != NULL) {
		*oset = sigset_from_linux(&old);
	}
	return 0;
}
#endif

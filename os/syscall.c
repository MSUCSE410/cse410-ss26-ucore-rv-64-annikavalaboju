#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_task_info(uint64 ti_va);
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd);
uint64 sys_munmap(uint64 start, uint64 len);

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

// implemented sys_gettimeofday 
// kernel implementation 
// returns current time, use copyout to write to virtual address
uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();

    TimeVal tv;
    uint64 cycle = get_cycle();
    tv.sec  = cycle / CPU_FREQ;
    tv.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

    if (copyout(p->pagetable, (uint64)val, (char *)&tv, sizeof(tv)) < 0)
        return -1;

    return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/
uint64 sys_task_info(uint64 ti_va)
{
    struct proc *p = curr_proc();

    TaskInfo ti; // build kernel 
    ti.status = Running;

    uint64 now = get_cycle();
    uint64 start = p->start_cycle ? p->start_cycle : now;
    ti.time = (int)((now - start) * 1000 / CPU_FREQ);

    for (int i = 0; i < MAX_SYSCALL_NUM; i++)
        ti.syscall_times[i] = p->syscall_times[i];

    if (copyout(p->pagetable, ti_va, (char *)&ti, sizeof(ti)) < 0)
        return -1;

    return 0;
}

// implement sys_getpid for project 2
// returns pid of current process
uint64 sys_getpid(void)
{
    return (uint64)curr_proc()->pid;
}

// implement sys_mmap for project 2
// map pages and free memory
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
    (void)flag; (void)fd;
    struct proc *p = curr_proc(); // get current process

    if (!PGALIGNED(start)) return -1; // validate inputs
    if (len == 0) return 0; 

    // set permissions based on port bits
    if (len > (1ULL << 30)) return -1;      // 1 GiB
    if ((port & ~0x7) != 0) return -1;      // only bits 0..2 allowed
    if ((port & 0x7) == 0) return -1;       // must have at least R/W/X (user access)

    // port must be valid and nonzero
    int perm = PTE_U; // user mode allowed to access
    if (port & 0x1) perm |= PTE_R;
    if (port & 0x2) perm |= (PTE_R | PTE_W);
    if (port & 0x4) perm |= PTE_X;

    uint64 a = PGROUNDDOWN(start); // round down to page boundary
    uint64 end = PGROUNDUP(start + len); // round up to page boundary

    // ensure all pages are unmapped
    for (uint64 va = a; va < end; va += PGSIZE) {
        pte_t *pte = walk(p->pagetable, va, 0);
        if (pte && (*pte & PTE_V)) return -1;
    }
    // walkaddr - refuse to see non user mapping
    // walk - if pte exists and valid

    // allocate physical memory (kalloc)
    // allocate+map - rollback on failure
    uint64 mapped_pages = 0;
    for (uint64 va = a; va < end; va += PGSIZE) {
        void *mem = kalloc(); // allocate one phys page
        if (!mem) {
            // if kalloc fail after mapping 
            uvmunmap(p->pagetable, a, mapped_pages, 1);
            sfence_vma();
            return -1;
        }
        memset(mem, 0, PGSIZE); // new mapped mem starts as zeros

        if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0) {
            kfree(mem);
            uvmunmap(p->pagetable, a, mapped_pages, 1);
            sfence_vma(); // remove/flush old translations
            return -1;
        }
        mapped_pages++;
    }

    // update max_page (npages)
    uint64 new_max = end / PGSIZE;
    if (new_max > p->max_page) p->max_page = new_max;

    sfence_vma();  // important after mapping
    return 0;
}

// implement sys_munmap for project 2
// removes mapping for the range 
uint64 sys_munmap(uint64 start, uint64 len)
{
    struct proc *p = curr_proc();
    if (len == 0) return 0; // validate

    if (!PGALIGNED(start)) return -1;

    uint64 a = PGROUNDDOWN(start); // rounding boundaries
    uint64 end = PGROUNDUP(start + len);
    uint64 npages = (end - a) / PGSIZE;

    // error if any page is unmapped
    for (uint64 va = a; va < end; va += PGSIZE) {
        pte_t *pte = walk(p->pagetable, va, 0);
        if (!pte || ((*pte & PTE_V) == 0)) return -1;
        // ^^ verify every page is mapped
    }

    // free physical pages (uvmunmap)
    uvmunmap(p->pagetable, a, npages, 1);
    sfence_vma();  // important after unmapping, cant keep old translations
    return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
        curr_proc()->syscall_times[id]++;
    }
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:  // proj2 add the gettimeofday switch case
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
    case SYS_getpid: // proj2 add the getpid switch case
        ret = sys_getpid();
        break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info: // how the syscall number 410 gets routed to function
        ret = sys_task_info(args[0]);
        break;
    
	// project 2 added these two cases for mmap and munmap in ID list
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
    
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;

    default:
        ret = -1;
        errorf("unknown syscall %d", id);
    }
    trapframe->a0 = ret;
    tracef("syscall ret %d", ret);
}
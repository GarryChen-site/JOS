// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	// pte_t pte = uvpt[PGNUM(addr)];
	envid_t envid = sys_getenvid(); // thisenv->env_id is error
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.

	// panic("pgfault not implemented");

	// if ((err & FEC_WR)== 0 || (pte& PTE_COW) == 0) {
	// 	panic("pgfault: bad faulting access\n");
	// }
	if(!((err & FEC_WR) && (uvpt[PGNUM(addr)] & PTE_COW) && (uvpt[PGNUM(addr)] & PTE_P) && (uvpd[PDX(addr)] & PTE_P))){
		panic("pgfault:not writtable or not cow pages\n");
  	}

	if((r = sys_page_alloc(envid, PFTEMP, PTE_W | PTE_U | PTE_P)) != 0) {
		panic("pgfault: %e", r);
	}

	addr = ROUNDDOWN(addr, PGSIZE); 
	memcpy(PFTEMP, addr, PGSIZE);

	if((r = sys_page_unmap(envid, addr)) < 0){
    		panic("pgfault:sys_page_unmap: %e \n", r);
	}

	if ((r = sys_page_map(envid, PFTEMP, envid, addr, PTE_W | PTE_U | PTE_P)) != 0) {
        panic("pgfault: %e", r);
    }

	// If no page is mapped, the function silently succeeds.
	if ((r = sys_page_unmap(envid, PFTEMP)) != 0) {
        panic("pgfault: %e", r);
    }

}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	// panic("duppage not implemented");

	void *addr;
	int perm;

	addr = (void*)((uint32_t)pn * PGSIZE);
	perm = PTE_P | PTE_U;

	if((uvpt[pn] & PTE_W) || (uvpt[pn] & PTE_COW)){
		perm |= PTE_COW;
	}

	// map into the child address space
	if((r = sys_page_map(0, addr, envid, addr, perm)) < 0){
		panic("sys_page_map: %e \n", r);
	}

	// if is cow, remap own address space
	if(perm & PTE_COW){
		if((r = sys_page_map(0, addr, 0, addr, perm)) < 0){
			panic("sys_page_map : %e \n", r);
		}
	}

	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
	uint8_t *addr;
	int r;
	extern void _pgfault_upcall(void);


	// LAB 4: Your code here.
	// panic("fork not implemented");

	set_pgfault_handler(pgfault);
	envid = sys_exofork();
	if(envid < 0 ){
		panic("sys_exofork: %e", envid);
	}

	if(envid == 0){
		// fix thisenv in child
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// copy the address space mappings to child
	for (addr = (uint8_t *)UTEXT; addr < (uint8_t *)(UXSTACKTOP - PGSIZE); addr += PGSIZE) {
		if((uvpd[PDX(addr)]&PTE_P) && (uvpt[PGNUM(addr)]&PTE_P)){
			duppage(envid, PGNUM(addr));
		}
	}


	// allocate a fresh page in the child for the exception stack
    if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_W | PTE_U | PTE_P)) != 0) {
        panic("fork: %e", r);
    }
    
    if((r = sys_page_map(envid, (void *)(UXSTACKTOP - PGSIZE), 0, UTEMP, PTE_P|PTE_U|PTE_W)) < 0){
    	panic("sys_page_map: %e \n", r);
    }
    memmove(UTEMP, (void *)(UXSTACKTOP -PGSIZE), PGSIZE);
    
    if((r = sys_page_unmap(0, UTEMP)) < 0){
	    panic("sys_page_unmap: %e \n", r);
    }
	// The parent sets the user page fault entrypoint for the child to look like its own
	if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) != 0) {
        panic("fork: %e", r);
    }

	// mark the child as runnable
	if((r = sys_env_set_status(envid, ENV_RUNNABLE)) != 0){
		panic("fork: %e", r);
	}

	return envid;

}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}

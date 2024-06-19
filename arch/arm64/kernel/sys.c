// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>

/*ARM64 implementation of elevate intended to be refactored
 into arch specific code */
#ifdef CONFIG_SYMBIOTE
struct vm_area_struct* get_task_base_vma(struct task_struct* task) {
    struct mm_struct* mm = task->mm;
    return mm->mmap;
}

struct vm_area_struct* get_next_vma(struct vm_area_struct* vma) {
    return vma->vm_next;
}

uint64_t get_task_vma_start(struct vm_area_struct* vma) {
    return vma->vm_start;
}

uint64_t get_task_vma_end(struct vm_area_struct* vma) {
    return vma->vm_end;
}

int unset_pxn_for_address(struct task_struct* task, uint64_t addr) {
    struct mm_struct* task_mm;
    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;

    task_mm = task->mm;

    pgd = pgd_offset(task_mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 1;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 1;
    else
		*p4d = __p4d(p4d_val(*p4d) & ~P4D_TABLE_PXN);

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return 1;
	else
		*pud = __pud(pud_val(*pud) & ~PUD_TABLE_PXN);

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 1;
	else
		*pmd = __pmd(pmd_val(*pmd) & ~(PMD_TABLE_PXN | PMD_SECT_PXN));

    pte = pte_offset_kernel(pmd, addr);
    if (!pte)
        return 1;
	else
		*pte = __pte(pte_val(*pte) & ~PTE_PXN);
    return 0;
}

void unset_process_pxn(void) {
    void* vma = get_task_base_vma(current);
    while (vma) {
        uint64_t vm_start = get_task_vma_start(vma);
        uint64_t vm_end = get_task_vma_end(vma);
		uint64_t vmpage;

        for (vmpage = vm_start; vmpage < vm_end; vmpage += PAGE_SIZE) {
			unset_pxn_for_address(current, vmpage);
        }

        vma = get_next_vma(vma);
    }
}

uint64_t symbi_check_elevate(void);
uint64_t symbi_check_elevate(){
	return current->symbiote_elevated;
}


unsigned long arch_elevate(unsigned long direction){
	uint64_t pstate;
	uint64_t EL1_MASK = 0x4;
	uint64_t EL0_MASK = 0x0;
	uint64_t daif_mask = 0x3C0;
	struct pt_regs *regs;

	regs = (struct pt_regs *)(current_pt_regs());

	/*mask appropriate bits into saved PSTATE so when state is restored
	 on return from syscall we will be elevated/lowered */
	pstate = regs->pstate;
	if (direction == 0){
		if (current->symbiote_elevated == 1){
			current->symbiote_elevated = 0;
			pstate = pstate & EL0_MASK;
			regs->pstate = pstate;
			return 0;
		}else{
			printk(KERN_ERR "Error: Cannot lower privilege level, already at EL0\n");
			return 0;
		}
	}
	else if (direction == 1){
		if (current->symbiote_elevated == 0){
			current->symbiote_elevated = 1;
			pstate = pstate | EL1_MASK | daif_mask;
			regs->pstate = pstate;

			/*PXN bits are set at all page table levels for the user text page
			  we are returning to. Use the saved user PC from pt_regs struct to
			  fix permissions for this page */
			unset_pxn_for_address(current, regs->pc);
			asm("tlbi vmalle1"); //flush TLB
			return 0;
		}else{
			printk(KERN_ERR "Error: Cannot elevate privilege level, already at EL1\n");
			return 0;
		}
	}else{
		printk(KERN_ERR "Error: Invalid argument\n");
		return 0;
	}
}
#endif

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return ksys_personality(personality);
}

asmlinkage long sys_ni_syscall(void);

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused)
{
	return sys_ni_syscall();
}

/*
 * Wrappers to pass the pt_regs argument.
 */
#define __arm64_sys_personality		__arm64_sys_arm64_personality

#undef __SYSCALL
#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = __arm64_##sym,

const syscall_fn_t sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd.h>
};

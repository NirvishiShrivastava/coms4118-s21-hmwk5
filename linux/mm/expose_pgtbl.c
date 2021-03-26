#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/expose_pgtbl.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>

/*
 * System call to get the page table layout information
 * of the current system. Use syscall number 436.
 * int get_pagetable_layout(struct pagetable_layout_info __user *pgtbl_info);
 */
       
SYSCALL_DEFINE1(get_pagetable_layout,
	struct pagetable_layout_info __user *, pgtbl_info)
{
	struct pagetable_layout_info temp_info;

	if (pgtbl_info == NULL)
		return -EINVAL;

	temp_info.pgdir_shift = PGDIR_SHIFT;
	temp_info.p4d_shift = P4D_SHIFT;
	temp_info.pud_shift = PUD_SHIFT;
	temp_info.pmd_shift = PMD_SHIFT;
	temp_info.page_shift = PAGE_SHIFT;

	if (copy_to_user(pgtbl_info, &temp_info, sizeof(struct pagetable_layout_info)))
		return -EFAULT;
	return 0;
}

/*
 * Map a target process's page table into the current process's address space.
 * Use syscall number 437.
 * int expose_page_table(pid_t pid, struct expose_pgtbl_args __user *args);
 */

SYSCALL_DEFINE2(expose_page_table, pid_t, pid,
	struct expose_pgtbl_args __user *, args)
{
	struct expose_pgtbl_args temp_args;
	struct mm_struct *task_mm;
	struct vm_area_struct *task_vma;
	struct task_struct *task;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	/* start, end and current virtual addresses of struct VMA pages*/
	unsigned long start_va, end_va, curr_va;

	/* Validating and copying expose_pgtbl_args from userspace */
	if (args == NULL || pid < -1)
		return -EINVAL;
	if (copy_from_user(&temp_args, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	/* Finding task_struct, mm_struct and vm_area_struct of given PID*/
	read_lock(&tasklist_lock);
	if (pid == -1)
		task = current;
	else if (pid == 0)
		task = &init_task;
	else
		task = find_task_by_vpid(pid);
	read_unlock(&tasklist_lock);

	task_mm = get_task_mm(task);

	if (task_mm == NULL)
		return -EFAULT;

	task_vma = find_vma(task_mm, temp_args.begin_vaddr);

	if (task_vma == NULL)
		return -EFAULT;

	if (task != current)
		spin_lock(&task_mm->page_table_lock);

	/* Traversing list of struct VMA’s */
    	for (; task_vma->vm_next != NULL; task_vma = task_vma->vm_next) {
		/* Determining start and end of each struct VMA */
		if (task_vma->vm_start > temp_args.begin_vaddr)
			start_va = task_vma->vm_start;
		else
			start_va = temp_args.begin_vaddr;
		if (task_vma->vm_end < temp_args.end_vaddr)
			end_va = task_vma->vm_end;
		else
			end_va = temp_args.end_vaddr;

		/* Traversing the current struct VMA from its start to end*/
		for (curr_va = start_va; curr_va <= end_va; curr_va++) {
			/* Get corresponding PGD entry from PGD table
			 * of current page using its virtual address (curr_va)
			 */
			pgd = pgd_offset(task_mm, curr_va);
			if (pgd_none_or_clear_bad(pgd))
				continue;
			/*
			 * TODO: create function that creates and copies fake PGD table entries 
			 * to user provided fake_pgd.
			 */

			/*
			 * Get corresponding P4D entry from P4D table
			 * of current page using its virtual address (curr_va)
			 */
			p4d = p4d_offset(pgd, curr_va);
			if (p4d_none_or_clear_bad(p4d))
				continue;
			/*
			 * TODO: create function that creates and copies fake P4D table entry
			 * to user provided fake_p4d.
			 */

			/* 
			 * Get corresponding PUD entry from PUD table
			 * of current page using its virtual address (curr_va)
			 */
			pud = pud_offset(p4d, curr_va);
			if (pud_none_or_clear_bad(pud))
				continue;
			/*
			 * TODO: create function that creates and copies fake PUD table entry
			 * to user provided fake_pud.
			 */

			 /*
			  * Get corresponding PMD entry from PMD table
			  * of current page using its virtual address (curr_va)
			  */
			pmd = pmd_offset(pud, curr_va);
			if (pmd_none_or_clear_bad(pmd))
				continue;
			/*
			 * TODO: create function that creates and copies fake PMD table entry
			 * to user provided fake_pmd.
			 */
		}
	}
	if (task != current)
		spin_unlock(&task_mm->page_table_lock);
	return 0;
}

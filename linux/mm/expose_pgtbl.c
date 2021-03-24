#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm_types.h>

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
}

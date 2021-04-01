#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/expose_pgtbl.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/mm.h>

static int fake_p4d_tbl_count;
static int fake_pud_tbl_count;
static int fake_pmd_tbl_count;
static int fake_pte_tbl_count;

static inline int remap_fake_pte(struct mm_struct *task_mm,
		struct task_struct *p, pmd_t *orig_pmd,
		unsigned long fake_pmd, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	unsigned long pfn;
	unsigned long *fake_pmd_entry, fake_pte_addr;
	struct vm_area_struct *pte_vma;

	fake_pmd_entry = (unsigned long *) (fake_pmd +
					pmd_index(addr) * sizeof(long));
	fake_pte_addr = temp_args.page_table_addr +
		fake_pte_tbl_count * (PTRS_PER_PTE * sizeof(unsigned long));
	fake_pte_tbl_count++;
	if (copy_to_user(fake_pmd_entry, &fake_pte_addr, sizeof(unsigned long)))
		return -EFAULT;

	pfn = pmd_pfn(*orig_pmd);
	pte_vma = find_vma(current->mm, fake_pte_addr);
	if (pte_vma == NULL)
		return -EFAULT;

	if (p != current)
		down_write(&p->mm->mmap_sem);
	down_write(&current->mm->mmap_sem);
	if (remap_pfn_range(pte_vma, fake_pte_addr, pfn,
		     PAGE_SIZE, pte_vma->vm_page_prot)) {
		if (p != current)
			up_write(&p->mm->mmap_sem);
		up_write(&current->mm->mmap_sem);
		return -EAGAIN;
	}
	if (p != current)
		up_write(&p->mm->mmap_sem);
	up_write(&current->mm->mmap_sem);

	return 0;
}

static inline int ctor_fake_pmd(struct mm_struct *task_mm,
		struct task_struct *tsk, pud_t *orig_pud,
		unsigned long fake_pud, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	unsigned long next;
	unsigned long *fake_pud_entry, fake_pmd_addr;
	pmd_t *orig_pmd;
	int ret;

	fake_pud_entry = (unsigned long *) (fake_pud +
			pud_index(addr) * sizeof(unsigned long));
	orig_pmd = pmd_offset(orig_pud, addr);

	fake_pmd_addr = temp_args.fake_pmds +
		fake_pmd_tbl_count * (PTRS_PER_PMD * sizeof(unsigned long));
	fake_pmd_tbl_count++;

	if (copy_to_user(fake_pud_entry, &fake_pmd_addr, sizeof(unsigned long)))
		return -EFAULT;

	do {
		next = pmd_addr_end(addr, end);

		if (pmd_none(*orig_pmd) || unlikely(pmd_bad(*orig_pmd))) {
			continue;
		}
		ret = remap_fake_pte(task_mm, tsk, orig_pmd, fake_pmd_addr,
				temp_args, addr, next);
		if (ret)
			return ret;
	} while (orig_pmd++, addr = next, addr < end);

	return 0;
}

static inline int ctor_fake_pud(struct mm_struct *task_mm,
		struct task_struct *tsk, p4d_t *orig_p4d,
		unsigned long fake_p4d, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{

	unsigned long next;
	unsigned long *fake_p4d_entry, fake_pud_addr;
	pud_t *orig_pud;
	int ret;

	if (!pgtable_l5_enabled()) {
		fake_p4d_entry = (unsigned long *) (fake_p4d +
				pgd_index(addr) * sizeof(unsigned long));
	} else {
		fake_p4d_entry = (unsigned long *) (fake_p4d +
				p4d_index(addr) * sizeof(unsigned long));
	}
	orig_pud = pud_offset(orig_p4d, addr);

	fake_pud_addr = temp_args.fake_puds + fake_pud_tbl_count *
		(PTRS_PER_PUD * sizeof(unsigned long));
	fake_pud_tbl_count++;

	if (copy_to_user(fake_p4d_entry, &fake_pud_addr, sizeof(unsigned long)))
		return -EFAULT;

	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(orig_pud)) {
			continue;
		}
		ret = ctor_fake_pmd(task_mm, tsk, orig_pud, fake_pud_addr,
						temp_args, addr, next);
		if (ret)
			return ret;
	} while (orig_pud++, addr = next, addr < end);

	return 0;
}

static inline int ctor_fake_p4d(struct mm_struct *task_mm,
		struct task_struct *tsk, pgd_t *orig_pgd,
		unsigned long fake_pgd, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	int ret;
	unsigned long next;
        unsigned long *fake_pgd_entry, fake_p4d_addr;
        p4d_t *orig_p4d;

	if (!pgtable_l5_enabled()) {
		ret = ctor_fake_pud(task_mm, tsk, (p4d_t *)orig_pgd, fake_pgd,
				temp_args, addr, end);
		return ret;
	}

	fake_pgd_entry = (unsigned long *) (fake_pgd +
			pgd_index(addr) * sizeof(unsigned long));
	orig_p4d = p4d_offset(orig_pgd, addr);


	fake_p4d_addr = temp_args.fake_p4ds +
			fake_p4d_tbl_count *
			(PTRS_PER_P4D * sizeof(unsigned long));
	fake_p4d_tbl_count++;

	if (copy_to_user(fake_pgd_entry, &fake_p4d_addr, sizeof(unsigned long)))
		return -EFAULT;

	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(orig_p4d))
			continue;
		ret = ctor_fake_pud(task_mm, tsk, orig_p4d, fake_p4d_addr,
				temp_args, addr, next);
		if (ret)
			return ret;
	} while (orig_p4d++, addr = next, addr < end);

	return 0;
}


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

	if (copy_to_user(pgtbl_info, &temp_info,
				sizeof(struct pagetable_layout_info)))
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
	struct task_struct *task;
	unsigned long addr, end, next;
	unsigned long fake_pgd;
	pgd_t *orig_pgd;
	int ret;
	unsigned long total_p4d_size, total_pud_size;
	unsigned long total_pmd_size, total_pte_size;
	unsigned long used_p4d_size, used_pud_size;
	unsigned long used_pmd_size, used_pte_size;
	unsigned long begin_p4d_clear, begin_pud_clear;
	unsigned long begin_pmd_clear, begin_pte_clear;

	fake_p4d_tbl_count = 0;
	fake_pud_tbl_count = 0;
	fake_pmd_tbl_count = 0;
	fake_pte_tbl_count = 0;

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

	addr = temp_args.begin_vaddr;
	end = temp_args.end_vaddr;

	if (addr >= end)
		return -EINVAL;

	fake_pgd = temp_args.fake_pgd;
	orig_pgd = pgd_offset(task_mm, addr);
	do {
		next = pgd_addr_end(addr, end);

		if (pgd_none(*orig_pgd) || unlikely(pgd_bad(*orig_pgd))
				|| pgd_val(*orig_pgd) == 0)
			continue;
		ret = ctor_fake_p4d(task_mm, task, orig_pgd,
				fake_pgd, temp_args,
				addr, next);
		if (ret)
			return ret;
	} while (orig_pgd++, addr = next, addr < end);


	/* Clearing unused p4d tables */
	if (pgtable_l5_enabled()) {
		used_p4d_size = fake_p4d_tbl_count * PTRS_PER_P4D * sizeof(unsigned long);
		total_p4d_size = PTRS_PER_PGD * PTRS_PER_P4D * sizeof(unsigned long);
		begin_p4d_clear = temp_args.fake_p4ds + used_p4d_size;
		if (do_munmap(task_mm, begin_p4d_clear,
			(int) (total_p4d_size - used_p4d_size), NULL))
			return -ENOMEM;
	}

	/* Clearing unused pud tables */
	used_pud_size = fake_pud_tbl_count * PTRS_PER_PUD * sizeof(unsigned long);
	total_pud_size = PTRS_PER_PGD * PTRS_PER_P4D * PTRS_PER_PUD * sizeof(unsigned long);
	begin_pud_clear = temp_args.fake_puds + used_pud_size;
	if (do_munmap(task_mm, begin_pud_clear,
		(int) (total_pud_size - used_pud_size), NULL))
		return -ENOMEM;

	/* Clearing unused pmd tables */
	used_pmd_size = fake_pmd_tbl_count * PTRS_PER_PMD * sizeof(unsigned long);
	total_pmd_size = PTRS_PER_PMD * total_pud_size;
	begin_pmd_clear = temp_args.fake_pmds + used_pmd_size;
	if (do_munmap(task_mm, begin_pmd_clear,
		(int) (total_pmd_size - used_pmd_size), NULL))
		return -ENOMEM;

	/* Clearing unused pte tables */
	used_pte_size = fake_pte_tbl_count * PTRS_PER_PTE * sizeof(unsigned long);
	total_pte_size = 1 * total_pmd_size;
	begin_pte_clear = temp_args.page_table_addr + used_pte_size;
	if (do_munmap(task_mm, begin_pte_clear,
		(int) (total_pte_size - used_pte_size), NULL))
		return -ENOMEM;

	return 0;
}

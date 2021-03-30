#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/expose_pgtbl.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>

static int fake_p4d_tbl_count;
static int fake_pud_tbl_count;
static int fake_pmd_tbl_count;
static int fake_pte_tbl_count;

static inline int remap_fake_pte(struct mm_struct *task_mm, struct task_struct *p, pmd_t *orig_pmd,
	unsigned long fake_pmd, struct expose_pgtbl_args temp_args,
	unsigned long addr, unsigned long end)
{
	pr_info("Inside %s", __func__);

	unsigned long pfn;
	unsigned long *fake_pmd_entry, fake_pte_addr;
	struct vm_area_struct *pte_vma;

	fake_pmd_entry = (unsigned long *) (fake_pmd +
					pmd_index(addr) * sizeof(long));

	fake_pte_addr = temp_args.page_table_addr + fake_pte_tbl_count * (PTRS_PER_PTE * sizeof(unsigned long));
	fake_pte_tbl_count++;

	// if (tsk != current)
		// spin_unlock(&task_mm->page_table_lock);
	/* Releasing lock before copy_to_user call */
	if (copy_to_user(fake_pmd_entry, &fake_pte_addr, sizeof(unsigned long)))
		return -EFAULT;
	// if (tsk != current)
		// spin_lock(&task_mm->page_table_lock);

	pfn = pmd_pfn(*orig_pmd);
	pr_info("PFN VALUE -------------> %lu",pfn);

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

static inline int ctor_fake_pmd(struct mm_struct *task_mm, struct task_struct *tsk, pud_t *orig_pud,
		unsigned long fake_pud, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	pr_info("Inside %s", __func__);

	unsigned long next;
	unsigned long *fake_pud_entry, fake_pmd_addr;
	pmd_t *orig_pmd;
	int ret;

	fake_pud_entry = (unsigned long *) (fake_pud + 
					pud_index(addr) * sizeof(unsigned long));
	orig_pmd = pmd_offset(orig_pud, addr);

	fake_pmd_addr = temp_args.fake_pmds + fake_pmd_tbl_count * (PTRS_PER_PMD * sizeof(unsigned long));
	fake_pmd_tbl_count++;

	// if (tsk != current)
		// spin_unlock(&task_mm->page_table_lock);
	/* Releasing lock before copy_to_user call */
	if (copy_to_user(fake_pud_entry, &fake_pmd_addr, sizeof(unsigned long)))
		return -EFAULT;
	// if (tsk != current)
		// spin_lock(&task_mm->page_table_lock);

	do {
		pr_info("PMD START ADDRESS #############%lu",addr);
		next = pmd_addr_end(addr, end);
		pr_info("PMD NEXT ADDRESS %lu",next);
		pr_info("PMD END ADDRESS ##############%lu",end);
		pr_info("------> ORIGINAL PMD : ----> %lu",pmd_val(*orig_pmd));
		if (pmd_none_or_clear_bad(orig_pmd))
		{
			pr_info("@@@@@@@@@@@@@@@@@@@@@ INSIDE PMD NONE CLEAR BAD @@@@@@@@@@@@@@@@@@@@");
			continue;
		}
		pr_info("Calling remap_fake_pte");
		ret = remap_fake_pte(task_mm, tsk, orig_pmd, fake_pmd_addr, 
					temp_args, addr, next);
		pr_info("Back from remap_fake_pte with return value: %d", ret);
		if (ret)
			return ret;
	} while (fake_pmd_addr++, orig_pmd++, addr = next, addr != end);

	return 0;
}

static inline int ctor_fake_pud(struct mm_struct *task_mm, struct task_struct *tsk, p4d_t *orig_p4d,
		unsigned long fake_p4d, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	pr_info("Inside %s", __func__);

	unsigned long next;
	unsigned long *fake_p4d_entry, fake_pud_addr;
	pud_t *orig_pud;
	int ret;

	fake_p4d_entry = (unsigned long *) (fake_p4d +
				p4d_index(addr) * sizeof(unsigned long));
	orig_pud = pud_offset(orig_p4d, addr);

	fake_pud_addr = temp_args.fake_puds + fake_pud_tbl_count * (PTRS_PER_PUD * sizeof(unsigned long));
	fake_pud_tbl_count++;

	// if (tsk != current)
		// spin_unlock(&task_mm->page_table_lock);
	/* Releasing lock before copy_to_user call */
	if (copy_to_user(fake_p4d_entry, &fake_pud_addr, sizeof(unsigned long)))
		return -EFAULT;
	// if (tsk != current)
		// spin_lock(&task_mm->page_table_lock);

	do {
		pr_info("PUD START ADDRESS ++++++++++++++%lu",addr);
		next = pud_addr_end(addr, end);
		pr_info("PUD NEXT ADDRESS %lu",next);
		pr_info("PUD END ADDRESS ++++++++++++++%lu",end);
		if (pud_none_or_clear_bad(orig_pud))
			continue;
		pr_info("Calling ctor_fake_pmd");
		ret = ctor_fake_pmd(task_mm, tsk, orig_pud, fake_pud_addr,
						temp_args, addr, next);
		pr_info("Back from ctor_fake_pmd with return value: %d", ret);
		if (ret)
			return ret;
	} while (fake_pud_addr++, orig_pud++, addr = next, addr != end);

	return 0;
}

static inline int ctor_fake_p4d(struct mm_struct *task_mm, struct task_struct *tsk, pgd_t * orig_pgd,
		unsigned long fake_pgd, struct expose_pgtbl_args temp_args,
		unsigned long addr, unsigned long end)
{
	pr_info("Inside %s", __func__);
	int ret;
	if (!pgtable_l5_enabled()) {
		ret = ctor_fake_pud(task_mm, tsk, (p4d_t *)orig_pgd, fake_pgd,
				temp_args, addr, end);
		return ret;
	}
	
	unsigned long next;
	unsigned long *fake_pgd_entry, fake_p4d_addr;
	p4d_t *orig_p4d;

	pr_info("ADDR FROM P4D: %lu", addr);
	pr_info("fake_pgd: %lu", fake_pgd);

	// fake_pgd_entry = (unsigned long *) pgd_offset_pgd(fake_pgd, addr);
	fake_pgd_entry = (unsigned long *) (fake_pgd +
			pgd_index(addr) * sizeof(unsigned long));
	orig_p4d = p4d_offset(orig_pgd, addr);

	pr_info("fake_pgd_entry: %lu", (unsigned long) fake_pgd_entry);

	fake_p4d_addr = temp_args.fake_p4ds + fake_p4d_tbl_count * (PTRS_PER_P4D * sizeof(unsigned long));
	fake_p4d_tbl_count++;

	// if (tsk != current)
		// spin_unlock(&task_mm->page_table_lock);
	/* Releasing lock before copy_to_user call */
	if (copy_to_user(fake_pgd_entry, &fake_p4d_addr, sizeof(unsigned long)))
		return -EFAULT;
	// if (tsk != current)
		// spin_lock(&task_mm->page_table_lock);

	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(orig_p4d))
			continue;
		pr_info("Calling ctor_fake_pud");
		ret = ctor_fake_pud(task_mm, tsk, orig_p4d, fake_p4d_addr,
			 			temp_args, addr, next);
		pr_info("Back from ctor_fake_pud with return value: %d", ret);
		if (ret)
			return ret;
	} while (fake_p4d_addr++, orig_p4d++, addr = next, addr != end);

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
	struct task_struct *task;
	unsigned long addr, end, next;
	unsigned long fake_pgd;
	pgd_t *orig_pgd;
	int ret;

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
	
	fake_pgd = temp_args.fake_pgd;
	orig_pgd = pgd_offset(task_mm, addr);
	pr_info("FAKE PGD: %lu", fake_pgd);
    pr_info("ORIG PGD: %lu", pgd_val(*orig_pgd));
	do {
		next = pgd_addr_end(addr, end);
		pr_info("addr in MAIN func: %lu $$$$$$$", addr);
		pr_info("next in MAIN func: %lu", next);
		pr_info("END in MAIN func: %lu $$$$$$$$", end);
		if (pgd_none_or_clear_bad(orig_pgd))
			continue;
		pr_info("Calling ctor_fake_p4d");
		ret = ctor_fake_p4d(task_mm, task, orig_pgd, fake_pgd, temp_args,
					    addr, next);
		pr_info("Back from ctor_fake_p4d with return value: %d", ret);
		if (ret)
			return ret;
	} while (fake_pgd++, orig_pgd++, addr = next, addr != end);

	return 0;
}

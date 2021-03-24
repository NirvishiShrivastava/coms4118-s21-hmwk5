#ifndef _INCLUDE_EXPOSE_PGTBL_H
#define _INCLUDE_EXPOSE_PGTBL_H

/*
 * Struct to investigate the page table layout.
 */
 struct pagetable_layout_info {
        uint32_t pgdir_shift;
        uint32_t p4d_shift;
        uint32_t pud_shift;
        uint32_t pmd_shift;
        uint32_t page_shift;
 };

/*
 * Struct to map a target process's page table into the current process's address space.
 */
struct expose_pgtbl_args {
        unsigned long fake_pgd;
        unsigned long fake_p4ds;
        unsigned long fake_puds;
        unsigned long fake_pmds;
        unsigned long page_table_addr;
        unsigned long begin_vaddr;
        unsigned long end_vaddr;
};

#endif

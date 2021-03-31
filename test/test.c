#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define __NR_get_pagetable_layout 436
#define __NR_expose_page_table 437

#define PTR_PER_PXX 512
#define PAGE_SIZE 4096

struct pagetable_layout_info {
        uint32_t pgdir_shift;
        uint32_t p4d_shift;
        uint32_t pud_shift;
        uint32_t pmd_shift;
        uint32_t page_shift;
 };

struct expose_pgtbl_args {
        unsigned long fake_pgd;
        unsigned long fake_p4ds;
        unsigned long fake_puds;
        unsigned long fake_pmds;
        unsigned long page_table_addr;
        unsigned long begin_vaddr;
        unsigned long end_vaddr;
};

int get_pagetbl_layout(struct pagetable_layout_info *pgtbl_info)
{
    return syscall(__NR_get_pagetable_layout, pgtbl_info);
}

int expose_page_tbl(pid_t pid, struct expose_pgtbl_args *args)
{
    return syscall(__NR_expose_page_table, pid, args);
}

static inline unsigned long get_phys_addr(unsigned long pte_entry)
{
    return (((1UL << 52) - 1) & pte_entry) >> 12 << 12;
}

static inline int young_bit(unsigned long pte_entry)
{
    return 1UL << 5 & pte_entry ? 1 : 0;
}

static inline int dirty_bit(unsigned long pte_entry)
{
    return 1UL << 6 & pte_entry ? 1 : 0;
}

static inline int write_bit(unsigned long pte_entry)
{
    return 1UL << 1 & pte_entry ? 1 : 0;
}

static inline int user_bit(unsigned long pte_entry)
{
    return 1UL << 2 & pte_entry ? 1 : 0;
}

static inline unsigned long page_index(unsigned long address, uint32_t shift)
{
    return (address >> shift) & (PTR_PER_PXX - 1);
}
struct s {
	int a[9999];
};

int main(int argc, char *argv[])
{
    struct pagetable_layout_info pgtbl_info;
    struct expose_pgtbl_args pgtbl_args;
    pid_t pid;
    int pgd_size, p4d_size, pud_size, pmd_size, pte_size, verbose, ret;
    unsigned long va_begin, va_end, current_va, *addr, *addr1, *addr2, *addr3, *addr4;
    unsigned long *fake_pgd, *fake_p4ds, *fake_puds, *fake_pmds, *fake_ptes;
    unsigned long *f_pgd, *f_p4d, *f_pud, *f_pmd, f_pte;
    
    struct s *ptr = malloc(sizeof(struct s));
    verbose = 1;
    pid = -1;
    va_begin = (unsigned long) ptr;
    va_end = (unsigned long) ptr + sizeof(struct s);
    
   
    printf("%d, %ld, %ld\n", pid, va_begin, va_end);
    if(verbose)
	    printf("Verbose is set\n");

    /* Assigning begin and end VA */
    pgtbl_args.begin_vaddr = va_begin;
    pgtbl_args.end_vaddr = va_end;

    pgd_size = 512 * sizeof(unsigned long);
    p4d_size = 1 * pgd_size;
    pud_size = 512 * p4d_size;
    pmd_size = 512 * pud_size;
    pte_size = 1 * pmd_size;
    
    
    /* Allocating memory for page tables */
    addr = (unsigned long *)malloc(pgd_size);
    if (!addr)
            return -ENOMEM;
    
    pgtbl_args.fake_pgd = (unsigned long)addr;
   
    addr1 = mmap(NULL, p4d_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr1 == MAP_FAILED) {
	free(addr);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
     
    pgtbl_args.fake_p4ds = (unsigned long)addr1;
    
    addr2 = mmap(NULL, pud_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr2 == MAP_FAILED) {
	free(addr);
	munmap(addr1,p4d_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pgtbl_args.fake_puds = (unsigned long)addr2;
    addr3 = mmap(NULL, pmd_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr3 == MAP_FAILED) {
	free(addr);
	munmap(addr1,p4d_size);
	munmap(addr2,pud_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
 
    pgtbl_args.fake_pmds = (unsigned long)addr3;
    addr4 = mmap(NULL, pte_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr4 == MAP_FAILED) {
	free(addr);
	munmap(addr1,p4d_size);
	munmap(addr2,pud_size);
	munmap(addr3,pmd_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pgtbl_args.page_table_addr = (unsigned long)addr4;
    
    /* Calling Get Page Table Layout System Call */
    ret = get_pagetbl_layout(&pgtbl_info);
    if (ret < 0) {
	free(addr);
	munmap(addr1,p4d_size);
	munmap(addr2,pud_size);
	munmap(addr3,pmd_size);
	munmap(addr4,pte_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        printf("Get Page Table Layout System Call Failed.\n");
        exit(EXIT_FAILURE);
    }
    
    printf("pgdir_shift: %d, p4d_shift: %d, pud_shift: %d, pmd_shift: %d, page_shift: %d \n\n", pgtbl_info.pgdir_shift, pgtbl_info.p4d_shift, pgtbl_info.pud_shift, pgtbl_info.pmd_shift, pgtbl_info.page_shift);
    
    
    printf("FAKE Addresses: %lu, %lu, %lu, %lu, %lu", pgtbl_args.fake_pgd,
		    pgtbl_args.fake_p4ds, pgtbl_args.fake_puds, pgtbl_args.fake_pmds,
		    pgtbl_args.page_table_addr);
    /* Calling Expose Page Table System Call */
    ret = expose_page_tbl(pid, &pgtbl_args);
    if (ret < 0) {
	free(addr);
	munmap(addr1,p4d_size);
	munmap(addr2,pud_size);
	munmap(addr3,pmd_size);
	munmap(addr4,pte_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        printf("Expose Page Table System Call Failed.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Printing the Page Entries */
    fake_pgd = (unsigned long *)pgtbl_args.fake_pgd;
    printf("\nPrinting Fake PGD Table:\n");
    for (int i = 0; i < 512; i++) {
	    if (fake_pgd[i])
		    printf("PGD Index (%d): %lu\n", i, fake_pgd[i]);
    }
    
    fake_p4ds = (unsigned long *)pgtbl_args.fake_p4ds;
    printf("Printing Fake P4Ds Table:\n");
    for (int i = 0; i < 512; i++) {
            if (fake_p4ds[i])
                    printf("P4D Index (%d): %lu\n", i, fake_p4ds[i]);
    }
   
    fake_puds = (unsigned long *)pgtbl_args.fake_puds;
    printf("Printing Fake PUDs Table:\n");
    for (int i = 0; i < 512; i++) {
            if (fake_puds[i])
                    printf("PUD Index (%d): %lu\n", i, fake_puds[i]);
    }

    fake_pmds = (unsigned long *)pgtbl_args.fake_pmds;
    printf("Printing Fake PMDs Table:\n");
    for (int i = 0; i < 512; i++) {
            if (fake_pmds[i])
                    printf("PMD Index (%d): %lu\n", i, fake_pmds[i]);
    }

    fake_ptes = (unsigned long *)pgtbl_args.page_table_addr;
    printf("Printing Fake PTEs Table:\n");
    for (int i = 0; i < 512; i++) {
            if (fake_ptes[i])
                    printf("PTE Index (%d): %lu\n", i, fake_ptes[i]);
    }


    for (current_va = va_begin; current_va < va_end; current_va += PAGE_SIZE) {
        
        f_pgd = (unsigned long *)fake_pgd[page_index( current_va, pgtbl_info.pgdir_shift )];
        if(f_pgd == 0)
            continue;
        
        /*f_p4d = (unsigned long *)f_pgd[page_index( current_va, pgtbl_info.p4d_shift )];
        if (f_p4d == 0)
            continue;
        */
        f_pud = (unsigned long *)f_pgd[page_index( current_va, pgtbl_info.pud_shift )];
        if (f_pud == 0)
            continue;
        
        f_pmd = (unsigned long *)f_pud[page_index( current_va, pgtbl_info.pmd_shift )];
        if (f_pmd == 0)
            continue;
        
        f_pte = f_pmd[page_index( current_va, pgtbl_info.page_shift )];
        if (f_pte == 0) {
            if (verbose)
                /* If a page is not present and the -v option is used */
                printf("0xdead00000000 0x00000000000 0 0 0 0\n");
            continue;
            
        }
        
        printf("%#014lx %#013lx %d %d %d %d\n", current_va, get_phys_addr(f_pte), young_bit(f_pte), dirty_bit(f_pte), write_bit(f_pte), user_bit(f_pte));
        
    }
    
    
    /* Free allocated space */
    free(addr);
    munmap(addr1,p4d_size);
    munmap(addr2,pud_size);
    munmap(addr3,pmd_size);
    munmap(addr4,pte_size);
    
    return 0;
    
}

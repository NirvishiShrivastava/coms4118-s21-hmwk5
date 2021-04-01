#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/wait.h>

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
struct temp {
    int a[9999];
};


int get_pagetable_range(unsigned long start, unsigned long end)
{
    struct pagetable_layout_info pgtbl_info;
    struct expose_pgtbl_args pgtbl_args;
    pid_t pid;
    int pgd_size, p4d_size, pud_size, pmd_size, pte_size, verbose, ret;
    unsigned long va_begin, va_end, current_va, *addr, *addr1, *addr2, *addr3, *addr4;
    unsigned long *fake_pgd;
    unsigned long *f_pgd, *f_p4d, *f_pud, *f_pmd, f_pte;
    
    verbose = 1;
    pid = -1;
    va_begin = start;
    va_end = end;
    
    /* Assigning begin and end VA */
    pgtbl_args.begin_vaddr = va_begin;
    pgtbl_args.end_vaddr = va_end;

    /* Calling Get Page Table Layout System Call */
    ret = get_pagetbl_layout(&pgtbl_info);
    if (ret < 0) {
        fprintf(stderr, "Error : %s\n", strerror(errno));
        printf("Get Page Table Layout System Call Failed.\n");
        return ret;
    }
    
    pgd_size = PTR_PER_PXX * sizeof(unsigned long);
    /* Check if paging level is 4 or 5 */
    if (pgtbl_info.pgdir_shift == pgtbl_info.p4d_shift)
        p4d_size = 1 * pgd_size;
    else
        p4d_size = PTR_PER_PXX * pgd_size;
    
    pud_size = PTR_PER_PXX * p4d_size;
    pmd_size = PTR_PER_PXX * pud_size;
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
        return -1;
    }
     
    pgtbl_args.fake_p4ds = (unsigned long)addr1;
    
    addr2 = mmap(NULL, pud_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr2 == MAP_FAILED) {
    free(addr);
    munmap(addr1,p4d_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        return -1;
    }

    pgtbl_args.fake_puds = (unsigned long)addr2;
    addr3 = mmap(NULL, pmd_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr3 == MAP_FAILED) {
    free(addr);
    munmap(addr1,p4d_size);
    munmap(addr2,pud_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        return -1;
    }
 
    pgtbl_args.fake_pmds = (unsigned long)addr3;
    addr4 = mmap(NULL, pte_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (addr4 == MAP_FAILED) {
    free(addr);
    munmap(addr1,p4d_size);
    munmap(addr2,pud_size);
    munmap(addr3,pmd_size);
        fprintf(stderr, "Error : %s\n", strerror(errno));
        return -1;
    }

    pgtbl_args.page_table_addr = (unsigned long)addr4;
    
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
        return ret;
    }
    
    /* Page Entries */
    fake_pgd = (unsigned long *)pgtbl_args.fake_pgd;
    
    for (current_va = va_begin; current_va < va_end; current_va += PAGE_SIZE) {
        f_pgd = (unsigned long *)fake_pgd[page_index( current_va, pgtbl_info.pgdir_shift )];
            if(f_pgd == 0)
                    goto verbose_continue;
    
	    if (pgtbl_info.pgdir_shift != pgtbl_info.p4d_shift) {
            	f_p4d = (unsigned long *)f_pgd[page_index( current_va, pgtbl_info.p4d_shift )];
            	if (f_p4d == 0)
                	goto verbose_continue;

            	f_pud = (unsigned long *)f_p4d[page_index( current_va, pgtbl_info.pud_shift )];
            	if (f_pud == 0)
                	goto verbose_continue;
            } else {
            	f_pud = (unsigned long *)f_pgd[page_index( current_va, pgtbl_info.pud_shift )];
            	if (f_pud == 0)
                	goto verbose_continue;
      	    }

            f_pmd = (unsigned long *)f_pud[page_index( current_va, pgtbl_info.pmd_shift )]; 
            if (f_pmd == 0)
                    goto verbose_continue;
    
            f_pte = f_pmd[page_index( current_va, pgtbl_info.page_shift )]; 
            if (f_pte == 0)
                    goto verbose_continue;

            printf("%#014lx %#013lx %d %d %d %d\n", current_va, get_phys_addr(f_pte), young_bit(f_pte), dirty_bit(f_pte), write_bit(f_pte), user_bit(f_pte));
            continue;

verbose_continue:
            if (verbose) {
                /* If a page is not present and the -v option is used */
                printf("0xdead00000000 0x00000000000 0 0 0 0\n");
            }   
            continue; 
    }
    
    
    /* Free allocated space */
    free(addr);
    munmap(addr1,p4d_size);
    munmap(addr2,pud_size);
    munmap(addr3,pmd_size);
    munmap(addr4,pte_size);
    
    return 0;
    
}

int main(int argc, char *argv[])
{
    int ret, read_var;

    printf("\n============================================\n");
    printf("TESTCASE 1: Allocating heap memory but not using it.\n");
    printf("============================================\n\n");
    
    printf("virtual_addr   physical_addr Y D W U\n");
    struct temp *test1 = malloc(sizeof(struct temp));
    if (!test1)
        return -ENOMEM;
    ret = get_pagetable_range((unsigned long) test1, (unsigned long) test1 + sizeof(struct temp) - 1);

    if (ret < 0) {
        free(test1);
        return -1;
    }

    printf("\n============================================\n");
    printf("TESTCASE 2: Write Fault\n");
    printf("============================================\n\n");
    
    struct temp *test2 = malloc(sizeof(struct temp));
    if (!test2) {
        free(test1);
        return -ENOMEM;
    }

    printf("Before Write Fault\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test2, (unsigned long) test2 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        return -1;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        test2->a[i] = 5;
        
    printf("\nAfter Write Fault\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test2, (unsigned long) test2 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        return -1;
    }

    printf("\n============================================\n");
    printf("TESTCASE 3: Read Fault followed by a Write\n");
    printf("============================================\n\n");
    
    struct temp *test3 = malloc(sizeof(struct temp));
    if (!test3) {
        free(test1);
        free(test2);
        return -ENOMEM;
    }

    printf("Before Read Fault\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test3,(unsigned long) test3 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        return -1;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        read_var = test3->a[i];

    printf("\nAfter Read Fault\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test3, (unsigned long) test3 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        return -1;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        test3->a[i] = 5;
    printf("\nAfter Write\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test3, (unsigned long) test3 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        return -1;
    }

    printf("\n============================================\n");
    printf("TESTCASE 4: Write (without fault)\n");
    printf("============================================\n\n");
    
    struct temp *test4 = malloc(sizeof(struct temp));
    if (!test4) {
        free(test1);
        free(test2);
        free(test3);
        return -ENOMEM;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        test4->a[i] = 5;
    printf("Before Write\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test4, (unsigned long) test4 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        free(test4);
        return -1;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        test4->a[i] = 15;
    printf("\nAfter Write\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test4, (unsigned long) test4 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        free(test4);
        return -1;
    }

    printf("\n============================================\n");
    printf("TESTCASE 5: Copy On Write\n");
    printf("============================================\n");
    
    struct temp *test5 = malloc(sizeof(struct temp));
    if (!test5) {
        free(test1);
        free(test2);
        free(test3);
        free(test4);
        return -ENOMEM;
    }

    for (unsigned long i = 0; i < 9999; ++i)
        test5->a[i] = 5;
    printf("\nParent\n");
    printf("virtual_addr   physical_addr Y D W U\n");
    ret = get_pagetable_range((unsigned long) test5, (unsigned long) test5 + sizeof(struct temp) - 1);
    if (ret < 0) {
        free(test1);
        free(test2);
        free(test3);
        free(test4);
        free(test5);
        return -1;
    }

    if (fork() == 0) {
        printf("\nChild\n");
        printf("virtual_addr   physical_addr Y D W U\n");
        ret = get_pagetable_range((unsigned long) test5, (unsigned long) test5 + sizeof(struct temp) - 1);
        if (ret < 0) {
            free(test1);
            free(test2);
            free(test3);
            free(test4);
            free(test5);
            return -1;
        }

    	for (unsigned long i = 0; i < 9999; ++i)
        	test5->a[i] = 5;

        printf("\nAfter Child writes\n");
        printf("virtual_addr   physical_addr Y D W U\n");
        ret = get_pagetable_range((unsigned long) test5, (unsigned long) test5 + sizeof(struct temp) - 1);
        if (ret < 0) {
            free(test1);
            free(test2);
            free(test3);
            free(test4);
            free(test5);
            return -1;
        }
    }

    else
        wait(NULL);

    free(test1);
    free(test2);
    free(test3);
    free(test4);
    free(test5);

    read_var = 0;
    return read_var;
}

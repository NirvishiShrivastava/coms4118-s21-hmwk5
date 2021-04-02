
TESTCASE 1: Allocating heap memory but not using it.
============================================

Test Performed: We dynamically allocated 10 pages worth of memory and called our system call (expose_pgtbl) to view virtual to physical address mapping.

Obeservation: Following is the output from our test which verifies allocation of one real page and rest are unmapped which confirms that no physical pages were allocated for the malloc'd virtual address range. 

virtual_addr   physical_addr Y D W U
0x5620f5bb2670 0x0008589b000 1 1 1 1
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0


TESTCASE 2: Write Fault
============================================

Test Performed: We dynamically allocated 10 pages worth of memory and called our system call (expose_pgtbl) to view virtual to physical address mapping. After viewing the allocation, we performed a write operation by assigning values to the requested memory.

Obeservation: Here we see initially physical pages weren't allocated for the virtual address range. Following the write operation, page faults are raised and then at that time kernel allocates actual physical pages and maps to the virtual addresses. Also since the data was recently written the dirty and write bits were set.

Before Write Fault
virtual_addr   physical_addr Y D W U
0x5620f5bbc680 0x00090b9e000 1 1 1 1
0x5620f5bbd680 0x000907f7000 1 1 1 1
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0

After Write Fault
virtual_addr   physical_addr Y D W U
0x5620f5bbc680 0x00090b9e000 1 1 1 1
0x5620f5bbd680 0x000907f7000 1 1 1 1
0x5620f5bbe680 0x000861f3000 1 1 1 1
0x5620f5bbf680 0x00085066000 1 1 1 1
0x5620f5bc0680 0x0008657e000 1 1 1 1
0x5620f5bc1680 0x00085927000 1 1 1 1
0x5620f5bc2680 0x0008504c000 1 1 1 1
0x5620f5bc3680 0x0008fd0e000 1 1 1 1
0x5620f5bc4680 0x00085906000 1 1 1 1
0x5620f5bc5680 0x000901a6000 1 1 1 1

TESTCASE 3: Read Fault followed by a Write
============================================

Test Performed: We dynamically allocated 10 pages worth of memory and called our system call (expose_pgtbl) to view virtual to physical address mapping. After viewing the allocation, we performed a read operation followed by a write operation.

Obeservation: Here we see initially physical pages weren't allocated for the virtual address range. Following the read operation, page faults are raised and then at that time kernel allocates actual physical pages and maps to the virtual addresses. 

Before Read Fault
virtual_addr   physical_addr Y D W U
0x5620f5bc6690 0x000847df000 1 1 1 1
0x5620f5bc7690 0x00085062000 1 1 1 1
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0
0xdead00000000 0x00000000000 0 0 0 0

After Read Fault
virtual_addr   physical_addr Y D W U
0x5620f5bc6690 0x000847df000 1 1 1 1
0x5620f5bc7690 0x00085062000 1 1 1 1
0x5620f5bc8690 0x00060503000 1 0 0 1
0x5620f5bc9690 0x00060503000 1 0 0 1
0x5620f5bca690 0x00060503000 1 0 0 1
0x5620f5bcb690 0x00060503000 1 0 0 1
0x5620f5bcc690 0x00060503000 1 0 0 1
0x5620f5bcd690 0x00060503000 1 0 0 1
0x5620f5bce690 0x00060503000 1 0 0 1
0x5620f5bcf690 0x00060503000 1 0 0 1

After Write
virtual_addr   physical_addr Y D W U
0x5620f5bc6690 0x000847df000 1 1 1 1
0x5620f5bc7690 0x00085062000 1 1 1 1
0x5620f5bc8690 0x00090539000 1 1 1 1
0x5620f5bc9690 0x00084c9d000 1 1 1 1
0x5620f5bca690 0x00090aa0000 1 1 1 1
0x5620f5bcb690 0x00085e2f000 1 1 1 1
0x5620f5bcc690 0x00086669000 1 1 1 1
0x5620f5bcd690 0x00084e85000 1 1 1 1
0x5620f5bce690 0x00084c26000 1 1 1 1
0x5620f5bcf690 0x00084c39000 1 1 1 1

TESTCASE 4: Write (without fault)
============================================

Test Performed: We dynamically allocated 10 pages worth of memory and performed a write operation by assigning values to the requested memory.Post which we called our system call (expose_pgtbl) to view virtual to physical address mapping. Then once again we did a write and exposed our fake pagetable mappings.

Obeservation: Here we see physical pages were allocated for the entire virtual address range when the first write operation was done. On second write operation since all the required pages were already allocated there were no more page faults raised and the new entries were over written on the same physical address. 

Before Write
virtual_addr   physical_addr Y D W U
0x5620f5bd06a0 0x00085909000 1 1 1 1
0x5620f5bd16a0 0x00085885000 1 1 1 1
0x5620f5bd26a0 0x00085691000 1 1 1 1
0x5620f5bd36a0 0x00090b2f000 1 1 1 1
0x5620f5bd46a0 0x000856a5000 1 1 1 1
0x5620f5bd56a0 0x0008fdee000 1 1 1 1
0x5620f5bd66a0 0x0008fdb5000 1 1 1 1
0x5620f5bd76a0 0x0008516a000 1 1 1 1
0x5620f5bd86a0 0x00085888000 1 1 1 1
0x5620f5bd96a0 0x00090ac6000 1 1 1 1

After Write
virtual_addr   physical_addr Y D W U
0x5620f5bd06a0 0x00085909000 1 1 1 1
0x5620f5bd16a0 0x00085885000 1 1 1 1
0x5620f5bd26a0 0x00085691000 1 1 1 1
0x5620f5bd36a0 0x00090b2f000 1 1 1 1
0x5620f5bd46a0 0x000856a5000 1 1 1 1
0x5620f5bd56a0 0x0008fdee000 1 1 1 1
0x5620f5bd66a0 0x0008fdb5000 1 1 1 1
0x5620f5bd76a0 0x0008516a000 1 1 1 1
0x5620f5bd86a0 0x00085888000 1 1 1 1
0x5620f5bd96a0 0x00090ac6000 1 1 1 1

TESTCASE 5: Copy On Write
============================================

Test Performed: We dynamically allocated 10 pages worth of memory and called fork system call to create a child process. Following which we called our system call (expose_pgtbl) to view virtual to physical address mappings. Then to test copy-on-write a write operation was performed on the child's address space.

Obeservation: We observed that in case of Linux with MMU fork works with copy-on-write. It only (allocates and) copies a few system structures and the page table, but the heap pages actually point to the ones of the parent until written. As for the allocation, the underlying memory pages point to the original physical ones of the parent process, so no extra memory pages are needed until they are modified. The copy-on-write also makes sure that the pages are write protected and hence we see the write bit for all the pages are set to 0 because of which when either the parent or the child writes to those pages a page fault occurs and new pages are allocated for the virtual address of the process performing the write operation.


Parent
virtual_addr   physical_addr Y D W U
0x5620f5bda6b0 0x00084f4a000 1 1 1 1
0x5620f5bdb6b0 0x00085f3a000 1 1 1 1
0x5620f5bdc6b0 0x000859bd000 1 1 1 1
0x5620f5bdd6b0 0x000863c7000 1 1 1 1
0x5620f5bde6b0 0x00085976000 1 1 1 1
0x5620f5bdf6b0 0x0008595b000 1 1 1 1
0x5620f5be06b0 0x000958b3000 1 1 1 1
0x5620f5be16b0 0x00085c53000 1 1 1 1
0x5620f5be26b0 0x000858da000 1 1 1 1
0x5620f5be36b0 0x00084f93000 1 1 1 1

Child
virtual_addr   physical_addr Y D W U
0x5620f5bda6b0 0x00084f4a000 0 1 0 1
0x5620f5bdb6b0 0x00085f3a000 0 1 0 1
0x5620f5bdc6b0 0x000859bd000 0 1 0 1
0x5620f5bdd6b0 0x000863c7000 0 1 0 1
0x5620f5bde6b0 0x00085976000 0 1 0 1
0x5620f5bdf6b0 0x0008595b000 0 1 0 1
0x5620f5be06b0 0x000958b3000 0 1 0 1
0x5620f5be16b0 0x00085c53000 0 1 0 1
0x5620f5be26b0 0x000858da000 0 1 0 1
0x5620f5be36b0 0x00084f93000 0 1 0 1

After Child writes
virtual_addr   physical_addr Y D W U
0x5620f5bda6b0 0x00085f82000 1 1 1 1
0x5620f5bdb6b0 0x00085e5f000 1 1 1 1
0x5620f5bdc6b0 0x00085f83000 1 1 1 1
0x5620f5bdd6b0 0x00085986000 1 1 1 1
0x5620f5bde6b0 0x00084d8b000 1 1 1 1
0x5620f5bdf6b0 0x00085191000 1 1 1 1
0x5620f5be06b0 0x00090838000 1 1 1 1
0x5620f5be16b0 0x00085881000 1 1 1 1
0x5620f5be26b0 0x00090469000 1 1 1 1
0x5620f5be36b0 0x00086423000 1 1 1 1

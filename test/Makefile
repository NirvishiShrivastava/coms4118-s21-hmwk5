AS = gcc
FLAGS = -Wall

all: vm_inspector test_cases

vm_inspector: vm_inspector.c
	$(AS) $(FLAGS) $< -o $@

test_cases: test_cases.c
	$(AS) $(FLAGS) $< -o $@

clean:
	rm vm_inspector test_cases

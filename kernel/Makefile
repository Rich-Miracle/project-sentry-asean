CLANG    ?= clang
ARCH     := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

tc_hook.o: tc_hook.c tc_hook.h
	$(CLANG) $(BPF_CFLAGS) -c tc_hook.c -o tc_hook.o

verify: tc_hook.o
	bpftool prog show

clean:
	rm -f tc_hook.o

.PHONY: verify clean

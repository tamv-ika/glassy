# XDP objects for the S3 probe. Needs clang with the BPF target and libbpf headers
# (Ubuntu: clang libbpf-dev).
CLANG ?= clang
ARCH_INCLUDE := /usr/include/$(shell uname -m)-linux-gnu
CFLAGS := -O2 -g -target bpf -Wall -Werror -I$(ARCH_INCLUDE)

all: xdp_pass.o xdp_reflect.o

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

.PHONY: all clean

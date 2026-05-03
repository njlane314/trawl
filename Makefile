# Trawl eBPF causal profiler.
# Requires clang, bpftool, libbpf, libelf, zlib, and kernel BTF at /sys/kernel/btf/vmlinux.

BUILD := build
BPF_CLANG ?= clang
CC ?= cc
ARCH ?= x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(BUILD) -Ibpf
USER_CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD) -Ibpf -Iinclude
USER_LDLIBS := -lbpf -lelf -lz -pthread -ldl -lm

.PHONY: all clean examples docker-build docker-demo docker-auto docker-smoke
all: $(BUILD)/trawl $(BUILD)/trawlctl $(BUILD)/trawl-studio $(BUILD)/libtrawl_shim.so

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/vmlinux.h: include/trawl_min_vmlinux.h | $(BUILD)
	if [ -r /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		cp include/trawl_min_vmlinux.h $@; \
	fi

$(BUILD)/trawl.bpf.o: bpf/trawl.bpf.c bpf/trawl_shared.h $(BUILD)/vmlinux.h | $(BUILD)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/trawl.skel.h: $(BUILD)/trawl.bpf.o
	bpftool gen skeleton $< > $@

$(BUILD)/trawlctl: src/trawlctl.c include/trawl_shm.h bpf/trawl_shared.h $(BUILD)/trawl.skel.h | $(BUILD)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

$(BUILD)/trawl-studio: src/trawl_studio.c | $(BUILD)
	$(CC) $(USER_CFLAGS) $< -o $@

$(BUILD)/trawl: scripts/trawl-wrapper.sh $(BUILD)/trawlctl $(BUILD)/trawl-studio | $(BUILD)
	cp $< $@
	chmod +x $@

$(BUILD)/libtrawl_shim.so: shim/trawl_shim.c include/trawl_shm.h include/trawl_marker.h | $(BUILD)
	$(CC) -g -O2 -Wall -Wextra -fPIC -shared -Iinclude $< -o $@ -ldl -pthread

examples: all
	$(MAKE) -C examples

clean:
	rm -rf $(BUILD)
	$(MAKE) -C examples clean

docker-build:
	./scripts/docker-build.sh

docker-demo:
	./scripts/run-demo.sh

docker-auto:
	./scripts/run-auto.sh

docker-smoke:
	./scripts/smoke-test.sh

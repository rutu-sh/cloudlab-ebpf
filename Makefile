CL_DIR=${CURDIR}/.cloudlab
TOOLS_SRC_DIR=${CURDIR}/setup/cloudlab-tools

.PHONY: all
all:
	@echo "Setting up eBPF..."
	cd ${CURDIR}/setup/cloudlab-tools/tools/ebpf && \
	$(MAKE) && \
	echo "eBPF setup complete"

include setup/cloudlab-tools/cloudlab_tools.mk

update-cl-tools:
	@echo "Updating cloudlab tools..."
	cd ${CURDIR}/setup/cloudlab-tools && git pull origin && cd ../.. && \
	echo "Cloudlab tools updated"


update-headers:
	@echo "Updating headers..."
	cd ${CURDIR}/lib/bpf-headers && \
		git clone https://github.com/libbpf/libbpf.git && \
		rm -r bpf/* && \
		cp -r libbpf/src/* bpf/ && \
		rm -r libbpf && \
		cd ${CURDIR} && \
		git submodule update --remote --merge lib/bpf-headers && \
		echo "Headers updated"
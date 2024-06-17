CL_DIR=${CURDIR}/.cloudlab
TOOLS_SRC_DIR=${CURDIR}/setup/cloudlab-tools
include setup/cloudlab-tools/cloudlab_tools.mk


update-cl-tools:
	@echo "Updating cloudlab tools..."
	@cd setup/cloudlab-tools && git pull origin && cd ../.. && \
	echo "Cloudlab tools updated"


setup:
	@echo "Setting up eBPF..."
	@cd setup/cloudlab-tools/tools/ebpf && \
	$(MAKE) setup && \
	echo "eBPF setup complete"

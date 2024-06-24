# Cloudlab eBPF

![](./docs/assets/cloudlab-ebpf.svg)

This repository contains the experimentation setup with eBPF on CloudLab. It uses the [cloudlab-tools](https://github.com/rutu-sh/cloudlab-tools/tree/main) repository as the submodule to automate the setup for running eBPF programs on CloudLab. 

To update the repository to use the latest version of the `cloudlab-tools` submodule, run the following command:

```bash
make update-cl-tools
```

## CloudLab setup 

1. Run the following command to create the required CloudLab config. This will create a `.cloudlab/cloudlab_config.mk` file which will be used to setup the CloudLab environment. Add your CloudLab username, ssh-key path, and the node IPs in the file.: 
```bash
make cl-setup
```

2. Open terminal (call it `terminal-1`) and SSH into the CloudLab machine and run the following command (replace `NODE_1` with the node name).
```bash
make cl-ssh-host NODE=NODE_1
```
3. Clone the repository in the CloudLab machine by running the following command in `terminal-1`.
```bash
git clone --recursive https://github.com/rutu-sh/cloudlab-ebpf.git
```
 or 

If you want to upload the code from local to CloudLab machine, open another terminal (call it `terminal-2`) and run the following command. This is a good option if you want to try out your code without the need to commit and push it to the repository.

 ```bash
 make cl-sync-code NODE=NODE_1
 ```

To sync the code to a particular path on the cloudlab node, run the following command:

```bash
make cl-sync-code NODE=NODE_1 REMOTE_DIR=PATH_ON_NODE
```



By default, the remote dir is `~/src`. 

4. CD into the the `cloudlab-ebpf` directory in cloudlab (in `terminal-1`) and run the following command to setup the environment:

```bash
make
```

5. Create a folder for your experiment in the experiments directory and add the eBPF `C` code and the `gen.go` file. The `gen.go` file is used to generate the `BPF` bytecode from the `C` code. But it requires clang, llvm, and other dependencies. If you're using a Mac, run the following command. This will perform the code generation part and copy the generated go and the object files to your experiment folder. Then you can start working on the rest of the go code.

```bash
make go-generate-exp NODE=NODE_0 EXPERIMENT=<experiment-name>
```

Example: 
```bash
make go-generate-exp NODE=NODE_0 EXPERIMENT=simple-tracepoint-hook
```


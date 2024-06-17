# Cloudlab eBPF

This repository contains the experimentations with eBPF on CloudLab. It uses the [cloudlab-tools](https://github.com/rutu-sh/cloudlab-tools/tree/main) repository as the submodule to automate the setup for running eBPF programs on CloudLab. 

To update the repository to use the latest version of the `cloudlab-tools` submodule, run the following command:

```bash
make update-cl-tools
```

## CloudLab setup 

1. Create a `.cloudlab/config` file in this directory and add the content as mentioned [here](https://github.com/rutu-sh/cloudlab-tools?tab=readme-ov-file#setting-up-cloudlab)
2. Open terminal (call it `terminal-1`) and SSH into the CloudLab machine and run the following command (replace `NODE_1` with the node name):
```bash
make cl-ssh-host NODE=NODE_1
```
3. Clone the repository in the CloudLab machine by running the following command in `terminal-1`:
```bash
git clone --recursive https://github.com/rutu-sh/cloudlab-ebpf.git
```
 or 

 If you want to upload the code from local to CloudLab machine, open another terminal (call it `terminal-2`) and run the following command:

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
make setup
```



# Dependencies

- Need Clang + llvm-dev version 3.X for any (2 <= X <= 4)
- http://llvm.org/apt/

apt-get install libelf-dev clang-3.4 llvm-3.4-dev

# Build LLVM plugin

*[Upstream] git://git.kernel.org/pub/scm/linux/kernel/git/ast/bpf*

git clone git://github.com/joestringer/linux
NN=$PWD/linux

cd $NN/tools/bpf/llvm/bld
make LLVM_CONFIG=`which llvm-config-3.4`

# Configure OVS to use BPF LLC

OVS=/path/to/openvswitch
cd $OVS
./configure --with-llc=$NN/tools/bpf/llvm/bld/Debug+Asserts/bin/llc

# Build OVS and BPF module

make
cd datapath/bpf
make

# Load BPF module

cd $NN/
make M=samples/bpf
samples/bpf/simple_load $OVS/datapath/bpf/simple.bpf

Note down which fd was used for the program. This will be used in next step.

# Install flow to use BPF

$OVS/utilities/ovs-dpctl add-flow "eth(src=00:00:00:00:00:00,dst=00:00:00:00:00:00)" "bpf(<FD>, 0)"

Success?

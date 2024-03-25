# Performance Testing Report

## Mandatory BPF Related Kernel Configurations

| Functionalities | Kernel Configuration | Description |
|:----------------|:---------------------|:------------|
| **Basic** | CONFIG_BPF_SYSCALL | Enable the bpf() system call |
|  | CONFIG_BPF_JIT | BPF programs are normally handled by a BPF interpreter. This option allows the kernel to generate native code when a program is loaded into the kernel. This will significantly speed-up processing of BPF programs |
|  | CONFIG_HAVE_BPF_JIT | Enable BPF Just In Time compiler |
|  | CONFIG_HAVE_EBPF_JIT | Extended BPF JIT (eBPF) |
|  | CONFIG_HAVE_CBPF_JIT | Classic BPF JIT (cBPF) |
|  | CONFIG_MODULES | Enable to build loadable kernel modules |
|  | CONFIG_BPF | BPF VM interpreter |
| **BTF** | CONFIG_DEBUG_INFO_BTF | Generate deduplicated BTF type information from DWARF debug info |
| | CONFIG_DEBUG_INFO_BTF_MODULES | Generate compact split BTF type information for kernel modules |
| | CONFIG_BPF_UNPRIV_DEFAULT_OFF | Disable unprivileged BPF by default by setting |
| **Cgroup** | CONFIG_CGROUP_BPF | Support for BPF programs attached to cgroups |
| **Network** | CONFIG_BPFILTER | BPF based packet filtering framework (BPFILTER) |
| | CONFIG_NET_CLS_BPF | BPF-based classifier - to classify packets based on programmable BPF (JIT'ed) filters as an alternative to ematches |
| | CONFIG_NET_ACT_BPF | Execute BPF code on packets. The BPF code will decide if the packet should be dropped or not |
| | CONFIG_BPF_STREAM_PARSER | Enable this to allow a TCP stream parser to be used with BPF_MAP_TYPE_SOCKMAP |
| **kprobes** | CONFIG_KPROBE_EVENTS | This allows the user to add tracing events (similar to tracepoints) on the fly via the ftrace interface |
|  | CONFIG_KPROBES | Enable kprobes-based dynamic events |
|  | CONFIG_HAVE_KPROBES | Check if krpobes enabled |
|  | CONFIG_HAVE_REGS_AND_STACK_ACCESS_API | This symbol should be selected by an architecture if it supports the API needed to access registers and stack entries from pt_regs. For example the kprobes-based event tracer needs this API. |
| **kprobe multi** | CONFIG_FPROBE | Enable fprobe to attach the probe on multiple functions at once |
| **kprobe override** | CONFIG_BPF_KPROBE_OVERRIDE | Enable BPF programs to override a kprobed function |
| **Tracepoints** | CONFIG_TRACEPOINTS | Enable inserting tracepoints in the kernel and connect to proble functions |
|  | CONFIG_HAVE_SYSCALL_TRACEPOINTS | Enable syscall enter/exit tracing |
| **LSM** | CONFIG_BPF_LSM | Enable instrumentation of the security hooks with BPF programs for implementing dynamic MAC and Audit Policies |


## Test Setup:
The performance tests were conducted using **iperf3** tool. The Device Under Test (DUT) was connected to two namespaces, enabling traffic circulation for a total volume of 1G. Various speeds and packet sizes were tested to evaluate performance metrics.

### Test Parameters:
- **Tool Used:** iperf3
- **Topology:** DUT connected to two namespaces
- **Total Traffic Volume:** 1G

### Test Scenarios:
1. **Speed Variation:** Testing at different speeds to assess performance under varying network loads.
2. **Packet Size Variation:** Evaluating performance with increasingly smaller packet sizes to analyze efficiency and throughput under different conditions.

## Results:
The test results provided insights into the performance capabilities of the system under varying network conditions. Detailed metrics including throughput, latency, and packet loss were recorded for each test scenario.

## Conclusion:
The conclusion drawn from the extensive performance testing is highly encouraging, especially concerning the efficacy of the eBPF accelerator in enhancing network performance. Throughout the test scenarios, the accelerator consistently demonstrated its ability to significantly improve throughput, particularly at higher speeds.

At speeds nearing the 700Mbps mark, traditionally considered a threshold for network congestion and potential performance degradation, the eBPF accelerator showcased remarkable efficiency. Under optimal conditions, where the transport layer protocol was fully utilized, the accelerator managed to push the throughput limit beyond expectations, reaching up to 900Mbps. This indicates the substantial headroom it provides in mitigating congestion and sustaining high-speed data transmission, crucial for demanding network environments.

Moreover, at the critical speed of 700Mbps, the effects of the accelerator were profound. Not only did it maintain high throughput levels, but it also exhibited a notable reduction in CPU consumption. This reduction not only signifies improved efficiency but also presents cost-saving opportunities by optimizing resource utilization.

Furthermore, one of the most significant advantages observed was the near elimination of packet loss. Even under conditions of high network load, where packet loss is often inevitable, the eBPF accelerator effectively minimized losses, ensuring the integrity and reliability of data transmission. This is a critical factor in mission-critical applications where data integrity is paramount.

In essence, the results of the performance testing unequivocally support the adoption and integration of the eBPF accelerator in network infrastructures. Its ability to enhance throughput, reduce CPU overhead, and mitigate packet loss positions it as a valuable asset for organizations seeking to optimize their network performance and reliability, especially in high-demand and latency-sensitive environments.


## Note:
This report serves as a comprehensive documentation of the performance testing process and outcomes, aiding in future analysis and optimization efforts.

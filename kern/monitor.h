#ifndef JOS_KERN_MONITOR_H
#define JOS_KERN_MONITOR_H
#ifndef JOS_KERNEL
# error "This is a JOS kernel header; user programs should not #include it"
#endif

struct Trapframe;

// Activate the kernel monitor,
// optionally providing a trap frame indicating the current state
// (NULL if none).
void monitor(struct Trapframe *tf);

// Functions implementing monitor commands.
int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_infokern(int argc, char **argv, struct Trapframe *tf);
int mon_infopg(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
int mon_showmappings(int argc, char **argv, struct Trapframe *tf);
int mon_flagset(int argc, char **argv, struct Trapframe *tf);
int mon_dumpmem(int argc, char **argv, struct Trapframe *tf);
uint32_t xtoi(char *x);

#endif  // !JOS_KERN_MONITOR_H

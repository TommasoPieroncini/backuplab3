// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

//INCLUDED for LAB2 CHALLENGE
#include <kern/pmap.h>

#define CMDBUF_SIZE 80 // enough for one VGA text line


struct Command {
  const char *name;
  const char *desc;
  // return -1 to force monitor to exit
  int (*func)(int argc, char **argv, struct Trapframe * tf);
};

static struct Command commands[] = {
  { "help",      "Display this list of commands",        mon_help       },
  { "info-kern", "Display information about the kernel", mon_infokern   },
  { "showmappings", "Display information about physical page mappings", mon_showmappings },
  { "flagset", "Change permission flags for a physical page", mon_flagset },
  { "dumpmem", "Show contents of memory in specified range", mon_dumpmem }
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
  int i;

  for (i = 0; i < NCOMMANDS; i++)
    cprintf("%s - %s\n", commands[i].name, commands[i].desc);
  return 0;
}

int
mon_infokern(int argc, char **argv, struct Trapframe *tf)
{
  extern char _start[], entry[], etext[], edata[], end[];

  cprintf("Special kernel symbols:\n");
  cprintf("  _start                  %08x (phys)\n", _start);
  cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
  cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
  cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
  cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
  cprintf("Kernel executable memory footprint: %dKB\n",
          ROUNDUP(end - entry, 1024) / 1024);
  return 0;
}


int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
  cprintf("Stack backtrace:\n");
  int *ebp = (int*) read_ebp();
  struct Eipdebuginfo info;
  while(ebp != 0)
  {
    int eip = *(ebp + 1);
    cprintf("  ebp %08x eip %08x args %08x %08x %08x %08x %08x\n", ebp, eip, *(ebp + 2), *(ebp + 3), *(ebp + 4), *(ebp + 5), *(ebp + 6));
    debuginfo_eip((uintptr_t) eip, &info);
    cprintf("    %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, eip - info.eip_fn_addr);
    ebp = (int*) *ebp;
  }
  return 0;
}

// CHALLENGE FOR LAB2 - Extend JOS kernel monitor commands

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
  if (argc < 3) {
    cprintf("Use: showmappings 0xstart 0xend\n");
    return 0;
  }
  uint32_t start = xtoi(argv[1]);
  uint32_t end = xtoi(argv[2]);
  for (; start <= end; start += PGSIZE) {
    pte_t *pte = pgdir_walk(kern_pgdir, (void *) start, 1);
    if (!pte) {
      panic("Can't create page, out of memory");
    }
    if (*pte & PTE_P) {
      cprintf("Page at %x. Flags: PTE_P: %x, PTE_U: %x, PTE_W: %x\n", start, *pte & PTE_P, *pte & PTE_U, *pte & PTE_W);
    } else {
      cprintf("Page at %x does not exist.\n", start);
    }
  }
  return 0;
}

int
mon_flagset(int argc, char **argv, struct Trapframe *tf)
{
  if (argc < 4) {
    cprintf("Use: flagset P/U/W 1/0 0xaddress\n");
    return 0;
  }
  char argf = *argv[1];
  int flag = 0;
  if (argf == 'P') {
    flag = PTE_P;
  } else if (argf == 'U') {
    flag = PTE_U;
  } else if (argf == 'W') {
    flag = PTE_W;
  }
  char set = *argv[2];
  uint32_t address = xtoi(argv[3]);
  pte_t *pte = pgdir_walk(kern_pgdir, (void *) address, 1);
  cprintf("Page at %x. Flags: PTE_P: %x, PTE_U: %x, PTE_W: %x\n", address, *pte & PTE_P, *pte & PTE_U, *pte & PTE_W);
  if (set == '1') {
    *pte = *pte | flag;
  } else {
    *pte = *pte & ~flag;
  }
  cprintf("Modified flag. %d %d\n", flag);
  cprintf("Page at %x. Flags: PTE_P: %x, PTE_U: %x, PTE_W: %x\n", address, *pte & PTE_P, *pte & PTE_U, *pte & PTE_W);
  return 0;
}

int
mon_dumpmem(int argc, char **argv, struct Trapframe *tf)
{
  if (argc < 3) {
    cprintf("Use: dumpmem 0xstart 0xrange\n");
    return 0;
  }
  void** start = (void **) xtoi(argv[1]);
  uint32_t range = xtoi(argv[2]);
  for (int x = 0; x < range; x++) {
    cprintf("Memory contents at %x: %x\n", start + x, start[x]);
  }
  return 0;
}

uint32_t
xtoi(char *x) {
  uint32_t res = 0;
  x += 2;
  while (*x) {
    if (*x >= 'a') {
      *x = *x - 'a' + '0' + 10;
    }
    res = res * 16 + *x - '0';
    x++;
  }
  //cprintf("Test %d", res);
  return res;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
  int argc;
  char *argv[MAXARGS];
  int i;

  // Parse the command buffer into whitespace-separated arguments
  argc = 0;
  argv[argc] = 0;
  while (1) {
    // gobble whitespace
    while (*buf && strchr(WHITESPACE, *buf))
      *buf++ = 0;
    if (*buf == 0)
      break;

    // save and scan past next arg
    if (argc == MAXARGS-1) {
      cprintf("Too many arguments (max %d)\n", MAXARGS);
      return 0;
    }
    argv[argc++] = buf;
    while (*buf && !strchr(WHITESPACE, *buf))
      buf++;
  }
  argv[argc] = 0;

  // Lookup and invoke the command
  if (argc == 0)
    return 0;
  for (i = 0; i < NCOMMANDS; i++)
    if (strcmp(argv[0], commands[i].name) == 0)
      return commands[i].func(argc, argv, tf);
  cprintf("Unknown command '%s'\n", argv[0]);
  return 0;
}

void
monitor(struct Trapframe *tf)
{
  char *buf;

  cprintf("Welcome to the JOS kernel monitor!\n");
  cprintf("Type 'help' for a list of commands.\n");

  if (tf != NULL)
    print_trapframe(tf);

  while (1) {
    buf = readline("K> ");
    if (buf != NULL)
      if (runcmd(buf, tf) < 0)
        break;
  }
}

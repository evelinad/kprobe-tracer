#include <linux/module.h>
#include "tracer.h"
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/ioctl.h>

#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/delay.h>
MODULE_DESCRIPTION("Tema 1");
MODULE_AUTHOR("Ion Ion");
MODULE_LICENSE("GPL");

#define LOG_LEVEL KERN_ALERT

LIST_HEAD(processes_list);
LIST_HEAD(allocated);

//functions for handling list

static int add(pid_t pid)
{
  struct proc_list *pl = kmalloc(sizeof(*pl), GFP_ATOMIC);
  if (!pl)
    return -ENOMEM;
  pl->data = kmalloc(sizeof(struct process), GFP_ATOMIC);
  pl->data->pid = pid;
  pl->data->kmalloc = 0;
  pl->data->kfree = 0;
  pl->data->kmalloc_mem = 0;
  pl->data->kfree_mem = 0;
  pl->data->sched = 0;
  pl->data->up = 0;
  pl->data->down = 0;
  pl->data->lock = 0;
  pl->data->unlock = 0;

  INIT_LIST_HEAD(&pl->list);
  list_add(&pl->list, &processes_list);
  return 0;
}


static int del(pid_t pid)
{
  struct list_head *i, *tmp;
  struct proc_list *pl;

  list_for_each_safe(i, tmp, &processes_list) {
    pl = list_entry(i, struct proc_list, list);
    if (pl->data->pid == pid) {
      list_del(i);
      kfree(pl->data);
      kfree(pl);
      break;
    }
  }

  return 0;
}

static struct proc_list*  find(pid_t pid)
{
  struct list_head *i, *tmp;
  struct proc_list *pl;

  list_for_each_safe(i, tmp, &processes_list) {
    pl = list_entry(i, struct proc_list, list);
    if (pl->data->pid == pid) {
      return pl;
    }
  }

  return NULL;
}

//functions for handling allocated list

static int add_to_allocated(unsigned size, void *address){
  struct allocated_list *al;
   al = kmalloc(sizeof(*al), GFP_ATOMIC);
  if (!al){
    return -ENOMEM;
  }
  al->size = size;
  al->address = address;
  list_add(&al->list, &allocated);
  return 0;
}

static int del_all_allocated(void){
  struct list_head *i, *tmp;
  struct allocated_list *al;

  list_for_each_safe(i, tmp, &allocated) {
    al = list_entry(i, struct allocated_list, list);
    list_del(i);
    kfree(al);
  }
  return 0;
}

static unsigned get_size_allocated(void* address)
{
  struct list_head *i, *tmp;
  struct allocated_list *pl;

  unsigned size = 0;
  list_for_each_safe(i, tmp, &allocated) {
    pl = list_entry(i, struct allocated_list, list);
    if (pl->address == address)
      return pl->size;
  }
  return size;

}

static int trace_proc_show(struct seq_file *m, void *v)
{
  struct list_head *i, *tmp;
  struct proc_list *pl;
  seq_printf(m, "%s %s %s %s %s %s %s %s %s %s\n",
      "PID", "kmalloc", "kfree","kmalloc_mem", "kfree_mem",
      "sched", "up", "down", "lock", "unlock");
  
  list_for_each_safe(i, tmp, &processes_list) {
    pl = list_entry(i, struct proc_list, list);
    seq_printf(m, "%d %u %u %u %u %u %u %u %u %u\n",
        pl->data->pid,
        pl->data->kmalloc,
        pl->data->kfree,
        pl->data->kmalloc_mem,
        pl->data->kfree_mem,
        pl->data->sched,
        pl->data->up,
        pl->data->down,
        pl->data->lock,
        pl->data->unlock);
  }
  return 0;


}

static long t_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  pid_t _pid;
  struct proc_list *elem;
  switch(cmd) {
    case TRACER_ADD_PROCESS:
      _pid = (pid_t)arg;
      add(_pid);
      return 0;
    case TRACER_REMOVE_PROCESS:
      _pid = (pid_t)arg;
      elem = find(_pid);
      if (elem == NULL) return 0;
      del(_pid);
    break;
    default:
      return -ENOTTY;
  }

  return 0;
}

static struct file_operations t_fops = {
	.unlocked_ioctl	= t_ioctl,
};

static struct miscdevice t_dev = {
	.minor	= TRACER_DEV_MINOR,
	.name	= TRACER_DEV_NAME,
	.fops	= &t_fops,
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{

  unsigned *u;
  u = (unsigned*)ri->data;
  *u = regs->ax;
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *retval = (void*)regs_return_value(regs);
  unsigned size = *((unsigned*)(ri->data));
  struct proc_list *list;

  list = find(current->pid);
  if (list == NULL) return 0;
  add_to_allocated(size, retval);
  list->data->kmalloc++;
  list->data->kmalloc_mem += size;
	return 0;
}

static struct kretprobe t_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(unsigned),
	.maxactive		= 32,
};

//jprobe for kfree
static void kfree_entry_handler(void* address)
{
  struct proc_list *list;
  unsigned size;
  list = find(current->pid);
  if (list != NULL){
    list->data->kfree++;
    size = get_size_allocated(address);
    list->data->kfree_mem += size;
  }
	jprobe_return();
}

static struct jprobe kfree_jprobe = {
	.entry			= kfree_entry_handler,
	.kp = {
		.symbol_name	= "kfree",
	},
};

//jprobe for sched
static void sched_entry_handler(void)
{
  struct proc_list *list;
  list = find(current->pid);
  if (list != NULL){
    list->data->sched++;
  }
	jprobe_return();
}

static struct jprobe sched_jprobe = {
  .entry = sched_entry_handler,
  .kp = {
		.symbol_name	= "schedule",
	},

};

//jprobe for up
static void up_entry_handler(void)
{
  struct proc_list *list;
  list = find(current->pid);
  if (list != NULL){
    list->data->up++;
  }
	jprobe_return();
}

static struct jprobe up_jprobe = {
  .entry = up_entry_handler,
  .kp = {
		.symbol_name	= "up",
	},

};


//jprobe for down_interruptible
static void down_entry_handler(void)
{
  struct proc_list *list;
  list = find(current->pid);
  if (list != NULL){
    list->data->down++;
  }
	jprobe_return();
}

static struct jprobe down_jprobe = {
  .entry = down_entry_handler,
  .kp = {
		.symbol_name	= "down_interruptible",
	},

};


//jprobe for mutex_lock
static void mutex_lock_entry_handler(void)
{
  struct proc_list *list;
  list = find(current->pid);
  if (list != NULL){
    list->data->lock++;
  }
	jprobe_return();
}

static struct jprobe mutex_lock_jprobe = {
  .entry = mutex_lock_entry_handler,
  .kp = {
		.symbol_name	= "mutex_lock",
	},

};

//jprobe for mutex_unlock
static void mutex_unlock_entry_handler(void)
{
  struct proc_list *list;
  list = find(current->pid);
  if (list != NULL){
    list->data->unlock++;
  }
	jprobe_return();
}

static struct jprobe mutex_unlock_jprobe = {
  .entry = mutex_unlock_entry_handler,
  .kp = {
		.symbol_name	= "mutex_unlock",
	},

};

static char km[NAME_MAX] = "__kmalloc";

static struct proc_dir_entry *proc_trace_read;

#define procfs_file_read	"tracer"

static int trace_read_open(struct inode *inode, struct	file *file)
{
	return single_open(file, trace_proc_show, NULL);
}

static const struct file_operations r_fops = {
	.open		= trace_read_open,
	.release	= single_release,
	.read		= seq_read,
};

static int __init init(void)

{
  int rc;
  proc_trace_read = proc_create(procfs_file_read, 0, NULL, &r_fops);
	if (!proc_trace_read)
    return -ENOMEM;
  rc = misc_register(&t_dev);
  if (rc < 0) {
		pr_err("misc_register: fail\n");
		return rc;
	}

  t_kretprobe.kp.symbol_name = km;
  rc = register_kretprobe(&t_kretprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_kretprobe failed, returned %d\n",
        rc);
    return -1;
  ;}
  printk(KERN_INFO "Planted return probe at %s: %p\n",
      t_kretprobe.kp.symbol_name, t_kretprobe.kp.addr);

  rc = register_jprobe(&kfree_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }
  rc = register_jprobe(&sched_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }
  rc = register_jprobe(&up_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }
  rc = register_jprobe(&down_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }
  rc = register_jprobe(&mutex_lock_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }
  rc = register_jprobe(&mutex_unlock_jprobe);
  if (rc < 0) {
    printk(KERN_INFO "register_jprobe failed, returned %d\n", rc);
    return -1;
  }

    return 0;
}

static void hello_exit(void)
{

  del_all_allocated();
  remove_proc_entry(procfs_file_read, NULL);
  unregister_kretprobe(&t_kretprobe);
	unregister_jprobe(&kfree_jprobe);
	unregister_jprobe(&sched_jprobe);
	unregister_jprobe(&up_jprobe);
	unregister_jprobe(&down_jprobe);
	unregister_jprobe(&mutex_lock_jprobe);
	unregister_jprobe(&mutex_unlock_jprobe);
	misc_deregister(&t_dev);
  printk(LOG_LEVEL "Goodbye!\n");
}

module_init(init);
module_exit(hello_exit);

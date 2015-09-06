/*
 * ptrace_utils.c
 *
 *  Created on: 2014-7
 *      Author: long
 * modify from author: boyliang 
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "ptrace_utils.h"
#include "elf_utils.h"
#include "log.h"
#include "tools.h"

struct process_hook {
	pid_t 		pid;
	char 		*dso;
} process_hook = {0, ""};

int main(int argc, char* argv[]) {

	struct pt_regs regs;
	//process_hook.dso = strdup(argv[1]);	//将参数1的字符串拷贝给process_hook.dso
	//process_hook.pid = atoi(argv[1]);	//把参数2（字符串）转换为长整型
	process_hook.dso = "/data/zygote/libgetJNIEnv.so";
	process_hook.pid = find_pid_of("zygote");

//	if (access(process_hook.dso, R_OK|X_OK) < 0) {		//判断so文件是否可读，可写
	if (access(process_hook.dso, R_OK) < 0) {
		LOGE("[-] so file must chmod rx\n");
		return 1;
	}
	const char* process_name = get_process_name(process_hook.pid);		//通过pid获取进程名字
	ptrace_attach(process_hook.pid, (int)strstr(process_name,"zygote"));		//衔接到zygote进程
	LOGI("[+] ptrace attach to [%d] %s\n", process_hook.pid, get_process_name(process_hook.pid));

	if (ptrace_getregs(process_hook.pid, &regs) < 0) {		//读取当前寄存器的内容，并保存到regs中
		LOGE("[-] Can't get regs %d\n", errno);
		goto DETACH;
	}

	LOGI("[+] pc: %x, r7: %x", (uint32_t)regs.ARM_pc, (uint32_t)regs.ARM_r7);

	void* remote_dlsym_addr = get_remote_address(process_hook.pid, (void *)dlsym);		//获取dlsym,dlopen的地址
	void* remote_dlopen_addr =  get_remote_address(process_hook.pid, (void *)dlopen);

	LOGI("[+] remote_dlopen address %p\n", remote_dlopen_addr);
	LOGI("[+] remote_dlsym  address %p\n", remote_dlsym_addr);

	void *handler = NULL; 
	handler = ptrace_dlopen(process_hook.pid, remote_dlopen_addr, process_hook.dso);		//调用dlopen函数，打开共享库，返回共享库地址	

	LOGI("[+] ptrace_dlopen handle: %p\n", handler);
	if(handler == NULL){
		LOGE("[-] Ptrace dlopen fail. %s\n", dlerror());
		goto DETACH;
	}

	//调用ptrace_dlsym函数，获取so_entry函数的地址
	uint32_t proc = 0;
	proc = (uint32_t)ptrace_dlsym(process_hook.pid,remote_dlsym_addr,handler,"so_entry");
	if(proc == 0){
		LOGE("[-] Ptrace dlsym fail.\n");	
		goto DETACH;
	}
	LOGI("[+] so_entry = %x\n",proc);

	int base = call_so_entry(process_hook.pid, proc);
	LOGI("[+] base is %d\n",base);
	if (base == -1){
		LOGE("[-] Call so_entry function fail.\n");
		goto DETACH;
	}
	
//regs.ARM_cpsr代表的是程序状态寄存器，出现在ptrace_call函数中
	if (regs.ARM_pc & 1 ) {
		// thumb
		regs.ARM_pc &= (~1u);
		regs.ARM_cpsr |= CPSR_T_MASK;
	} else {
		// arm
		regs.ARM_cpsr &= ~CPSR_T_MASK;
	}

//还原寄存器的内容
	if (ptrace_setregs(process_hook.pid, &regs) == -1) {
		LOGE("[-] Set regs fail. %s\n", strerror(errno));
		goto DETACH;
	}

	LOGI("[+] Inject success!\n");

DETACH:
	ptrace_detach(process_hook.pid);
	LOGI("[+] Inject done!\n");
	return 0;
}

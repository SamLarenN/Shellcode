;;; This function retrieves function addresses from desired modules.
;;; Remember that the module have to be loaded by the process to access it from PEB.
;;; DllNameW is a wchar_t*
;;; C calling convention: GetFunctionAddress(char* FuncName, DWORD FuncNameLen, wchar_t* DllNameW, DWORD DllNameLen)
GetFunctionAddress:
FuncName	equ dword[ebp + 8]
FuncNameLen	equ dword[ebp + 12]
DllNameW	equ dword[ebp + 16]
DllNameLen	equ dword[ebp + 20]
ImageBase	equ dword[ebp - 4]
pExportDir	equ dword[ebp - 8]

	push	ebp
	mov	ebp, esp
	sub	esp, 8

	mov	eax, [fs:0x30]			; Get PEB from TIB
	mov	eax, [eax + 0x0C]		; Get Pointer to PEB_LDR_DATA
	mov	eax, [eax + 0x14]		; Get LIST_ENTRY

;;; Loop DLL whilst comparing to desired DLL
@DllLoop:
	lea	ebx, [eax + 0x24]
	mov	esi, [ebx + 0x04]		; Get UNICODE_STRING->buffer (not null terminated).
	mov	edi, DllNameW
	mov	ecx, DllNameLen
	repe	cmpsb				; Compare with argument.
	je	@Found

	mov	eax, [eax]
	jmp	@DllLoop

@Found:
	mov	eax, [eax + 0x10]
	mov	ImageBase, eax

	cmp	word[eax], 'MZ'
	jne	@Ret

	add	eax, [eax + 0x3C]		; ImageBase + e_lfanew = PIMAGE_NT_HEADERS

	cmp	word[eax], 'PE'
	jne	@Ret
	mov	eax, [eax + 0x18 + 0x60]	; PIMAGE_NT_HEADERS +18h +60h = DataDirectory[0]
	add	eax, ImageBase			; Add ImageBase to RVA in order to get export table
	mov	pExportDir, eax

	mov	edx, pExportDir
	mov	edx, [edx + 0x14]		; Get NumberOfFunctions  (EDX is counter)
	mov	ebx, pExportDir
	mov	ebx, [ebx + 0x20]		; Get AddressOfNames
	add	ebx, ImageBase			; Which is a RVA from ImageBase

@FuncLoop:
	dec	edx
	mov	esi, [ebx + edx * 4]
	add	esi, ImageBase			; Compare func name
	mov	edi, FuncName			; with func name from argument.
	mov	ecx, FuncNameLen
	repe	cmpsb
	je	@FoundFunc

	test	edx, edx
	jnz	@FuncLoop
	jmp	@Ret

@FoundFunc:
	mov	eax, pExportDir
	mov	eax, [eax + 0x24]		; Get AddressOfOrdinals.
	add	eax, ImageBase			; It is RVA from ImageBase.
	movzx	eax, word[eax + edx * 2]	; EAX now holds Ordinal of desired function.
						; Notice that we use 2 as multiplier for the Ordinals are WORDs.
	mov	ebx, pExportDir
	mov	ebx, [ebx + 0x1C]		; Get AddressOfFunctions.
	add	ebx, ImageBase			; Which is a RVA from ImageBase.
	mov	eax, [ebx + eax * 4]		; AddressOfFunctions[Ordinal] = DesiredFuncAddress
	add	eax, ImageBase			; Which also is a RVA from ImageBase.

@Ret:
	add	esp, 8
	pop	ebp
	ret	16
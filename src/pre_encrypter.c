#include <asm-generic/fcntl.h>
#include <cstdio>

// Calculos
// readelf -S pestilence
//
// [Nr] Nombre            Tipo             Dirección         Despl
//      Tamaño            TamEnt           Opts   Enl   Info  Alin
// [...]
// [ 1] .text             PROGBITS         0000000000401000  00001000
//      000000000000050a  0000000000000000  AX       0     0     16
// [...]
//
// Para la section_offset = Despl = (0x00001000)
// Para la section_va = Dirección = (0x0000000000401000)
// Para la symbol_va
// nm -S pestilence | grep fn_name
// 
// [...]
// 0000000000401002 t directory_name_isdigit 
// [...]
//
// file_offset = section_offset + (symbol_va - section_va)
// file_offset = 0x00001000 + (0x0401002 - 0x0401000)
//
// Para el size
// nm -S pestilence| grep directory_name_isdigit
// 0000000000401002 t directory_name_isdigit
// 000000000040100a t directory_name_isdigit.bucle
// 0000000000401025 t directory_name_isdigit.directory_name_isdigit_end
// 0000000000401021 t directory_name_isdigit.out
//
// size = directory_name_isdigit.directory_name_isdigit_end - directory_name_isdigit
//

void xor_cipher(uint8_t *buf, size_t size, uint8_t *key) {
    for (size_t i = 0; i < size; i++) {
        buf[i] ^= key[i & 7];
    }
}

int main(void) {
    uint8_t key[8] = "p3st1l3!"
    int fd = open("pestilence", O_RDWR);
    
    xor_cipher(buf, size, key);

    close(fd);
    return 0;
}
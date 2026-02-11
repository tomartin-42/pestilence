#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

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
// size = directory_name_isdigit.directory_name_isdigit_end -
// directory_name_isdigit
//

void xor_cipher(uint8_t *buf, size_t size, uint8_t *key, size_t offset,
                int fd) {

  lseek(fd, offset, SEEK_SET);
  read(fd, buf, size);

  for (size_t i = 0; i < size; i++) {
    buf[i] ^= key[i & 7];
  }

  lseek(fd, offset, SEEK_SET);
  write(fd, buf, size);
}

int main(void) {
  uint8_t key[8] = "p3st1l3!";
  int fd = open("pestilence", O_RDWR);
  uint8_t buf[1024];
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  struct stat st;
  void *map;

  fstat(fd, &st);
  map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ehdr = (Elf64_Ehdr *)map;
  phdr = (Elf64_Phdr *)((char *)map + ehdr->e_phoff);
  for (int i = 0; i < ehdr->e_phnum; i++)
  {
      if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
      {
          phdr[i].p_flags = PF_R | PF_W | PF_X;
      }
  }
  munmap(map, st.st_size);
  // directory_name_isdigit
  xor_cipher(buf, 0x20, key, 0x1002, fd);

  close(fd);
  return 0;
}

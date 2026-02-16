#!/bin/bash

# Podría trabajar solo con la primera columna pero para lo que procesa importa poco

base_offset=$(awk -F' ' '{print $1}' <(nm -na pestilence  | grep -w '_start'))

awk -F' ' -v base_offset=${base_offset} '

BEGIN {
	func_start=-1;
	base_offset=strtonum("0x"base_offset);
}

{
	if (func_start == -1) {
		func_start = strtonum("0x"$1);
		next ;
	}
	
	printf("%d%s%d\n", func_start - base_offset, ":", strtonum("0x"$1) - func_start);
	func_start = -1;
	
}' <(nm -na pestilence  | grep '__F_'  | grep -v '\.')


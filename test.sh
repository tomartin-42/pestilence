#!/bin/bash

program_name="pestilence"
trace="Pestilence version 1.0 (c)oded by tomartin & carce-bo"
declare -a test_dirs=( /tmp/test{,2,3,4,5} )

[[ ! -e ./${program_name} ]] && { echo "Que tal si compilas amigo" && exit 1; }

for dir in "${test_dirs[@]}"; do
	if [[ ! -d $dir ]]; then
		mkdir -p $dir
	else
		rm -f $dir/*
	fi
done

# Lanzamos 1 vez ${program_name} con /tmp/test poblado
cp /usr/bin/cat /usr/bin/ls /tmp/test/

./${program_name} || { echo "${program_name} no ha retornado 0" && exit 1; }

! strings /tmp/test/ls | grep -q "${trace}"  && { echo "El paciente 0 no infecta" && exit 1; }
! strings /tmp/test/cat | grep -q "${trace}"  && { echo "El paciente 0 no itera correctamente todos los ficheros" && exit 1; }

# Movemos los binarios infectados a test3 para que no se reinfecten. Cuando tengamos
# el flag que indica que un binario ya está infectado y lo gestionemos podremos quitar eso
mv /tmp/test/* /tmp/test3/

cp /usr/bin/cat /usr/bin/ls /tmp/test2/

# Ejecutamos el ls infectado (dejo la traza para que se vea que salta el ls)
/tmp/test3/ls || { echo "El binario infectado 1 no ha retornado 0" && exit 1; }

! strings /tmp/test2/ls | grep -q "${trace}"  && { echo "El binario infectado 1 no infecta" && exit 1; }
! strings /tmp/test2/cat | grep -q "${trace}"  && { echo "El binario infectado 1 no itera correctamente todos los ficheros" && exit 1; }

#repetimos la jugada para el cat, que nos dio problemas esto
cp /usr/bin/cat /usr/bin/ls /tmp/test2/

/tmp/test3/cat < /dev/null || { echo "El binario infectado 2 no ha retornado 0" && exit 1; }

! strings /tmp/test2/ls | grep -q "${trace}"  && { echo "El binario infectado 1 no infecta" && exit 1; }
! strings /tmp/test2/cat | grep -q "${trace}"  && { echo "El binario infectado 1 no itera correctamente todos los ficheros" && exit 1; }

# Tercera iteracion del virus, comprobando que se infectan en /tmp/test y /tmp/test2
mv /tmp/test2/* /tmp/test4/

cp /usr/bin/cat /usr/bin/ls /tmp/test2/
cp /usr/bin/cat /usr/bin/ls /tmp/test/

/tmp/test4/ls || { echo "El binario infectado de segunda generacion no ha retornado 0" && exit 1; }

! strings /tmp/test/ls | grep -q "${trace}"  && { echo "El binario infectado de segunda generacion no infecta" && exit 1; }
! strings /tmp/test/cat | grep -q "${trace}"  && { echo "El binario infectado de segunda generacion no itera correctamente todos los ficheros" && exit 1; }
! strings /tmp/test2/ls | grep -q "${trace}"  && { echo "El binario infectado de segunda generacion no infecta" && exit 1; }
! strings /tmp/test2/cat | grep -q "${trace}"  && { echo "El binario infectado de segunda generacion no itera correctamente todos los ficheros" && exit 1; }

( vim /tmp/_____ &>/dev/null; ) &

cp /usr/bin/cat /usr/bin/ls /tmp/test/

mv /tmp/test2/* /tmp/test5/

/tmp/test5/ls || { echo "El binario infectado de tercera generacion no ha retornado 0" && exit 1; }

strings /tmp/test/ls | grep -q "${trace}" && { echo "El binario infecta a pesar de tener corriendo el programa prohibido" && exit 1; }
strings /tmp/test/cat | grep -q "${trace}" && { echo "El binario infecta a pesar de tener corriendo el programa prohibido" && exit 1; }

pkill -SIGKILL -f "vim /tmp/_____"

exit 0

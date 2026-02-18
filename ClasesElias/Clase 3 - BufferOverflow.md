# Clase 3: Buffer Overflow

#BufferOverflow #ExploitDevelopment #BinaryExploitation #MemoryCorruption #StackOverflow #x64Assembly #GDB #Pwntools #C #ReverseEngineering

---

## Código de prueba inicial

Hagamos este código sencillo de prueba:

```c
int main() {
    char buf[20];
    char secret[20];

    gets(buf);

    puts(buf);
}
```

Imaginemos que `secret` es un arreglo el cual no debemos poder ver. Bueno, ¿cómo sabe el programa el tamaño y cuándo deja de imprimir?

Cuando se topa al **null byte** → `\x00`

Cuando detecta eso lo deja de imprimir. Por ejemplo:

```bash
python2 -c "print 'Hola\x00Mundo'" | ./vuln
Hola
```

---

## Modificación del código

Cambiemos el código así:

```c
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    char secret[16];
    char buf[16];

    buf[0] = 'A';
    secret[0] = 'B';

    int archivo = open("input", O_RDONLY); 

    read(archivo, buf, 20);

    puts(buf);
}
```

Código que lee desde un archivo que le metimos 20 'A' llamado "input".

---

## Programa básico con Pwntools

Ahora con **pwntools** vamos a hacer un programa básico:

```python
from pwn import *

p = process("./vuln")

payload = "A"*20

p.sendline(payload)

p.interactive()
```

---

## Análisis con GDB

Ahora vemos `vuln` con GDB y hacemos un `disassemble main`:

```bash
gdb ./vuln
disassemble main
```

```nasm
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000000000401146 <+0>:     push   rbp
   0x0000000000401147 <+1>:     mov    rbp,rsp
   0x000000000040114a <+4>:     sub    rsp,0x40
   0x000000000040114e <+8>:     mov    BYTE PTR [rbp-0x40],0x41 <-------- Arreglo Secret
   0x0000000000401152 <+12>:    mov    BYTE PTR [rbp-0x20],0x42 <-------- Arreglo Buf
   0x0000000000401156 <+16>:    mov    esi,0x0
   0x000000000040115b <+21>:    lea    rax,[rip+0xea2]        # 0x402004
   0x0000000000401162 <+28>:    mov    rdi,rax
   0x0000000000401165 <+31>:    mov    eax,0x0
   0x000000000040116a <+36>:    call   0x401050 <open@plt>
   0x000000000040116f <+41>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401172 <+44>:    lea    rcx,[rbp-0x40]
   0x0000000000401176 <+48>:    mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401179 <+51>:    mov    edx,0x14
   0x000000000040117e <+56>:    mov    rsi,rcx
   0x0000000000401181 <+59>:    mov    edi,eax
   0x0000000000401183 <+61>:    call   0x401040 <read@plt>
   0x0000000000401188 <+66>:    lea    rax,[rbp-0x40]
   0x000000000040118c <+70>:    mov    rdi,rax
   0x000000000040118f <+73>:    call   0x401030 <puts@plt>
   0x0000000000401194 <+78>:    mov    eax,0x0
   0x0000000000401199 <+83>:    leave
   0x000000000040119a <+84>:    ret
End of assembler dump.
gef➤  
```

---

## Depuración del Stack

Debugueamos un poco y avanzamos con `n` para ver la asignación de los `char` que pusimos en cada uno 'A' 'B' en el stack:

```
0x00007fffffffdc90│+0x0000: 0x0000000000000041 ("A"?)    ← $rsp
0x00007fffffffdc98│+0x0008: 0x0000000000000000
0x00007fffffffdcb0│+0x0020: 0x0000000000000042 ("B"?)
0x00007fffffffdca8│+0x0018: 0x0000000000000000
0x00007fffffffdcb8│+0x0028: 0x00007ffff7fe4780  →   push rbp
0x00007fffffffdcc0│+0x0030: 0x0000000000000000
0x00007fffffffdcc8│+0x0038: 0x00007fffffffdd60  →  0x0000000000000001
```

Avanzamos por línea de código con `n` y:

```
0x00007fffffffdca0│+0x0000: "AAAAAAAAAAAAAAAAB"  ← $rsp, $rsi
0x00007fffffffdca8│+0x0008: "AAAAAAAAB"
0x00007fffffffdcb0│+0x0010: 0x0000000000000042 ("B"?)
```

Vemos que la 'B' como que se indexa, es decir nos filtra el contenido de `secret`.

---

## Ejemplo de fuga de información (Leak)

Imaginemos un código así:

```c
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    char secret[16];
    char buf[16];

    buf[0] = 'A';
    secret[0] = 'p';
    secret[1] = 'a';
    secret[2] = 's';
    secret[3] = 's';
    secret[4] = 'w';
    secret[5] = 'o';
    secret[6] = 'r';
    secret[7] = 'd';

    int archivo = open("./input", O_RDONLY);

    read(archivo, buf, 16);

    puts(buf);
}
```

Compilamos y ejecutamos:

```bash
./vuln                          
AAAAAAAAAAAAAAAApassword    
```

Pasa porque `read` no pone el null byte, lo encuentra hasta que acaba de leer `password`. A esto se le llama **leak**. Estos leaks nos pueden ayudar a calcular un offset para brincar a direcciones de memoria de librerías como `system` que permiten ejecutar comandos.

---

## Código útil para sobreescribir el Base Pointer

Podemos hacer otro código útil:

```c
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void vuln() {
    char buf[16];
    int archivo = open("./input", O_RDONLY);

    read(archivo, buf, 666);
}

int main() {
    char buf[16];
    char secret[16];

    buf[0] = 'g';
    buf[1] = 'o';
    buf[2] = 'k';
    buf[3] = 'u';

    secret[0] = 'p';
    secret[1] = 'a';
    secret[2] = 's';
    secret[3] = 's';
    secret[4] = 'w';
    secret[5] = 'o';
    secret[6] = 'r';
    secret[7] = 'd';

    vuln();

    puts(buf);
}
```

---

## Disassemble de main y vuln

Lo compilamos y hacemos un `disassemble main` y `vuln`:

```nasm
gef➤  disassemble main
Dump of assembler code for function main:
=> 0x0000000000401183 <+0>:     push   rbp
   0x0000000000401184 <+1>:     mov    rbp,rsp
   0x0000000000401187 <+4>:     sub    rsp,0x20
   0x000000000040118b <+8>:     mov    BYTE PTR [rbp-0x10],0x67
   0x000000000040118f <+12>:    mov    BYTE PTR [rbp-0xf],0x6f
   0x0000000000401193 <+16>:    mov    BYTE PTR [rbp-0xe],0x6b
   0x0000000000401197 <+20>:    mov    BYTE PTR [rbp-0xd],0x75
   0x000000000040119b <+24>:    mov    BYTE PTR [rbp-0x20],0x70
   0x000000000040119f <+28>:    mov    BYTE PTR [rbp-0x1f],0x61
   0x00000000004011a3 <+32>:    mov    BYTE PTR [rbp-0x1e],0x73
   0x00000000004011a7 <+36>:    mov    BYTE PTR [rbp-0x1d],0x73
   0x00000000004011ab <+40>:    mov    BYTE PTR [rbp-0x1c],0x77
   0x00000000004011af <+44>:    mov    BYTE PTR [rbp-0x1b],0x6f
   0x00000000004011b3 <+48>:    mov    BYTE PTR [rbp-0x1a],0x72
   0x00000000004011b7 <+52>:    mov    BYTE PTR [rbp-0x19],0x64
   0x00000000004011bb <+56>:    mov    eax,0x0
   0x00000000004011c0 <+61>:    call   0x401146 <vuln> <-- leer debajo, volver aquí (aquí recupera su valor guardado en stack de vuln)
   0x00000000004011c5 <+66>:    lea    rax,[rbp-0x10]
   0x00000000004011c9 <+70>:    mov    rdi,rax
   0x00000000004011cc <+73>:    call   0x401030 <puts@plt>
   0x00000000004011d1 <+78>:    mov    eax,0x0
   0x00000000004011d6 <+83>:    leave
   0x00000000004011d7 <+84>:    ret
End of assembler dump.
```

Primero `main`: vemos que `main` tiene su base pointer `rbp` que usa para sus variables y después llama a `vuln`. Si vemos abajo, `vuln` guarda el base pointer `rbp` actual, que es el que era de `main`, luego lo cambia por el stack pointer `rsp` (donde se encuentra actualmente el stack):

```nasm
gef➤  disassemble vuln
Dump of assembler code for function vuln:
   0x0000000000401146 <+0>:     push   rbp <-- agarra el base pointer rbp de main
   0x0000000000401147 <+1>:     mov    rbp,rsp <-- lo cambia por el stack pointer rsp, valor más nuevo del stack
   0x000000000040114a <+4>:     sub    rsp,0x20
   0x000000000040114e <+8>:     mov    esi,0x0
   0x0000000000401153 <+13>:    lea    rax,[rip+0xeaa]        # 0x402004
   0x000000000040115a <+20>:    mov    rdi,rax
   0x000000000040115d <+23>:    mov    eax,0x0
   0x0000000000401162 <+28>:    call   0x401050 <open@plt>
   0x0000000000401167 <+33>:    mov    DWORD PTR [rbp-0x4],eax
   0x000000000040116a <+36>:    lea    rcx,[rbp-0x20]
   0x000000000040116e <+40>:    mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401171 <+43>:    mov    edx,0x29a
   0x0000000000401176 <+48>:    mov    rsi,rcx
   0x0000000000401179 <+51>:    mov    edi,eax
   0x000000000040117b <+53>:    call   0x401040 <read@plt>
   0x0000000000401180 <+58>:    nop
   0x0000000000401181 <+59>:    leave
   0x0000000000401182 <+60>:    ret
End of assembler dump.
gef➤  
```

---

## Explicación del Base Pointer

Cuando se deje de ejecutar `vuln`, `vuln` va a recuperar el base pointer de `main` que tenía guardado en el stack.

Como `vuln` tiene un overflow, podemos sobreescribir el base pointer `rbp` de `main`.

---

## Depuración hasta la invocación de vuln

Entonces depuramos y llegamos hasta que se invoque la función de `vuln` y en los registros vemos el base pointer `rbp`:

```
$rax   : 0x0               
$rbx   : 0x00007fffffffdde8  →  0x00007fffffffe163  →  "/home/kali/Documents/pwn/eliasCodesPruebas/2/buf"
$rcx   : 0x0000000000403130  →  0x0000000000401110  →  <__do_global_dtors_aux+0000> endbr64 
$rdx   : 0x00007fffffffddf8  →  0x00007fffffffe194  →  "COLORFGBG=15;0"
$rsp   : 0x00007fffffffdcb0  →  0x64726f7773736170 ("password"?)
$rbp   : 0x00007fffffffdcd0  →  0x0000000000000001 <-- Base pointer rbp
$rsi   : 0x00007fffffffdde8  →  0x00007fffffffe163  →  "/home/kali/Documents/pwn/eliasCodesPruebas/2/buf"
$rdi   : 0x1               
$rip   : 0x00000000004011c0  →  <main+003d> call 0x401146 <vuln>
```

Si guardamos su valor y seguimos la depuración, veremos cómo se mete en el stack, luego sale y se mete en los registros de nuevo.

---

## Explotación

Entonces pasemos con la explotación:

```bash
python2 -c "print b'A'*0x20" > input
```

Eso, si recordamos que el buffer leerá donde está el `rbp` (base pointer) - `0x20` en hexadecimal (32 en decimal) por esa línea del ensamblador de `vuln`:

```nasm
0x000000000040116a <+36>:    lea    rcx,[rbp-0x20]
```

Entonces quiere decir que los siguientes 8 caracteres serán el base pointer `rbp`.

Entonces ejecutamos:

```bash
python2 -c "print b'A'*0x20" > input
```

Entonces podemos debuguear poniendo breakpoint en `vuln` por si no hallaste cuándo se viene el base pointer `rbp` de `main`.

Luego de eso asigna espacio para nuestras variables.

---

**... Continuará**
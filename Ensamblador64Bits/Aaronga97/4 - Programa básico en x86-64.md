# Secciones en Código Ensamblador

#assembly #nasm #x86-64 #elf64 #syscalls #stack-frames

## Secciones Principales del Código Ensamblador

En el código ensamblador existen varias secciones que organizan diferentes tipos de datos e instrucciones.

### Tabla de Secciones

| Name     | Descripción                                      |
| -------- | ------------------------------------------------ |
| `.text`  | Código ejecutable (instrucciones del programa)   |
| `.rodata`| Datos de solo lectura (constantes, cadenas fijas)|
| `.data`  | Variables inicializadas                          |
| `.bss`   | Variables no inicializadas                       |

---

## Sección .text

#section-text #executable-code #entry-point

Una de las principales es la sección `.text`, que contiene el código ejecutable. Es donde el instruction pointer `rip` se va a ir línea a línea ejecutando las instrucciones del programa.

### Estructura básica:
```asm
section .text    ; Segmento de código
    global _start    ; Punto de entrada para el Linker (le decimos que empieza en _start)

_start:
    ; Salir del programa
    mov    rax, 60    ; syscall: exit
    mov    rdi, 0     ; código de salida 0
    syscall
```

Este programa es muy sencillo, lo único que hace es salirse del programa con código de salida 0, es como un `return 0` en C.

---

## Sección .rodata

#section-rodata #read-only #constants

Aquí se guardan las constantes, cosas que no van a cambiar a lo largo de la ejecución del programa.

### Definición de constantes:
```asm
section .rodata    ; Segmento de datos de solo lectura

const1 db "Soy una constante", 10, 0    ; 10 = \n, 0 = \0
const1_len equ $ - const1               ; Calcula longitud de const1
```

Como dice allí, el `,10` significa salto de línea `\n` y el `,0` un null byte terminator, supongo como dice allí `\0` (no sé si sea igual a `\x00`).

La segunda línea es para calcular el tamaño: la posición de la memoria donde estamos actualmente menos la posición de la memoria de la constante anterior.

---

## Sección .data

#section-data #initialized-variables #global-variables

Luego están las globales que sí se pueden editar (vistas con Elías ya), valores predefinidos estáticos y son globales.

### Declaración de variables inicializadas:
```asm
section .data    ; Segmento de datos inicializados

msg1    db "Hola desde .data", 10, 0    ; Cadena con salto de línea y terminador nulo
msg1_len equ $ - msg1                   ; Calcula longitud de msg1
```

Igual que lo anterior, tiene salto de línea y null terminator, y abajo el cálculo de su tamaño.

---

## Sección .bss

#section-bss #uninitialized-variables #memory-allocation #resb #resq

Tenemos el `.bss` que es para las variables no inicializadas read-write, podemos modificarlas. La diferencia con la anterior es que esta no agarra espacio del binario, es decir, no está guardado su valor en el binario, sino que se guardarán en memoria.

### Definición de variables no inicializadas:
```asm
section .bss    ; Segmento de datos no inicializados

    buffer  resb 64    ; Reserva 64 bytes
    number  resq 1     ; Reserva 8 bytes (para un quad-word)
```

La variable `buffer` reserva 64 bytes y la variable `number` reserva 8 bytes.

- `resb` (b) de byte
- `resq` (q) de quad-word: una word son 16 bits, una quad son 4 de 16, es decir 64 bits, 64/8 = 8 bytes, por eso da 8 bytes.

---

## Ejemplo Completo con las 4 Secciones
```asm
section .data    ; Initialized data segment
    msg1   db "Hola desde .data", 10, 0
    msg1_len equ $ - msg1

section .rodata    ; Read-only data segment
    const1  db "Soy una constante", 10, 0  ; 10= \n, 0= \0
    const1_len equ $ - const1

section .bss    ; Uninitialized data segment
    buffer  resb 64    ; Reserve 64 bytes
    number  resq 1    ; Reserve 8 bytes

section .text    ; Code segment
    global _start    ; Entry point for Linker

_start:
    ; Exit program
    mov    rax, 60    ; syscall: exit
    mov    rdi, 0    ; exit code 0
    syscall
```

Este código repito solo es para cerrar el programa con código de éxito.

---

## Proceso de Compilación y Ejecución

#nasm-compilation #ld-linker #elf64-format

Ahora para ejecutar el código ensamblador se requieren de 3 pasos ligeros:

### 1. Compilar
```bash
nasm -f elf64 ./codigo.asm
```

Con `nasm` podemos hacerlo, `-f` para especificar formato `elf64`. Ya lo habíamos visto, es para especificar que será un ejecutable de Linux. **ELF**: Executable and Linkable Format de 64 bits. Luego el código fuente del programa assembly.

### 2. Linkear
```bash
ld -o ./codigo ./codigo.o
```

Aquí todos los símbolos se juntan, toda la metadata está unida en un mismo lugar, librerías externas, todo.

### 3. Ejecución
```bash
./codigo
```

---

## Ejemplo de Programa con Funciones

#function-prologue #function-epilogue #stack-alignment #calling-convention

Entonces armamos este código que fue el de ejemplo en C:
```asm
section .text
    global _start

square:
    push    rbp         ; <- Estas 2 son el prólogo de todas las funciones
    mov     rbp, rsp    ; <-
    sub     rsp, 16     ; we sub 16 for stack to be aligned
    mov     [rbp-4], edi    ; DWORD PTR (32 bits) <- le quitamos 4 espacios porque cada espacio es de 8
    mov     eax, [rbp-4]    ; DWORD PTR (32 bits)
    imul    eax, eax
    mov     rsp, rbp
    pop     rbp         ; <- Este es el final de todas las funciones (epílogo)
    ret                 ; <- restaura el rbp de la función anterior para restaurar la ejecución y hace return

main:
    push    rbp         ; <- empuja el rbp al stack
    mov     rbp, rsp    ; <- le mete el rsp al rbp, es decir, los nivela a la misma posición
    mov     edi, 10     ; <- por defecto al llamar a una función en x64 se usa el registro edi
    call    square
    mov     eax, 0      ; <- aquí eax tendría el resultado de square y lo estamos reseteando
    mov     rsp, rbp
    pop     rbp
    ret

_start:
    call main
    ; exit the program
    mov rax, 60         ; syscall number for sys_exit
    xor rdi, rdi        ; exit code 0
    syscall             ; invoque syscall
```

### Explicación del Stack Alignment

Cuando empujamos `push`, movemos 8 bytes. Tenemos que tener un número par de empujadas para estar bien alineados. Como metemos un valor (en este caso no es de 16 bits), estamos haciendo espacio para nuestra variable.
```asm
mov     [rbp-4], edi    ; DWORD PTR (32 bits)
```
Le quitamos 4 espacios porque cada espacio es de 8, y como es valor de 32 bits pues 4×8=32, todo bien. Allí metimos nuestro 10.
```asm
mov     eax, [rbp-4]    ; DWORD PTR (32 bits)
```
Aquí estamos metiendo el mismo valor al registro `eax` (10).

### Multiplicación con imul

Luego sigue la función `imul` que es para multiplicar. Allí estamos haciendo la potencia, como quien dice, de nuestro programa:
```asm
imul    eax, eax
```

Entonces, como el valor de retorno ya está en el registro indicado `eax`, ya podemos restaurar el stack al inicio:
```asm
mov     rsp, rbp
pop     rbp    ; <- regresamos el base pointer anterior
ret            ; <- restauramos la ejecución rip instruction pointer de como estábamos antes de llamar a square
```

---

## Mejora del Código

#code-refactoring #exit-syscall

Como el `eax` tiene el valor de square con 10 y lo estamos reseteando, lo mejor sería meterlo al registro `edi`:
```asm
mov edi, eax
```

Así que hacemos mejor una función llamada `exit_program`. A `_start` solo le dejamos el call a `main` y movemos la línea de `main` como dije arriba, dejando el código así:
```asm
section .text
    global _start

square:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 16         ; we sub 16 for stack to be aligned
    mov     [rbp-4], edi    ; DWORD PTR (32 bits)
    mov     eax, [rbp-4]    ; DWORD PTR (32 bits)
    imul    eax, eax
    mov     rsp, rbp
    pop     rbp
    ret

main:
    push    rbp
    mov     rbp, rsp
    mov     edi, 10
    call    square
    mov     edi, eax
    call    exit_program

_start:
    call main

exit_program:
    ; exit the program
    mov rax, 60         ; syscall number for sys_exit
    syscall             ; invoque syscall
```

También eliminamos el `xor` que estaba en `exit_program` o antes `_start`.

---

## Compilación y Ejecución del Programa Final

Entonces ya solo hacemos los 3 pasos para correrlo:

### Compilar
```bash
nasm -f elf64 ./code.asm
```

### Linkear
```bash
ld -o ./nombrebinario ./code.o
```

### Ejecutar
```bash
./nombrebinario
```

Y pues no nos retorna nada, pero el valor está en:
```bash
echo $?
```

Que imprime el código del último comando ejecutado, nuestro binario.

---

## Debugging con strace

#strace #debugging #syscall-tracing

Otra cosa que podemos hacer es:
```bash
strace ./nombrebinario
```

**Salida:**
```
execve("./nombrebinario", ["./nombrebinario"], 0x7ffd40539010 /* 56 vars */) = 0
exit(100)                               = ?
+++ exited with 100 +++
```
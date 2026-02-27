# 🔍 Assembly Assortment — Ingeniería Inversa

> [!NOTE] ¿De qué trata esto? Serie de retos de ingeniería inversa donde analizamos binarios ELF de 64 bits con `objdump` y `gdb`, identificamos la lógica de validación en ensamblador y calculamos el argumento correcto para obtener la flag.

---

## 🧩 Reto 1 — Suma con `add`

### Análisis del binario

```bash
objdump -d -M intel /challenge/reverse-me
```

```asm
0000000000401000 <_start>:
  401000:  48 8b 44 24 10    mov    rax, QWORD PTR [rsp+0x10]  ; ← Nuestra entrada
  401005:  80 00 1d          add    BYTE PTR [rax], 0x1d       ; ← Le suma 0x1d a nuestra entrada
  401008:  80 38 66          cmp    BYTE PTR [rax], 0x66       ; ← Compara el resultado con 0x66
  40100b:  75 62             jne    40106f <fail>              ; ← Si no es igual, salta a fail
  40100d:  c6 04 24 2f       mov    BYTE PTR [rsp], 0x2f       ; ← Comienza a cargar "/flag\0"
  401011:  c6 44 24 01 66    mov    BYTE PTR [rsp+0x1], 0x66
  401016:  c6 44 24 02 6c    mov    BYTE PTR [rsp+0x2], 0x6c
  40101b:  c6 44 24 03 61    mov    BYTE PTR [rsp+0x3], 0x61
  401020:  c6 44 24 04 67    mov    BYTE PTR [rsp+0x4], 0x67
  401025:  c6 44 24 05 00    mov    BYTE PTR [rsp+0x5], 0x0
  ...
```

### Lógica de validación

El programa toma el primer byte de nuestro argumento, le suma `0x1d` y compara el resultado con `0x66`. Si son iguales → imprime la flag. Si no → salta a `<fail>`.

### Solución

Para pasar la comparación necesitamos que:

```
entrada + 0x1d == 0x66
entrada == 0x66 - 0x1d
entrada == 0x49 (decimal: 73)
```

```python
>>> print(0x66 - 0x1d)
73
>>> print(chr(73))
'I'
```

> [!SUCCESS] Argumento correcto Pasar la letra **`I`** como argumento al programa.

---

## 📡 Paréntesis — File Descriptors y Syscalls en Linux

> [!TIP] ¿Qué es stdout y los File Descriptors? En Linux/Unix, **todo es un archivo**. Cuando un programa arranca, el sistema operativo le entrega tres "canales" de comunicación ya abiertos, identificados con un número llamado **File Descriptor (fd)**:

|fd|Nombre|Descripción|Syscall asociada|
|---|---|---|---|
|`0`|**stdin**|Entrada estándar (teclado)|`sys_read`|
|`1`|**stdout**|Salida estándar (pantalla)|`sys_write`|
|`2`|**stderr**|Salida de errores (pantalla, canal separado)|`sys_write`|

### Las 4 syscalls fundamentales — Ejemplo completo

```asm
section .data
    filename db "datos.txt", 0    ; Nombre del archivo (termina en 0 = null terminator)

section .bss
    buffer resb 100               ; Espacio para guardar 100 bytes leídos

section .text
    global _start

_start:
    ; ─── 1. OPEN (Syscall 2) ──────────────────────────────────────────
    mov rax, 2          ; ID para sys_open
    mov rdi, filename   ; RDI: Dirección del nombre del archivo
    mov rsi, 0          ; RSI: Flags (0 = Read Only)
    syscall             ; Llamamos al kernel
    ; El kernel devuelve el File Descriptor en RAX → lo guardamos en RDI
    mov rdi, rax

    ; ─── 2. READ (Syscall 0) ──────────────────────────────────────────
    mov rax, 0          ; ID para sys_read
    ; rdi ya tiene el fd del archivo abierto
    mov rsi, buffer     ; RSI: Dónde guardar lo que leamos
    mov rdx, 100        ; RDX: Cuántos bytes máximo leer
    syscall
    ; El kernel devuelve en RAX cuántos bytes leyó realmente
    mov rbx, rax        ; Guardamos esa cantidad para el write

    ; ─── 3. WRITE (Syscall 1) ─────────────────────────────────────────
    mov rax, 1          ; ID para sys_write
    mov rdi, 1          ; RDI: 1 = STDOUT (la pantalla)
    mov rsi, buffer     ; RSI: Qué vamos a imprimir
    mov rdx, rbx        ; RDX: Cuántos bytes (lo que devolvió read)
    syscall

    ; ─── 4. CLOSE (Syscall 3) ─────────────────────────────────────────
    mov rax, 3          ; ID para sys_close
    ; rdi sigue teniendo el fd de datos.txt
    syscall

    ; ─── SALIDA DEL PROGRAMA ──────────────────────────────────────────
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; status 0
    syscall
```

---

## 🧩 Reto 2 — Resta con `sub`

### Análisis del binario

```asm
0000000000401000 <_start>:
  401000:  48 8b 44 24 10    mov    rax, QWORD PTR [rsp+0x10]
  401005:  80 28 1a          sub    BYTE PTR [rax], 0x1a       ; ← Resta
  401008:  80 38 38          cmp    BYTE PTR [rax], 0x38       ; ← Compara con 0x38
  40100b:  75 62             jne    40106f <fail>
  40100d:  c6 04 24 2f       mov    BYTE PTR [rsp], 0x2f
  ...
```

### Solución

Ahora el programa **resta** `0x1a` antes de comparar con `0x38`. Entonces hacemos lo inverso: sumamos lo que se resta.

```
entrada - 0x1a == 0x38
entrada == 0x38 + 0x1a
entrada == 0x52 (decimal: 82)
```

```python
>>> print(0x38 + 0x1a)
82
>>> print(chr(82))
'R'
```

> [!SUCCESS] Argumento correcto Pasar la letra **`R`** como argumento al programa.

---

## 🧩 Reto 3 — XOR bit a bit

### ¿Qué es XOR?

Una operación lógica **bit a bit** que produce `1` cuando los bits son **diferentes**, y `0` cuando son **iguales**:

```
   01001011
⊕ 01011101
──────────
   00010110
```

### 🔑 Propiedad clave — Autoinversa (Involución)

Esta propiedad hace que XOR sea útil en cifrados simples:

```
A ⊕ B = C     → Ciframos A usando la "llave" B
C ⊕ B = A     → Recuperamos A usando la misma llave B
C ⊕ A = B     → Si tenemos el mensaje y el resultado, podemos descubrir la llave
```

> [!INFO] Hacer XOR dos veces con la misma llave devuelve el valor original. Esta es la base de muchos sistemas de cifrado simétrico básico.

Las líneas del objdump fueron:

~~~
xor rax, 0x36
cmp rax, 0x62

Entonces
~~~
~~~
>>> print(hex(0x62 ^ 0x36))
0x54
>>> print(chr(0x54))
T
~~~

Argumento = T

---

## 🧩 Reto 4 — Contraseña en `.rodata`

Este reto carga una cadena (la contraseña) desde la sección **`.rodata`** del binario, fuera de la sección `.text` donde está el código.

### Tres formas de extraerla

---

#### 🔵 Método 1 — GDB (el más didáctico)

Al hacer el disassemble de `_start`, GDB ya nos da una pista directa:

```asm
0x0000000000401000 <+0>:  mov    rdi, QWORD PTR [rsp+0x10]
0x0000000000401005 <+5>:  lea    rsi, [rip+0xff4]    # 0x402000  ← aquí salta $rip
```

```asm
x/10i $rip
   0x401000 <_start>:     mov    rdi, QWORD PTR [rsp+0x10]
   0x401005 <_start+5>:   lea    rsi, [rip+0xff4]    # 0x402000
   0x40100c <loop>:       mov    al,  BYTE PTR [rsi]
```

La instrucción `0x40100c + 0xff4 = 0x402000` — el compilador nos resuelve la dirección. Sabemos que ahí está la contraseña, así que la inspeccionamos:

```bash
# Ver el contenido como string
x/s 0x402000

# Ver los bytes en hex (útil si está cifrada)
x/20xb 0x402000
```

```
(gdb) x/s 0x402000
0x402000: "0pveXJ"
```

---

#### 🟢 Método 2 — `strings` (el más rápido)

```bash
strings /challenge/reverse-me
```

```
0pveXJ
tmp.ZkZJ5fMqNf.o
password
loop
fail
success
__bss_start
_edata
_end
.symtab
.strtab
.shstrtab
.text
.rodata
```

Lo que más parece una contraseña entre todo ese output es: **`0pveXJ`** — y sí, lo es.

---

#### 🟠 Método 3 — `objdump` (el más explícito)

```bash
objdump -s -j .rodata /challenge/reverse-me
```

```
/challenge/reverse-me:     file format elf64-x86-64

Contents of section .rodata:
 402000 30707665 584a00    0pveXJ.
```

Nos muestra directamente el contenido de `.rodata` en hex y ASCII.

---

> [!TIP] Veredicto de dificultad Ciertamente el más difícil de los tres era con GDB 😄 — pero también el más instructivo para entender cómo funciona la memoria en tiempo de ejecución.

---

## 📌 Resumen de técnicas

|Reto|Operación|Estrategia para resolverlo|
|---|---|---|
|1|`add 0x1d` → `cmp 0x66`|`0x66 - 0x1d = 'I'`|
|2|`sub 0x1a` → `cmp 0x38`|`0x38 + 0x1a = 'R'`|
|3|`xor`|Aplicar XOR con la misma llave (propiedad autoinversa)|
|4|Contraseña en `.rodata`|`gdb x/s`, `strings`, u `objdump -s -j .rodata`|

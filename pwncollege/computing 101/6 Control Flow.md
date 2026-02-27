# 🧠 Control Flow — Computing 101

> [!info] Sobre este módulo Este módulo introduce conceptos nuevos de control de flujo en ensamblador x86-64: comparaciones, flags, saltos, labels, switch tables y loops.

---

## 📌 La instrucción `cmp`

`cmp` **compara dos valores** restando el segundo al primero, pero **no guarda el resultado** — solo activa flags.

```asm
cmp rdi, 42
```

### 🚩 Zero Flag (ZF)

|Resultado|ZF|
|---|---|
|Los valores **son iguales** (resta = 0)|`1`|
|Los valores **son distintos**|`0`|

---

## ⚙️ Instrucciones de seteo según ZF

|Instrucción|Significado|Condición|
|---|---|---|
|`setz`|Setear si es **cero** (iguales)|ZF = 1|
|`setnz`|Setear si **no es cero** (distintos)|ZF = 0|

---

## 🧪 Ejercicio 1 — ¿El número de argumentos es 42?

> [!note] Contexto Los argumentos `argc` se pasan al stack al inicio. `rsp` apunta a ellos. Como las flags caben en 1 byte, usamos `dil` (byte bajo de `rdi`).

```asm
.intel_syntax noprefix
.global _start
_start:

    mov rdi, [rsp]       ; cargar argc desde el stack
    cmp rdi, 42          ; comparar con 42
    setz dil             ; ZF=1 si son iguales → dil = 1
    mov rax, 60
    syscall
```

---

## 📦 Recordatorio: `BYTE PTR`

> [!warning] Importante Siempre que trabajemos con **un solo byte** (como un caracter), hay que usar `BYTE PTR` para decirle al CPU el tamaño exacto con el que estamos trabajando.

---

## 🧪 Ejercicio 2 — ¿El primer byte del argumento es `'p'`?

> [!note] Contexto El primer argumento del programa (su valor, la cadena) está en `rsp+16`. Lo cargamos en `rdi` y comparamos su primer byte con el caracter `'p'`.

```asm
.intel_syntax noprefix
.global _start
_start:

    mov rdi, [rsp+16]         ; dirección de la cadena del primer argumento
    cmp BYTE PTR [rdi], 'p'   ; comparar primer byte con 'p'
    setz dil                  ; ZF=1 si son iguales
    mov rax, 60
    syscall
```

---

## 🔀 Saltos y Labels

Se introducen las instrucciones de salto y el concepto de **label** (etiqueta de dirección de memoria).

|Instrucción|Significado|
|---|---|
|`je`|Jump if Equal — salta si son iguales|
|`jne`|Jump if Not Equal — salta si NO son iguales|
|`label:`|Marca una dirección de memoria con nombre, para saltar ahí|

### Estructura típica:

```asm
main:
    [cargar y comparar]
    jne fail          ; saltar a fail si NO son iguales

success:              ; label
    mov rdi, 0
    mov rax, 60
    syscall

fail:                 ; label
    mov rdi, 1
    mov rax, 60
    syscall
```

---

## 🧪 Ejercicio 3 — Verificar `'p'` sin usar `setz`

> [!note] Mismo ejercicio anterior pero usando saltos en lugar de `setz` No se puede setear `1` a `dil` directamente en este contexto, así que se usa `rdi`.

```asm
.intel_syntax noprefix
.global _start
_start:

    mov rdi, [rsp+16]
    cmp BYTE PTR [rdi], 'p'
    jne fail                   ; si no es 'p', saltar a fail

exito:
    mov rdi, 0
    mov rax, 60
    syscall

fail:
    mov rdi, 1
    mov rax, 60
    syscall
```

---

## 🧪 Ejercicio 4 — Verificar la cadena `'pwn'`

> [!note] Mismo patrón pero comparando 3 caracteres consecutivos

```asm
.intel_syntax noprefix
.global _start
_start:

    mov rax, [rsp+16]

    cmp BYTE PTR [rax],   'p'
    jne fail

    cmp BYTE PTR [rax+1], 'w'
    jne fail

    cmp BYTE PTR [rax+2], 'n'
    jne fail

exit:
    mov rdi, 0
    mov rax, 60
    syscall

fail:
    mov rdi, 1
    mov rax, 60
    syscall
```

---

## 🔍 Reto: Reversear contraseña con `objdump`

> [!tip] Comando usado
> 
> ```bash
> objdump -d -M intel /challenge/reverse-me
> ```

### Disassembly relevante:

```asm
401000:  mov    rax, QWORD PTR [rsp+0x10]   ; cargar dirección del argumento
401005:  cmp    BYTE PTR [rax],    0x69      ; comparar 1er caracter
401008:  jne    40107e <fail>
40100a:  cmp    BYTE PTR [rax+0x1], 0x62    ; 2do caracter
40100e:  jne    40107e <fail>
401010:  cmp    BYTE PTR [rax+0x2], 0x65    ; 3er caracter
401014:  jne    40107e <fail>
401016:  cmp    BYTE PTR [rax+0x3], 0x75    ; 4to caracter
40101a:  jne    40107e <fail>
```

### Decodificación de los valores hex:

|Hex|`chr()`|Caracter|
|---|---|---|
|`0x69`|`chr(0x69)`|`i`|
|`0x62`|`chr(0x62)`|`b`|
|`0x65`|`chr(0x65)`|`e`|
|`0x75`|`chr(0x75)`|`u`|

> [!success] Contraseña encontrada: `ibeu`
> 
> ```bash
> /challenge/reverse-me ibeu
> # → pwn.college{YOxVYRmsrGxcOfG7onpAMIaWi2v.01N0czMywSM1ETM0EzW}
> ```

---

## 🗂️ Switch Table (Jump Table)

> [!abstract] Concepto Es el equivalente en ensamblador de un `switch/case`. Se salta a una dirección de memoria calculada a partir del input del usuario + la base de la tabla.

### Disassembly de `_start`:

```asm
0x401000:  mov    rcx, QWORD PTR [rsp+0x10]   ; cargar argumento
0x401005:  xor    eax, eax                     ; limpiar eax
0x401007:  mov    al,  BYTE PTR [rcx]          ; tomar primer byte del argumento → su valor ASCII va al byte al 
0x401009:  mov    rax, QWORD PTR [rax*8+0x401085]  ; calcular dirección de salto desde la tabla
0x401011:  jmp    rax                          ; saltar a esa dirección
```

> [!note] ¿Por qué `*8`? Estamos en 64 bits, cada dirección de memoria ocupa **8 bytes**, por eso se multiplica el índice (valor ASCII del input) por 8.

### Ver la jump table con GDB:

```gdb
x/100a jump_table
```

**¿Qué significa `x/100a`?**

- `x` → Examine (inspeccionar memoria)
- `100` → cantidad de elementos a ver
- `a` → formato Address: GDB interpreta los bytes como direcciones y muestra sus etiquetas si las tienen

### Extracto del resultado:

```
0x401215 <jump_table+400>:  0x401013 <success>   0x401075 <fail>
; ↑ La única entrada que lleva a success está aquí
```

### Cálculo para encontrar el input correcto:

```
Dirección de success en la tabla: 0x401215
Base de la tabla:                  0x401085
Distancia:  0x401215 - 0x401085 = 0x190 = 400 (decimal)

El input se multiplica por 8, así que:
400 / 8 = 50

ASCII 50 = '2'
```

> [!success] Input correcto: `2`
> 
> ```bash
> /challenge/reverse-me 2
> ```

### Verificación en GDB:

```gdb
(gdb) p $rax        ; antes del cálculo
$2 = 50             ; valor ASCII de '2' ✓

(gdb) ni            ; ejecutar mov rax, [rax*8+0x401085]

(gdb) p $rax
$3 = 4198419        ; = 0x401013 = dirección de <success> ✓

(gdb) ni            ; jmp rax → salta a success → da la flag 🎉
```

---

## 🔁 Loop — Comparar argumento con contraseña caracter a caracter

> [!abstract] Concepto Primer vistazo a un **bucle en ensamblador**. Compara el argumento del usuario con una contraseña byte a byte.

### Función `loop`:

```asm
0x40102b:  mov    al, BYTE PTR [rsi]    ; cargar byte de la contraseña en al
0x40102d:  cmp    al, BYTE PTR [rdi]    ; comparar con byte del argumento
0x40102f:  jne    0x40109f <fail>       ; si no son iguales → fail
0x401031:  cmp    al, 0x0               ; ¿es null byte? (fin de cadena)
0x401033:  je     0x40103d <success>    ; si al es 0x0 → llegamos al final → success
0x401035:  inc    rdi                   ; avanzar puntero del argumento
0x401038:  inc    rsi                   ; avanzar puntero de la contraseña
0x40103b:  jmp    0x40102b <loop>       ; repetir
```

> [!note] Lógica del loop
> 
> 1. Compara byte a byte argumento vs contraseña
> 2. Si no coinciden → `fail`
> 3. Si ambos llegan al `null byte 0x0` al mismo tiempo → `success`
> 4. Si coinciden pero no es null → avanza al siguiente caracter y repite

### Función `_start` — donde se define la contraseña:

```asm
0x401000:  mov    rdi, QWORD PTR [rsp+0x10]   ; rdi = puntero al argumento del usuario

; La contraseña se escribe directamente en el stack:
0x401005:  mov    BYTE PTR [rsp],     0x56     ; V
0x401009:  mov    BYTE PTR [rsp+0x1], 0x4b     ; K
0x40100e:  mov    BYTE PTR [rsp+0x2], 0x4e     ; N
0x401013:  mov    BYTE PTR [rsp+0x3], 0x71     ; q
0x401018:  mov    BYTE PTR [rsp+0x4], 0x69     ; i
0x40101d:  mov    BYTE PTR [rsp+0x5], 0x38     ; 8
0x401022:  mov    BYTE PTR [rsp+0x6], 0x0      ; null terminator

0x401027:  lea    rsi, [rsp]   ; rsi = dirección del stack (donde está la contraseña)
                               ; (con lea los [] no desreferencian, solo calculan la dirección)
```

### Decodificación de la contraseña:

|Hex|Caracter|
|---|---|
|`0x56`|`V`|
|`0x4b`|`K`|
|`0x4e`|`N`|
|`0x71`|`q`|
|`0x69`|`i`|
|`0x38`|`8`|

> [!success] Contraseña: `VKNqi8`

> [!tip] Nota sobre `lea` `lea rsi, [rsp]` **no desreferencia** `rsp`. Solo copia la **dirección** de `rsp` en `rsi`. Los corchetes aquí son "sintaxis" de la instrucción, no una desreferencia real. `rsi` apuntará a los bytes de la contraseña en el stack.

---

> [!check] Fin del módulo Control Flow Temas cubiertos: `cmp`, Zero Flag, `setz`/`setnz`, `je`/`jne`, labels, jump tables, loops en ASM.
# Instruction Set Architecture (ISA)

#ISA #x86-64 #ARM #CISC #RISC #registros #ensamblador

---

## ¿Qué es un ISA?

Existe algo llamado **Instruction Set Architecture (ISA)** o en español set de instrucciones para alguna arquitectura.

Un ISA es como un lenguaje de programación, se podría decir.

---

## Filosofías de Diseño

Hay 2 filosofías de diseño:

### CISC: Complex Instruction Set Computing

- Arquitecturas que se enfocan en sacarle todo el jugo al procesador
- Ejemplos: **x86**, **x86-64** (creado por Intel)

### RISC: Reduced Instruction Set Computing

- Arquitectura más simple
- No se ocupa tanto poder para ejecutar
- Más eficientes
- Ejemplo: **Instruction Set ARM** es el lenguaje que usan los procesadores más nuevos que usan esta filosofía

---

## Lenguajes de Ensamblador Comunes

Entonces esos son los lenguajes más comunes de ensamblador que nos toparemos: **x86-64**, **ARM**.

- **ARM** tiene su propio instruction set, tendrá alguna que otra cosa similar a x86/x86-64 pero sí es diferente
- En cambio, **x86** y **x86-64** sí son muy similares (aprendiendo x86-64 aprendes x86)

---

## Syntax Flavors

Los syntax flavors es como referirse al mismo código pero escrito de manera distinta.

Se usará a lo largo de este corto curso la **syntax flavor de Intel**.

### Ejemplo de Instrucción

```asm
mov rax, 42
```

- `mov` es una instrucción
- `rax` es uno de los registros de x86-64
- `42` es un valor

Esta instrucción dice: **mover el valor 42 al registro rax**

---

## ¿Qué son los Registros?

Los registros son pedazos de memoria que están muy cerca del CPU. Lo podemos ver como una "variable" y esta memoria es la más rápida a la que tenemos acceso como programadores, por ende también es muy limitada.

---

## Tamaño de los Registros en x86-64

En x86-64 el tamaño de un registro es de **64 bits**, es decir **8 bytes**. Podemos acceder a estos de 5 maneras diferentes:

```
; Registros de 64 bits (x86-64)

rax         ; Registro de 64 bits (completo)
├── eax     ; Registro de 32 bits (mitad baja de rax)
    ├── ax  ; Registro de 16 bits (mitad baja de eax)
    │   ├── ah  ; Byte alto de ax (8 bits)
    │   └── al  ; Byte bajo de ax (8 bits)
```

Podemos ver cómo se dividen en 5 accesos: desde abajo en 2 hemisferios de 8 bits `ah` y `al`, luego los 2 juntos que es `ax`, luego el registro de 32 bits `eax` para acabar con `rax` de 64 bits completo.

---

## Registros Principales de Propósito General

Son 4 principales en total:

### Registro RAX (Acumulador)

```
rax         ; 64 bits
├── eax     ; 32 bits (mitad baja)
    ├── ax  ; 16 bits
    │   ├── ah  ; 8 bits (byte alto)
    │   └── al  ; 8 bits (byte bajo)
```

### Registro RBX (Base)

```
rbx         ; 64 bits
├── ebx     ; 32 bits (mitad baja)
    ├── bx  ; 16 bits
    │   ├── bh  ; 8 bits (byte alto)
    │   └── bl  ; 8 bits (byte bajo)
```

### Registro RCX (Contador)

```
rcx         ; 64 bits
├── ecx     ; 32 bits (mitad baja)
    ├── cx  ; 16 bits
    │   ├── ch  ; 8 bits (byte alto)
    │   └── cl  ; 8 bits (byte bajo)
```

### Registro RDX (Datos)

```
rdx         ; 64 bits
├── edx     ; 32 bits (mitad baja)
    ├── dx  ; 16 bits
    │   ├── dh  ; 8 bits (byte alto)
    │   └── dl  ; 8 bits (byte bajo)
```

---

## Registros Adicionales

Existen 2 registros más de propósito general y los 3 que había visto en la clase de Elías más a detalle:

### Registros de propósito general con subdivisiones

```
rax         ; 64 bits (Acumulador)
├── eax     ; 32 bits
    ├── ax  ; 16 bits
    │   ├── ah  ; 8 bits (byte alto)
    │   └── al  ; 8 bits (byte bajo)

rbx         ; 64 bits (Base)
├── ebx     ; 32 bits
    ├── bx  ; 16 bits
    │   ├── bh  ; 8 bits (byte alto)
    │   └── bl  ; 8 bits (byte bajo)

rcx         ; 64 bits (Contador)
├── ecx     ; 32 bits
    ├── cx  ; 16 bits
    │   ├── ch  ; 8 bits (byte alto)
    │   └── cl  ; 8 bits (byte bajo)

rdx         ; 64 bits (Datos)
├── edx     ; 32 bits
    ├── dx  ; 16 bits
    │   ├── dh  ; 8 bits (byte alto)
    │   └── dl  ; 8 bits (byte bajo)
```

### Registros de propósito general sin subdivisiones de 8/16 bits

```
- RDI: 64 bits (Registro completo)
    
    - ├── EDI: 32 bits (Parte baja de 32 bits)
        
        - ├── DI: 16 bits (Parte baja de 16 bits)
            
            - ├── DIL: 8 bits (Byte bajo de DI) *(Accesible solo en modo 64-bit)*

- RSI: 64 bits (Registro completo)
    
    - ├── ESI: 32 bits (Parte baja de 32 bits)
        
        - ├── SI: 16 bits (Parte baja de 16 bits)
            
            - ├── SIL: 8 bits (Byte bajo de SI) *(Accesible solo en modo 64-bit)*
```

### Registros especiales

```
rip         ; 64 bits (Instruction Pointer - Contador de programa)
rsp         ; 64 bits (Stack Pointer - Puntero de pila)
rbp         ; 64 bits (Base Pointer - Puntero base)
```

> **Nota:** Los que tienen la `r` al inicio y números no se incluyeron, son de 64 bits y de x86-64 exclusivos si bien de eso es este curso no se mencionan a profundidad.

---

## Registros Que Debemos Acordarnos Siempre

### `rip` - Instruction Pointer

Dice cuál es la siguiente línea de código que debe de correrse. Se puede manipular indirectamente, no directo, por medio de llamadas o vueltas de llamadas.

> **Importante para los hackers**

### `rsp` - Stack Pointer

Se utiliza para saber en qué posición estamos actualmente en el stack de memoria. Siempre apunta al tope.

### `rbp` - Base Pointer

Se utiliza para guardar la posición del stack al momento de entrar a una función. Se utiliza para crear las variables locales de una función, poder accesar a ellas y utilizarlas sin problema. El `rbp` junto al `rsp` se utilizan en conjunto para restaurar la ejecución entre llamadas de funciones.

### `rax` - Primer Registro de Memoria

Se utiliza usualmente para almacenar el valor que se regresa de las funciones. Por ejemplo, función que suma 2 números, el retorno se guardará usualmente en `rax`.

---

## Ejemplos Prácticos con Instrucciones

### Ejemplo 1: Mover valor a eax

```asm
mov eax, 0xdeadbeef
```

Entonces la instrucción dice que vamos a mover (`mov`) el valor `0xdeadbeef` al registro `eax`, recordando que `eax` es el registro `rax` pero en el acceso a los primeros 32 bits.

**Nota:**

- `[0x]` ← esto solo quiere decir que es un valor hexadecimal
- Un dígito que puede ir desde 0 hasta 15 (16 valores distintos)

**Entonces así se vería:**

```
; Estado de los registros después de: mov eax, 0xdeadbeef

; Registro RAX
rax         ; 64 bits: 0x00000000deadbeef
├── eax     ; 32 bits: 0xdeadbeef
    ├── ax  ; 16 bits: 0xbeef
    │   ├── ah  ; 8 bits: 0xbe
    │   └── al  ; 8 bits: 0xef
```

### Ejemplo 2: Mover valor a bx

```asm
mov bx, 0xbabe
```

```
; Registro RBX
rbx         ; 64 bits: ??? 
├── ebx     ; 32 bits: ???
    ├── bx  ; 16 bits: 0xbabe
    │   ├── bh  ; 8 bits: 0xba
    │   └── bl  ; 8 bits: 0xbe
```

### Ejemplo 3: Mover valor a rcx

```asm
mov rcx, 0xdeadbeef
```

Aunque indiquemos el registro entero de 64 bits, como el valor es de 32 bits se guarda igual que el primero.

```
; Registro RCX
rcx         ; 64 bits: 0x00000000deadbeef
├── ecx     ; 32 bits: 0xdeadbeef
    ├── cx  ; 16 bits: 0xbeef
    │   ├── ch  ; 8 bits: 0xbe
    │   └── cl  ; 8 bits: 0xef
```

### Ejemplo 4: Sobrescribir ecx

```asm
mov ecx, 0xdeadbabe
```

Ahora indica los primeros 32 bits de ese mismo registro (`rcx`) así que solo se sobrescribe `ba-be`.

```
; Registro RCX
rcx         ; 64 bits: 0x00000000deadbabe
├── ecx     ; 32 bits: 0xdeadbabe
    ├── cx  ; 16 bits: 0xbabe
    │   ├── ch  ; 8 bits: 0xba
    │   └── cl  ; 8 bits: 0xbe
```

### Estado del Registro RDX

```
; Registro RDX
rdx         ; 64 bits: ??? 
├── edx     ; 32 bits: ???
    ├── dx  ; 16 bits: ???
    │   ├── dh  ; 8 bits: ???
    │   └── dl  ; 8 bits: ???
```

---

## Nota Importante

> **Nota:** La instrucción `mov eax, 0xdeadbeef` solo afecta a los 32 bits bajos de RAX. Los 32 bits altos de RAX se ponen a cero por diseño en x86-64.
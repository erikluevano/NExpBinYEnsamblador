---
tags:
  - #assembly
  - #syscall
  - #x86-64
  - #registros
  - #rax
  - #rdi
  - #rsi
  - #exit
  - #as
  - #ld
  - #intel-syntax
---
---
tags:
  - #assembly
  - #syscall
  - #x86-64
  - #registros
  - #rax
  - #rdi
  - #rsi
  - #exit
  - #as
  - #ld
  - #intel-syntax
---

# Syscalls y Funciones en Assembly

Entonces, ahora lo nuevo que no sabía (no recordaba) es que las funciones tienen un número al ser llamadas. Por ejemplo, la función `exit` tiene el número de 60, y al invocar un syscall el número que se toma es el que esté almacenado en el registro `rax`.

Por ejemplo, para invocar esa función de `exit` sería:
```asm
mov rax, 60
syscall
```

Y `exit` tomaría un argumento para dar el código de estado o de error del cual salió, el cual lo toma de lo que haya almacenado en `rdi`. Por ejemplo:
```asm
mov rdi, 42
mov rax, 60
syscall
```

Esto haría que el programa se cierre con código de error 42.

## Estructura básica del código

Para que no salten errores debemos poner el código así:
```asm
.intel_syntax noprefix    <- indicar la sintaxis del código ensamblador
.global _start            <- indicar dónde comienza todo
_start:                   <- la función que se invoca primero indicado en global
    mov rdi, 42
    mov rax, 60
    syscall
```

## Compilación y linkeo

Ahora para compilarlo en `program.o`:
```bash
as -o program.o program.s
```

`program.s` es el código de ensamblador de arriba.

Y solo faltaría linkearlo con:
```bash
ld -o program program.o
```

Y para inspeccionar la última variable del sistema damos:
```bash
echo $?
```

## Reto: Sacar el valor de un registro rsi como código de salida

Un reto muy simple para sacar el valor de un registro `rsi` como código de salida para que nos den la flag:
```asm
.intel_syntax noprefix
.global _start
_start:
    mov rdi, rsi
    mov rax, 60
    syscall
```

Ahora lo compilamos y linkeamos:
```bash
as -o mija.o mija.s
ld -o mija mija.o
```

## Lección aprendida

Y bueno, ahora algo muy tonto de lo que a veces uno ignora sin querer es que obviamente si ejecuto eso y ya, el registro `rsi` no tendrá el valor o no me mostrará lo que espera el challenge porque no tiene nada o tiene basura. En su lugar, obviamente `/challenge/check`, ese programa sí establece ese valor secreto a `rsi`, entonces al correrlo por allí pues sí funciona. Pequeñas cosas insignificantes que hacen a uno aprender más.

---

Este fue el final del módulo 1 de este dojo.
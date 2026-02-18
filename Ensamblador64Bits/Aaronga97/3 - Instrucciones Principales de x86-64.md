---

tags:

- assembly
- mov
- add
- sub
- flags
- ZF
- SF
- CF
- OF
- cmp
- test
- jmp
- je
- jne
- call
- ret
- registros
- rax
- complemento-a-2
- instrucciones-condicionales

---

# Introducción al Lenguaje Ensamblador (Ahora sí)

## Instrucciones Básicas

### MOV - Mover

```assembly
mov dst, src
```

Mueve el valor de `src` al destino `dst`

**Ejemplo:**

```assembly
mov rax, 42
```

Mueve el valor de 42 al registro `rax`

### ADD - Sumar

```assembly
add dst, src
```

Suma `dst + src`, el resultado se guarda en `dst`

**Ejemplo:**

```assembly
add rax, 42
```

Esto sería como un `rax += 42`

### SUB - Restar

```assembly
sub dst, src
```

Es una resta `dst - src`, el resultado se guarda en `dst`

**Ejemplo:**

```assembly
sub rax, 42
```

Igual a hacer `rax -= 42`

---

## Las Flags

Una flag es como un booleano, una bandera, tiene dos posibles valores: `0`, `1` o encendida o apagada. Estas se actualizan en ciertas operaciones, se utilizan para las condicionales, "esta variable es igual a esta", etc. En ensamblador se hace mediante estas flags.

Se mencionarán 4 flags:

### ZF - Zero Flag

Te dice si el resultado de una operación es 0

**Ejemplos:**

```assembly
7 - 2 = 5  ; La bandera ZF estará apagada [0]
5 - 5 = 0  ; La ZF se encenderá [1]
```

### SF - Sign Flag

Se prende cuando el bit más grande (el del extremo lado izquierdo (MSB)) sea 1, porque un número cuando tiene signo, el bit de la mera izquierda es el que se prende. En la representación de complemento a 2, ese número en realidad es un número con signo (negativo).

**Ejemplo:**

```assembly
mov al, 0   ; al = 8-bit register
sub al, 1   ; 0b11111111 (two's complement)
```

### CF - Carry Flag

Se prenderá cuando tenemos un overflow de un número que no tiene signo:

#### Unsigned Overflow

```assembly
mov al, 255  ; 8-bit register
```

Recordar que con 8 bits lo que podemos tener son valores del 0 al 255. Por eso las direcciones IP son de 32 bits: 255.255.255.255

Si hacemos:

```assembly
add al, 1  ; al = 0, CF = 1 (unsigned overflow)
```

Lo que pasa es que se da la vuelta, pues el valor máximo para 8 bits es 255 (valor que ya tenía) y al sumarle 1 este dará la vuelta y se convertirá en 0. El 1 se iría a la izquierda a la carry flag prendiéndola bien rico.

#### Número Prestado en Resta

```assembly
mov al, 5   ; 8-bit register
sub al, 10  ; 5 < 10, CF = 1, necesitamos número prestado del siguiente nivel
```

Lo que pasó es que al ser 5 menor que lo que se le quiere restar (10), se debe "pedir prestado" al siguiente nivel activando la CF.

#### Último Bit que se Salió en un Shift

```assembly
mov al, 0b10000001  ; [0b es un prefijo para representar un número de manera binaria]
```

(Función `shr` = función shift right que es correr todos los bits a la derecha)

```assembly
shr al, 1  ; Shift right, CF = 1 (El último bit que se sale es 1)
           ; 0b01000000 | 1 (sale un 1 por la derecha, entra un 0 por la izquierda)
```

Ese 1 que se salió es el que se guarda en el carry flag activándola. Si hubiese sido un 0, ese se guardaría en el carry flag.

### OF - Overflow Flag

Overflow de aritmética de números con signo

**Ejemplo:**

```assembly
mov al, 100
add al, 50  ; 127 (máximo con signo de 8-bit) rango de -128 a 127
            ; Resultado da la vuelta a -106
            ; OF = 1 (signed overflow) se prende la overflow con signo
```

Cuando pasamos de 127 positivo damos un overflow pasándonos a la posición más pequeña -128. Si fuera 127 pero como nos pasamos con 23 (150 total), le sumamos esos 23 a -128 dando como resultado -106.

### Pequeño Resumen

- **ZF - Zero flag**: resultado es 0
- **SF - Sign flag**: bit más grande es 1
- **CF - Carry flag**: prestado en resta, bit se sale, unsigned overflow
- **OF - Overflow flag**: signed overflow

---

## Instrucciones Condicionales

### CMP - Comparar

```assembly
cmp a, b
```

**Lo que está pasando:** `a - b` activa banderas

Es decir, activa las banderas entre ellas la ZF (zero flag). Si el resultado es 0, el valor es el mismo; si no, pues son diferentes.

### TEST - Probar

```assembly
test a, b
```

**Lo que pasa:** `a & b`, activa banderas

Es la compuerta lógica de AND/&. Si son iguales true, si son diferentes false.

### JMP - Saltar

```assembly
jmp function
```

**Lo que pasa:** salta a `function`

### JE - Saltar si es Igual

```assembly
je function
```

**Lo que pasa:** salta a `function` si `ZF = 1`

Es decir que si la ZF está prendida = 1, salta a la función; si no, no.

Entonces sería como un `if` si mezclamos `cmp a, b` con `je function`. Se compara `a` y `b`, se activa o no la bandera ZF, y se activa o no el salto dependiendo de la operación que dio resultado a la ZF.

### JNE - Saltar si No es Igual

```assembly
jne function
```

**Lo que pasa:** salta a `function` si `ZF = 0`

Esta es lo mismo pero saltará a la función si la zero flag está apagada. Sería como un `else`.

---

## Funciones: CALL y RET

### CALL - Llamar Función

```assembly
call function
```

**Esto es lo que hace tras escena:** `push rip, jmp fn`

Esto hace un push al instruction pointer (`rip`) y luego un jump (`jmp`) a la función. Como en el ejemplo de C, guarda en el stack el instruction pointer y salta a la función nueva. El salto solo cambia el `rip` a la línea en la que está la función.

### RET - Retornar

```assembly
ret
```

**Lo que hace:** `pop rip`

Lo que hace es hacerle un pop al instruction pointer (`rip`), o mejor dicho, `pop` siempre popea al último elemento del stack *rsp* y se lo asignaría al `rip` (instruction pointer).
````
# Notas de Práctica: Ensamblador x86_64 y Manipulación de Datos

---
**Tags:** #x86_64 #Assembly #Registers #BitwiseOperations #StackManipulation #MemoryDereference #ControlFlow #SystemV_ABI #Endianness #JumpTables

---

## Introducción a Instrucciones Básicas
Este módulo es de práctica. Parece que nos pusieron a hacer asignaciones con:

* **mov**
* **imul**
* **add**

Como ya habíamos hecho antes. Estas últimas como tal no las habíamos usado, pero ya sabía para qué eran. Aparte, recordé que `mul` e `imul` son para *unsigned* y *signed*; no trabajan igual y existen diferencias entre ellas.

## Operaciones de División y Modulo
Luego nos introducen **div**, que es un poco rara:

```assembly
.intel_syntax noprefix
.global _start
_start:

mov rdx, 0      # Parte alta del dividendo = 0
mov rax, rdi    # Parte baja del dividendo = distance
div rsi          # Divide rdx:rax por rsi (time)
                # rax = cociente = distance / time = speed
                # rdx = resto
# ¡NO hacer mov rax, rsi aquí!
# rax ya tiene el resultado correcto (speed)
````

Este código fue para resolver esto:

`speed = distance / time`, donde:

- `distance = rdi`
    
- `time = rsi`
    
- `speed = rax`
    

Entonces:

Para la instrucción div reg, sucede lo siguiente:

1. `rax = rdx:rax / reg`
    
2. `rdx = remainder (resto)`
    

`rdx:rax` significa que `rdx` será los 64 bits superiores del dividendo de 128 bits y `rax` será los 64 bits inferiores.

Se dice que `div` trabaja con un operador de 128 bits, es decir, el doble de un registro, ¿para abarcar números muy grandes? Tal vez.

Esto pasaría si no tuviese 0 en rdx:

rdx = 1, rax = 10 → rdx:rax = $100...00010$ (en binario) = ¡un número ENORME!

div 3 → (número enorme) / 3 = resultado incorrecto.

Entonces usa 2 registros `rdx:rax` juntos (128 bits / 16 bytes) porque se usa con números grandes al parecer y, por defecto, el cociente o resultado lo guarda en `rax`. Por eso el código quedó así:

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
mov rdx, 0
mov rax, rdi
div rsi
```

### Obtener el resto (módulo) rdi % rsi

Tenemos que primero anular el lado alto del número doble que usará div:

mov rdx, 0

Luego tenemos que asignar el valor de rdi a rax como número "no enorme" para div (parte baja):

mov rax, rdi

Luego hacemos el div con rsi:

div rsi

Ahora el módulo o sobrante estará en `rdx`. Debemos hacer `mov rax, rdx`, ya que el problema era asignarle a `rax` el resto; sin hacer eso, lo que habrá en `rax` es el resultado de la división:

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
mov rdx, 0
mov rax, rdi
div rsi
mov rax, rdx
```

## Acceso Parcial a Registros

Después nos mencionan los diferentes accesos de los registros. Como sabemos, son de 64 bits, pero tienen un acceso de 32, luego de 16 y por último de 8 bits. Ya lo habíamos visto antes; nos piden mover un valor a los 8 bits altos de `ax`.

Plaintext

```
MSB                                                LSB
+----------------------------------------------------+
|                    rax                             |
+--------------------+-------------------------------+
                     |          eax                  |
                     +---------+---------------------+
                               |         ax          |
                               +----------+----------+
                               |    ah    |    al    |
                               +----------+----------+
```

Quiere decir que al registro `ah` se le asignará el valor `0x42`.

## Módulo con Potencias de 2

Seguimos computando; esta vez nos enseñaron a hacer el módulo (`%`) de manera más sencilla sin usar la operación `div`. Esto solo es posible si en `x % y`, la `y` es potencia de 2. En este caso lo son:

- `rdi % 256`
    
- `rsi % 65536`
    

Nos dicen:

> "If we have x % y, and y is a power of 2, such as 2^n, the result will be the lower n bits of x."

Entonces el módulo debe estar en el bit bajo de cada registro y recordemos que los valores de bits bajos van con bits bajos. Por ejemplo, nos piden:

- `rax = rdi % 256`
    
- `rbx = rsi % 65536`
    

Pero obvio que esos valores no van en rax o rbx directamente; van en su equivalente bajo. Por ejemplo, debemos hacer un:

bit bajo rbx = bit bajo de rdi (porque allí está el módulo).

Sería:

al = dil → mov al, dil

bx = si → mov bx, si (porque el valor 65536 es de 16 bits, no de 8).

De hecho, los dos se pasan por 1 los valores máximos de los bits que son de 8 y 16, no sé por qué. Bueno, no pasa nada.

## Desplazamiento de Bits (Shifting)

Esto se puede hacer para que los bytes de un registro corran hacia la derecha o izquierda. Como lo habíamos visto antes, esto también activa las flags, si no me equivoco, la _Carry Flag_.

Este reto consiste en quedarnos con el quinto byte (B4), el último en significancia en rax de rdi. Para solo quedarnos con ese valor, tenemos que primero:

rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |

Objetivo: Setear rax al valor de B4.

Como nos quedaremos con el byte 4, corremos todo a la derecha para eliminar los valores B3 al B0; por la izquierda entrarán ceros.

Luego tenemos que eliminar del B5 al B7 haciendo un corrido a la izquierda de 52 bits (porque 7x8=56, ya que B4 quedó en la posición de B0 con el corrimiento pasado y cada B son 8 bits). Con ese segundo deslizamiento borramos los B que faltaban. Ahora tenemos que poner nuestro B4 en la posición B0 con otro corrimiento a la derecha de nuevo de 56 bits y así nos quedaríamos con solo ese valor:

Fragmento de código

```
0x400000:       mov     rax, rdi
0x400003:       shr     rax, 0x20
0x400007:       shl     rax, 0x38
0x40000b:       shr     rax, 0x38
```

De esa manera nos quedamos con `B4` usando corrimientos de bits.

## Operaciones Lógicas (Bitwise)

Vienen las comparaciones de registros bit a bit. Se usa la palabra _Bitwise_ y se emplean las funciones:

- **AND**
    
- **OR**
    
- **XOR**
    

Recordando las tablas de verdad, se comparan los bits uno a uno de los dos registros.

### Tablas de Verdad

AND (A=1 y B=1 = 1; si uno es 0, entonces 0)

| A | B | X |

|---|---|---|

| 0 | 0 | 0 |

| 0 | 1 | 0 |

| 1 | 0 | 0 |

| 1 | 1 | 1 |

OR (si al menos uno es 1, entonces 1)

| A | B | X |

|---|---|---|

| 0 | 0 | 0 |

| 0 | 1 | 1 |

| 1 | 0 | 1 |

| 1 | 1 | 1 |

XOR (exclusivo: si son diferentes es 1, si son iguales es 0)

Nota del usuario: El usuario anotó "si los 2 son iguales es = 1 y si son diferentes = 0", pero la tabla correcta es:

| A | B | X |

|---|---|---|

| 0 | 0 | 0 |

| 0 | 1 | 1 |

| 1 | 0 | 1 |

| 1 | 1 | 0 |

Nos ponen un challenge: tenemos que setear el valor de la operación `rdi AND rsi` en `rax`. El reto dice que `rax` tiene todos los bits en 1 y no nos dejan usar `mov`. Entonces hacemos:

Fragmento de código

```
and rdi, rsi
```

Como `rax` tiene todo en 1, para copiar el valor de `rdi` bastaría con hacer un `AND rax, rdi` para que se copien los 1 solo donde coincida `rax` con `rdi`.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
and rdi, rsi
and rax, rdi
```

**Diferencia entre OR y XOR:** OR es si alguno es 1; XOR es solo si exclusivamente uno es 1.

### Determinar si un número es par

La forma de saberlo es si el bit menos significativo es 0. Podemos usar operaciones lógicas AND para aislar ese bit:

and rdi, 1

Eso compararía los 64 bits de `rdi` con `1`. Si queda como 1, entonces no es par; si es 0, entonces lo es.

Para aislar el más significativo, podríamos usar hexadecimal. Recordemos que en hexadecimal se dividen los 64 bits en grupos de cuatro: 16 grupos con 16 valores posibles.

El "número mágico" sería: 0x8000000000000000

El 8 es 1000, que es el bit más significativo. Los ceros restantes representan los otros 15 grupos de bits como 0000, aislando solo el más significativo.

¿Por qué and rdi, 1 nos daría rdi 1 o 0? Porque comparamos rdi con 63 ceros y un 1 al final:

...00000000001 con rdi = ...100100101[0]

Todo lo anterior al bit menos importante se volverá 0.

Sabiendo esto, podemos:

1. Poner `rax` en 0 con la operación `xor rax, rax` (un XOR con el mismo registro anula todo lo duplicado).
    
2. Requerimos que si es par (rdi = 0), el valor en rax sea 1; si no, 0. Invertimos el valor de rdi:
    
    xor rdi, 1 (si es 0 se vuelve 1, si es 1 se vuelve 0).
    
3. Movemos el resultado a `rax`: `xor rax, rdi`.
    

Fragmento de código

```
0x400000:       and     rdi, 1
0x400004:       xor     rax, rax
0x400007:       xor     rdi, 1
0x40000b:       xor     rax, rdi
```

Lógica final:

Si x es even (par) → y = 1.

Si no → y = 0.

## Desreferencia de Memoria

Asignar a rax el valor que contiene una dirección de memoria: [0x404000]. Es un repaso:

mov rax, [0x404000]

Sin los corchetes, se asignaría el valor hexadecimal literal. El siguiente challenge es al revés: poner lo que hay en rax en [0x404000].

Otro challenge: poner en `rax` lo que hay en `[0x404000]` y luego sumarle a esa dirección la cantidad hexadecimal `0x1337`.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
mov rax, [0x404000]
add qword PTR [0x404000], 0x1337
```

Debemos tratarla como `qword` (64 bits).

### Tipos de Punteros (PTR)

`PTR` le dice al procesador el tamaño de la caja en esa dirección:

- **BYTE PTR**: Carta pequeña.
    
- **WORD PTR**: Paquete mediano (16 bits).
    
- **DWORD PTR**: Caja grande (32 bits).
    
- **QWORD PTR**: Contenedor (64 bits).
    

Sin eso es ambiguo: `mov [0x404000], 5` —¿5 qué? ¿Bytes, 16 bits, 32 bits?—.

**Contexto Histórico del WORD (16 bits):**

- 1978: Intel 8086 (16 bits). `WORD` se definió como 16 bits por ser el tamaño nativo.
    
- Se mantuvo por compatibilidad.
    
- Evolución: 80386 (32 bits) -> `DWORD`. x86-64 (2003) -> `QWORD`.
    
- Cambiarlo sería un problema documental masivo.
    

En x86_64 puedes acceder a estos tamaños al desreferenciar, igual que con los registros:

- `mov al, [address]` -> Mueve el byte menos significativo.
    
- `mov ax, [address]` -> Mueve la word menos significativa.
    
- `mov eax, [address]` -> Mueve la double word menos significativa.
    
- `mov rax, [address]` -> Mueve la quad word completa.
    

Esto **no limpia** los bits superiores del registro (excepto en accesos de 32 bits a registros de 64 bits, donde x86_64 suele poner a cero la parte alta automáticamente).

Challenge de práctica:

Setear rax al byte, rbx a la word, rcx a la dword y rdx a la qword de 0x404000:

Fragmento de código

```
0x400000:       mov     al, byte ptr [0x404000]
0x400007:       mov     bx, word ptr [0x404000]
0x40000f:       mov     ecx, dword ptr [0x404000]
0x400016:       mov     rdx, qword ptr [0x404000]
```

## Little Endian y Constantes Grandes

Little Endian escribe al revés en memoria. 0x1337:0xdead se ve como:

[0x1337]=0xad, [0x1338]=0xde.

Challenge: mover `0xdeadbeef00001337` y `0xc0ffee0000` a las direcciones en `rdi` y `rsi`. No podemos mover constantes tan grandes directamente a memoria; hay que cargarlas en un registro primero.

Fragmento de código

```
0x400000:       movabs  rax, 0xdeadbeef00001337
0x40000a:       mov     qword ptr [rdi], rax
0x40000d:       movabs  rax, 0xc0ffee0000
0x400017:       mov     qword ptr [rsi], rax
```

Como dice la instrucción: "El mexicano no lee", pero requiere trucos para asignar constantes grandes.

Sumar dos `qword` en la dirección de `rdi` y guardar en `rsi`:

Fragmento de código

```
0x400000:       mov     rax, qword ptr [rdi]
0x400003:       add     rax, qword ptr [rdi + 8]
0x400007:       mov     qword ptr [rsi], rax
```

## El Stack (Pila)

Instrucciones `pop` y `push`:

- `push`: Mete al tope (donde apunta `rsp`).
    
- `pop`: Quita el tope y lo mete en el registro.
    

Challenge: Al tope del stack restarle lo de `rdi` y meterlo de nuevo:

Fragmento de código

```
0x400000:       pop     rax
0x400001:       sub     rax, rdi
0x400004:       push    rax
```

Challenge: Invertir valores de `rdi` y `rsi` usando solo stack:

Fragmento de código

```
0x400000:       push    rdi
0x400001:       push    rsi
0x400002:       pop     rdi
0x400003:       pop     rsi
```

Challenge: Promedio de 4 `qwords` en `rsp` y poner el resultado en el stack:

Fragmento de código

```
0x400000:       mov     rax, qword ptr [rsp]
0x400004:       add     rax, qword ptr [rsp + 8]
0x400009:       add     rax, qword ptr [rsp + 0x10]
0x40000e:       add     rax, qword ptr [rsp + 0x18]
0x400013:       mov     rdx, 0
0x40001a:       mov     rcx, 4
0x400021:       div     rcx
0x400024:       push    rax
```

## Saltos (Jumps)

- **Relative jumps**: Salto +/- desde la siguiente instrucción.
    
- **Absolute jumps**: Salto a una dirección específica.
    
- **Indirect jumps**: Salto a la dirección especificada en un registro.
    

Reto: Saltar a la dirección absoluta `0x403000`.

Fragmento de código

```
0x400073:       mov     rax, 0x403000
0x40007a:       jmp     rax
```

### Uso de Labels y Relleno

Aprendemos `.rept`, `nop`, label y `.endr`.

- `nop`: No hace nada (1 byte).
    
- `.rept n`: Repite la instrucción `n` veces.
    
- Label: Etiqueta donde saltará el `jmp`.
    

Reto: El `jmp` debe saltar exactamente `0x51` bytes de la posición actual y setear `rax` a `0x1`.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
jmp birria
.rept 0x51
nop
.endr

birria:
mov rax, 0x1
```

**Trampolín de dos saltos:**

1. Primer `jmp` relativo a `0x51` bytes.
    
2. En `0x51`, poner el tope del stack en `rdi`.
    
3. Saltar a la dirección absoluta `0x403000`.
    

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
jmp burras
.rept 0x51
nop
.endr

burras:
pop rdi
mov rax, 0x403000
jmp rax
```

## Saltos Condicionales (IF/ELSE)

Challenge:

Plaintext

```
if [x] is 0x7f454c46:
    y = [x+4] + [x+8] + [x+12]
else if [x] is 0x00005A4D:
    y = [x+4] - [x+8] - [x+12]
else:
    y = [x+4] * [x+8] * [x+12]
Donde: x = rdi, y = rax.
```

Pueden ser con signo (`imul`) y son `dword`.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
xor rax, rax
cmp dword PTR [rdi], 0x7f454c46
jne nopero
mov eax, dword PTR [rdi+4]
add eax, dword PTR [rdi+8]
add eax, dword PTR [rdi+12]
jmp done

nopero:
cmp dword PTR [rdi], 0x00005A4D
jne else
mov eax, dword PTR [rdi+4]
sub eax, dword PTR [rdi+8]
sub eax, dword PTR [rdi+12]
jmp done

else:
mov eax, dword PTR [rdi+4]
imul eax, dword PTR [rdi+8]
imul eax, dword PTR [rdi+12]
jmp done

done:
```

## Switch Case y Jump Tables

La instrucción `lea` calcula y guarda una dirección: `lea rax, [rsi+32]`.

Reto: Tabla de saltos. rdi tiene el caso, rsi la dirección base de la tabla.

Cada dirección en la tabla mide 8 bytes.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
cmp rdi, 3
ja default

lea rax, [rsi + rdi*8]
jmp [rax]

default:
lea rax, [rsi + 32]
jmp [rax]
```

## Bucles (Loops)

Sumar qwords de una dirección y sacar el promedio.

rdi = base addr, rsi = cantidad (n), rax = promedio.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
xor rax, rax    # acumulador
mov rbx, 0      # contador

loop:
cmp rbx, rsi
jae end         # Si rbx >= rsi, terminar
add rax, [rdi + rbx*8]
add rbx, 1
jmp loop

end:
mov rdx, 0
div rsi
```

### Contar bytes no nulos (While loop)

Si `rdi = 0`, entonces `rax = 0`. Usamos `test` para verificar nulidad.

Fragmento de código

```
.intel_syntax noprefix
.global _start
_start:
xor rcx, rcx
test rdi, rdi
jz end

while:
cmp byte PTR [rdi + rcx], 0
je end
add rcx, 1
jmp while

end:
mov rax, rcx
```

_Nota: Es vital especificar `byte PTR` para que el compilador sepa el tamaño de la comparación._

## Funciones y Convención de Llamadas (ABI)

Implementar `str_lower(src_addr)`. Si es mayúscula (`<= 0x5a`), llamar a `foo([src_addr])`.

**Reglas System V ABI:**

- Primer argumento → `rdi`.
    
- Valor retorno → `rax`.
    
- Hay que preservar `rdi` y `rax` antes de llamar a `foo`.
    

Fragmento de código

```
.intel_syntax noprefix
.global str_lower

str_lower:
    push rbx             # Preserva rbx (callee-saved)
    xor rax, rax         # i = 0
    test rdi, rdi        # src_addr != NULL?
    jz fin

while:
    mov cl, byte ptr [rdi]
    test cl, cl          # Fin de string?
    jz fin
    cmp cl, 0x5a         # Es mayúscula? (<= 'Z')
    jg skipif
    
    push rax             # Guarda contador i
    push rdi             # Guarda dirección
    
    movzx rdi, cl        # Argumento para foo
    call 0x404000        # Llama a foo
    
    pop rdi              # Recupera dirección
    pop rbx              # Recupera i en rbx temporalmente
    
    mov byte ptr [rdi], al
    inc rbx              # i++
    mov rax, rbx         # Actualiza rax con i

skipif:
    inc rdi
    jmp while

fin:
    pop rbx
    ret
```

### Tabla de saltos condicionales

- **Signed**: `jl` (less), `jle`, `jg` (greater), `jge`.
    
- **Unsigned**: `jb` (below), `jbe`, `ja` (above), `jae`.
    

## Challenge Complejo: most_common_byte

Implementar un histograma en el stack para hallar el byte más frecuente.

Requiere manejo de Stack Frame (rbp).

**Errores detectados en el primer intento:**

1. Escribir `mov rsp, rbp` en lugar de `mov rbp, rsp`.
    
2. No reservar espacio con `sub rsp, 0x200`.
    
3. Usar registros de 8 bits en cálculos de direcciones.
    
4. `push` infinito dentro de un bucle.
    
5. No limpiar la memoria del stack (basura).
    

**Solución funcional:**

Fragmento de código

```
.intel_syntax noprefix
.global most_common_byte

most_common_byte:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200          # 512 bytes para 256 contadores de 2 bytes
    xor rcx, rcx

limpiar_loop:
    cmp rcx, 256
    je empezar_conteo
    mov r8, rcx
    neg r8
    mov word ptr [rbp + r8*2 - 2], 0
    inc rcx
    jmp limpiar_loop

empezar_conteo:
    xor rcx, rcx

while_contar:
    cmp rcx, rsi
    jge preparar_busqueda
    xor rax, rax
    mov al, byte ptr [rdi + rcx]
    mov r8, rax
    neg r8
    inc word ptr [rbp + r8*2 - 2]
    inc rcx
    jmp while_contar

preparar_busqueda:
    xor rcx, rcx
    xor rbx, rbx            # max_freq
    xor rax, rax            # max_freq_byte (ganador)

while_buscar_max:
    cmp rcx, 256
    je fin
    xor rdx, rdx
    mov r8, rcx
    neg r8
    mov dx, word ptr [rbp + r8*2 - 2]
    cmp dx, bx
    jle siguiente_byte
    mov bx, dx
    mov rax, rcx

siguiente_byte:
    inc rcx
    jmp while_buscar_max

fin:
    leave
    ret
```

---

```

---

### Seccion de Correcciones y Aclaraciones

Tras analizar tus notas, aquí están los puntos que estaban "un poco mal" o que requieren precisión técnica:

1.  **Lógica del XOR:** En tu descripción de la tabla de verdad de XOR, mencionaste: *"si los 2 son iguales es = 1 y si son diferentes = 0"*. Esto es **incorrecto**. El XOR (O exclusivo) es exactamente al revés: **si son diferentes es 1, y si son iguales es 0**. He corregido la tabla en el bloque de Obsidian para que sea técnicamente exacta.
2.  **Limpieza de la parte alta en divisiones:** Mencionas que se usa `mov rdx, 0` para limpiar la parte alta. Esto es correcto para divisiones **sin signo** (`div`). Sin embargo, para divisiones **con signo** (`idiv`), se suele usar la instrucción `cqo`, que extiende el signo de `rax` hacia `rdx`. Es un detalle importante si llegas a usar `idiv`.
3.  **El "Truco del Negativo" en el Stack:** En el código final de `most_common_byte`, usas `neg r8` y luego `[rbp + r8*2 - 2]`. Esto es una solución creativa para el hecho de que el direccionamiento de Intel no permite una resta directa del tipo `[rbp - rcx*2]`. Es una excelente práctica para gestionar arreglos locales en el stack.
4.  **Preservación de registros en Funciones:** En `str_lower`, recordaste bien que `rdi` y `rax` se pierden al llamar a otra función. Solo como recordatorio: los registros `rbx`, `rbp`, y `r12-r15` son "callee-saved", lo que significa que si tú los usas, debes devolverlos como estaban (usando `push`/`pop`), tal como hiciste con `rbx`.
5.  **Diferencia de acceso de 32 bits:** Mencionaste que los accesos parciales no limpian los bits superiores. Ojo: en x86_64, cuando haces un `mov` a un registro de **32 bits** (como `eax`), el procesador **sí pone a cero automáticamente** los 32 bits superiores de `rax`. Esto es una excepción a la regla de los registros de 8 y 16 bits.

¿Te gustaría que profundicemos en algún otro ejercicio de desreferencia de memoria o que cree una guía de estudio rápida basada en estas notas?
```
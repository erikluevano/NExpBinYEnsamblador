---
tags:
  - x86-assembly
  - memory-addressing
  - registers
  - pointers
  - dereferencing
  - syscalls
  - pwn-college
---

# Módulo 3 - Memoria en Ensamblador x86

¡Vaya, eres un programador de ensamblaje x86 en ciernes! Has establecido registros, activado llamadas al sistema y escrito tu primer programa que sale limpiamente. Ahora tenemos un gran concepto más para ti: **la memoria**.

## Analogía de la Memoria

Tú, como (presumiblemente) ser humano, tienes memoria a corto plazo y memoria a largo plazo. Al realizar cálculos específicos, tu cerebro carga información que has aprendido previamente en tu memoria a corto plazo, luego actúa sobre esa información y, finalmente, coloca nueva información resultante en tu memoria a largo plazo. Societalmente, también inventamos otras formas de almacenamiento a más largo plazo: historias orales, revistas, libros y Wikipedia. Si no hay suficiente espacio en tu memoria a largo plazo para alguna información, o la información no es importante para memorizarla a largo plazo, siempre puedes buscarla en Wikipedia, hacer que tu cerebro la introduzca en tu memoria a largo plazo y extraerla de tu memoria a corto plazo cuando la necesites más adelante.

### Jerarquía de Memoria

Esta jerarquía multinivel de acceso a la información desde "pequeña pero accesible" (tu memoria a corto plazo, que está ahí cuando la necesitas pero solo almacena de 5 a 9 piezas de información) hasta "grande pero lenta" (recordar cosas de tu enorme memoria a largo plazo) a "masiva pero absolutamente glacial" (buscando cosas en Wikipedia) es en realidad la base de la jerarquía de memoria de la informática moderna. Ya aprendimos sobre la parte "pequeña pero accesible" de esto en el módulo anterior: son **registros**, limitados pero **RÁPIDOS**.

Más espaciosa incluso que todos los registros juntos, pero mucho MUCHO más lenta de acceder, es la **memoria de la computadora**, y esto es lo que profundizaremos con este módulo, brindándote una idea de otro nivel de la jerarquía de memoria.

## Cargando desde Memoria

Básicamente nos explicaron cómo sacar un valor de dirección de memoria en el código ensamblador:
```
  Address │ Contents
+────────────────────+
│ 133700  │ ???      │
+────────────────────+
```

De esta manera se sacaría en el código de salida el valor de la memoria en la dirección: `133700`
```asm
.intel_syntax noprefix
.global _start
_start:

mov rdi, [133700]
mov rax, 60
syscall
```

Hacemos los famosos pasos:
```bash
as -o adres.o adres.s
ld -o adres adres.o
/challenge/check adres
```

Y listo:
```bash
hacker@memory~loading-from-memory:~/Desktop$ /challenge/check adres

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 133700 (value 66) to succeed!

hacker@memory~loading-from-memory:/home/hacker/Desktop$ /tmp/your-program
hacker@memory~loading-from-memory:/home/hacker/Desktop$ echo $?
66
hacker@memory~loading-from-memory:/home/hacker/Desktop$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{sSmaeQRVqLEywov3AfTtg1e26jz.QX0ITO1wSM1ETM0EzW}
```

## Dereferencing the Pointer (Desreferenciación de Punteros)

Es cuando en lugar de pasarle a `rdi`, por ejemplo, la dirección de memoria tal cual `[n...]`, le pasamos el valor de la dirección, luego lo cargamos como puntero de memoria. Ese valor del puntero apunta a otro puntero.
```asm
mov rax, 33700
mov rdi, [rax]
```

Estamos desreferenciando a `rax` para que argumente los datos a la dirección que apunta el valor que contiene. En este caso, el valor de la dirección donde se almacena nuestro valor secreto está en `rax` y así lo resolvemos:
```asm
.intel_syntax noprefix
.global _start
_start:

mov rdi, [rax]
mov rax, 60
syscall
```

**Flag obtenida:**
```
pwn.college{8LMqcJycOAS6MFxGdg9nu6zRgfc.QXxMTO1wSM1ETM0EzW}
```

## Acceso a Múltiples Valores (Offset de Memoria)

Después de ese reto nos mencionan que no siempre es un solo valor o queremos ir al valor primero que apunta una dirección en memoria, sino que a veces apuntan a un libro de valores. Puede ser al inicio, por ejemplo `rdi` que tenga el valor `1337`, pero ese valor apunta a un `47` que es el inicio de un libro de valores. Para acceder a los demás, podemos simplemente añadir con `+`. Por ejemplo, para el quinto valor de ese libro:
```asm
mov rdi, [rdi+4]
```

Así le otorgamos el valor quinto de ese libro a `rdi`.

### Reto
```
    Address │ Contents
  +────────────────────+
┌▸│ 31337   │ 0        │
│ │ 31337+1 │ 0        │
│ │ 31337+2 │ 0        │
│ │ 31337+3 │ 0        │
│ │ 31337+4 │ 0        │
│ │ 31337+5 │ 0        │
│ │ 31337+6 │ 0        │
│ │ 31337+7 │ 0        │
│ │ 31337+8 │ ???      │
│ +────────────────────+
│
└────────────────────────┐
                         │
   Register │ Contents   │
  +────────────────────+ │
  │ rdi     │ 31337    │─┘
  +────────────────────+
```

**Solución:**
```asm
.intel_syntax noprefix
.globl _start
_start:

mov rdi, [rdi+8]
mov rax, 60
syscall
```

**Flag obtenida:**
```
pwn.college{A7tVKaRfZVgoi0nCmjOVZLPWnms.QX1QTO1wSM1ETM0EzW}
```

## Desreferenciación Simple

Después, otro reto era obtener el valor de una dirección de memoria, luego meterle a `rdi` lo que tenía guardado. Eso que estaba guardado en esa dirección de memoria para `rdi` y ese sería nuestro código de error para salir del programa.

## Desreferenciación Doble (Encapsulación)

El siguiente desafío fue una como encapsulación. Simplemente debíamos otorgarle a `rdi` el valor de la dirección almacenada en `rax` y después a ese valor volver a desreferenciarlo, ya que era otra dirección que contenía ahora sí el valor del código de error:
```asm
.intel_syntax noprefix
.global _start
_start:

mov rdi, [rax]
mov rdi, [rdi]
mov rax, 60
syscall
```

## Desreferenciación Triple

El siguiente fue lo mismo pero con una triple, que fue desreferenciar otra vez y ya:
```asm
.intel_syntax noprefix
.global _start
_start:

mov rdi, [rdi]
mov rdi, [rdi]
mov rdi, [rdi]
mov rax, 60
syscall
```

---

**Eso fue todo por este módulo.**
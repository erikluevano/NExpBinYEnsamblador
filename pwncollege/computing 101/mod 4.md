---
tags:
  - #syscall
  - #write
  - #read
  - #exit
  - #rdi
  - #rsi
  - #rdx
  - #rax
  - #assembly
  - #intel_syntax
---
---
tags:
  - #syscall
  - #write
  - #read
  - #exit
  - #rdi
  - #rsi
  - #rdx
  - #rax
  - #assembly
  - #intel_syntax
---

# Módulo 4

Aquí nos enseñan de la función write la cual se invoca con el 1 en syscall la cual tiene 3 parámetros el estándar normal y de error el normal es 1 y el de error es 2, luego la dirección de memoria a manipular que es el parámetro 2 luego los caracteres a escribir:
```
write(1, 534627, 10)
```

La manera de invocarla por ejemplo con salida output regular en la dirección 66666666 y con 1 solo carácter de escritura es:

Con los registros de rdi y sus subregistros como hemos visto en otros lados:
el primero es rdi:1 luego el 2 rsi:2 luego el 3 rdx:3

De esta forma:
```assembly
mov rdi, 1
mov rsi, 66666666
mov rdx, 1
mov rax, 1
syscall
```

Y listo write sería llamado con nuestros parámetros.

El reto fue de eso y el segundo fue de meterle el exit además de eso que simplemente fue meterle el valor 60 a rax después del syscall de write meterle el código de error que nos pedían de salida en rdi luego el syscall.

Luego nos enseñan de la función read que tiene los mismos parámetros solo que la que lo llama es el número 0 y ese el primer parámetro que se le debe pasar también el 0 luego la dirección de memoria a manipular luego los bytes exactos esta vez que leeremos, van en los mismo registros los parámetros.

Nos piden que leamos de una dirección 8 bytes luego que los escribamos esos mismos 8 bytes y salgamos con código de estado 42, primero escribí este código:
```assembly
.intel_syntax noprefix
.global _start
_start:
mov rdi, 0
mov rsi, 1337000
mov rdx, 8
mov rax, 0
syscall
mov rdi, 1
mov rax, 1
syscall
mov rdi, 42
mov rax, 60
syscall
```

Pero el programa pedía más instrucciones en el de arriba quise ahorrar pero realmente no sé si está del todo bien:
```assembly
.intel_syntax noprefix
.global _start
_start:
mov rdi, 0
mov rsi, 1337000
mov rdx, 8
mov rax, 0
syscall
mov rdi, 1
mov rsi, 1337000 
mov rdx, 8
mov rax, 1
syscall
mov rdi, 42
mov rax, 60
syscall
```

El primero lo escribí asumiendo que rdx y rsi no serían cambiados pues noté que se usan los mismo valores, entonces aquí dependemos que read que es lo primero que se invoca no los altere que en principio no lo hace y los 2 jalan igual pero no es la manera correcta de hacerlo pues siempre debemos especificar y documentar y preservar lo que tenemos en nuestros registros sin dependencias que no controlemos.

Y este es el fin del módulo.

---

## Correcciones y Aclaraciones

### 1. Syscall write - Número de llamada
La función `write` se invoca con `rax = 1` (no con el valor 1 en syscall directamente). El número 1 en `rax` es lo que identifica la syscall de write.

### 2. Parámetros de write
- **rdi**: File descriptor (1 = stdout, 2 = stderr)
- **rsi**: Dirección del buffer (puntero a los datos)
- **rdx**: Número de bytes a escribir

### 3. Función read
La función `read` se invoca con `rax = 0`:
- **rdi**: File descriptor (0 = stdin)
- **rsi**: Dirección del buffer donde guardar lo leído
- **rdx**: Número máximo de bytes a leer

### 4. Problema con el primer código
En el primer ejemplo hay un error crítico: después del `syscall` de read, se modifica `rdi` a 1 para write, pero **NO se restablecen `rsi` y `rdx`**. Aunque funcionó, esto depende de que read no modifique estos registros, lo cual es una mala práctica porque:

- **rax** es modificado por syscall (devuelve el número de bytes leídos/escritos)
- Otros registros podrían ser alterados dependiendo de la implementación del kernel
- No es un código robusto ni predecible

### 5. Buena práctica
El segundo código es el correcto porque:
- Especifica explícitamente todos los parámetros antes de cada syscall
- No depende de valores residuales en los registros
- Es más legible y mantenible
- Sigue el principio de no asumir estado de registros entre syscalls

### 6. Exit syscall
La syscall `exit` (número 60) requiere:
- **rax**: 60 (número de syscall)
- **rdi**: Código de salida (exit code)

El código 42 que se usa es simplemente el valor de retorno que el programa dará al sistema operativo.
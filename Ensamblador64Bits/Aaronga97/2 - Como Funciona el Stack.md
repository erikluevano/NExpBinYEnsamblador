---
tags:
  - #assembly
  - #stack
  - #LIFO
  - #push
  - #pop
  - #rsp
  - #rbp
  - #rip
  - #stack-overflow
  - #función-recursiva
  - #registros
created: 2025-10-22
---

# Stack en Assembly

## Concepto LIFO

El stack es **LIFO: Last In First Out**. El último que entra es el primero que sale, lo contrario a FIFO en una fila: el primero que entra es el primero que sale.

## Funciones Principales del Stack

### Push - Agregar al Stack

**Sintaxis:** `push src`  
**Operación:** `stack[--rsp] = src`

`push` tiene un argumento (`src`). Lo que en realidad hace es que se va al stack y le resta 1 unidad primero al stack pointer `rsp`, y después de esa resta almacena el argumento `src` que le enviamos. Es decir, simplemente empuja un valor nuevo al stack.

#### Representación:
```assembly
mov rax, 42  ; mueve el valor 42 al registro rax
push rax     ; mete el registro rax al stack
```
```
0
1
2
3
4    42 <- rsp <- el registro rsp apunta al valor más nuevo del stack (el tope)
```

Se puede ver que el stack **crece para abajo** como decía mi buen Elías. Es decir, para agregar un valor primero le restamos al stack pointer `rsp` y luego agregamos el valor. Entonces, si metemos otro valor le restamos otra unidad a `rsp` y se metería, esta vez en la posición 3 en este caso:
```assembly
mov rax, 69
push rax
```
```
0
1
2
3    69 <- rsp
4    42
```
```assembly
push rax
```
```
0
1
2    69 <- rsp
3    69
4    42
```

### Pop - Sacar del Stack

**Sintaxis:** `pop dst`  
**Operación:** `dst = stack[rsp++]`

Ahora, si no queremos que se nos llene nuestro stack, aquí está otra función principal del stack.

`pop` lo que hace es que recibe un argumento (`dst`), saca lo que está hasta arriba del stack, es decir saca lo que está apuntando el `rsp` stack pointer en este momento, luego lo que sacamos lo almacenamos en la variable de destino (`dst`).

Entonces sería: destino es igual al stack en la posición actual del `rsp` stack pointer y, una vez que se realizó la asignación, incrementamos el stack pointer `rsp++`. O sea, sacamos el último elemento (recordar que crece para abajo).

#### Ejemplo con pop:
```assembly
pop rbp  ; (base pointer)
```
```
rbp = 69

0
1
2    69
3    69 <- rsp
4    42
```
```assembly
pop rbp  ; (base pointer)
```
```
rbp = 69

0
1
2    69
3    69
4    42 <- rsp
```
```assembly
pop rbp  ; (base pointer)
```
```
rbp = 42

0
1
2    69
3    69
4    42
     <- rsp <- stack vacío
```

Sabemos que los números siguen allí, pero como el stack se controla a través del `rsp` stack pointer, si está este hasta abajo significa que el stack está vacío, aunque los valores sigan allí.

## Stack Overflow

### Llenando el stack:
```assembly
mov rax, 42; push rax
mov rax, 69; push rax
mov rax, 420; push rax
mov rax, 999; push rax
mov rax, 0xdead; push rax
```
```
     0xdead  <- rsp
0    999
1    420
2    69
3    69
4    42
```

Si nos pasamos pasa un **stack overflow**. Y dirás: ¿quién llenaría esto adrede? Aparte de gente como yo xd, se puede llenar sin intención de hacerlo, como con una función recursiva sin caso base fijo. Las llamadas a funciones generan que se tenga que guardar cada vez su base pointer `rbp` y la creación de las variables locales, entonces, muerte.

## Ejemplo de Ejecución: Llamada a Función

Veamos esto en ejecución con el siguiente código y su comportamiento en el stack con los 3 apuntadores paso a paso:

### Paso 1
```c
0 int square(int num) {
1     return num * num;
2 }
3
4 int main() {        <- instrucción pointer rip
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4
5
6
7
-    ???  <- stack pointer rsp <- base pointer rbp
```

### Paso 2
```c
0 int square(int num) {
1     return num * num;
2 }
3
4 int main() {
5     square(10);  <- rip
6     return 0;
7 }
```
```
0
1
2
3
4
5
6
7    &4   <- rsp
-    ???      <- rbp
```

El stack recoge el valor que tomó el `rip` línea 4 de inicio `main`. `rsp` apunta a él.

### Paso 3
```c
0 int square(int num) {
1     return num * num;
2 }
3
4 int main() {
5     square(10);  <- rip
6     return 0;
7 }
```
```
0
1
2
3
4
5
6
7    &4   <- rsp <- rbp
-    ???
```

`rbp` se une al inicio de función `main` con `rsp`. El `rbp` se quedará allí porque referencia al inicio de `main`. Tenemos la llamada a `square(10)`.

### Paso 4
```c
0 int square(int num) {
1     return num * num;
2 }
3
4 int main() {
5     square(10);  <- rip
6     return 0;
7 }
```
```
0
1
2
3
4
5
6    &5   <- rsp
7    &4       <- rbp
-    ???
```

Se mete el instrucción pointer porque eso se va a utilizar para restaurar la ejecución cuando terminemos de ejecutar `sqrt()` &5 (línea 5 del código).

### Paso 5
```c
0 int square(int num) {  <- rip
1     return num * num;
2 }
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4
5
6    &5   <- rsp
7    &4       <- rbp
-    ???
```

Se va el rip al comienzo de square()
### Paso 6
```c
0 int square(int num) {
1     return num * num;  <- rip
2 }
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4
5    &7   <- rsp
6    &5
7    &4       <- rbp
-    ???
```

Se mete el valor del registro base pointer `rbp` al stack (dirección del stack [7]), para cuando terminemos la ejecución de la función `sqrt`. Al final podamos restaurar la posición del `rbp` para cuando lleguemos a la ejecución de la función de `main` antes de entrar a `sqrt`.

### Paso 6 (continuación)
```c
0 int square(int num) {
1     return num * num;  <- rip
2 }
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4
5    &7   <- rsp <- rbp
6    &5
7    &4
-    ???
```

Nos llevamos el base pointer `rbp` al mismo apuntador que el stack pointer `rsp`, porque es lo que usaremos como referencia para las variables locales de esa función.

### Paso 7
```c
0 int square(int num) {
1     return num * num;  <- rip
2 }
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4    &10  <- rsp
5    &7       <- rbp
6    &5
7    &4
-    ???
```

Metemos el valor 10 al stack subiendo el stack pointer `rsp` como la primer variable local.

### Paso 8
```c
0 int square(int num) {
1     return num * num;
2 }            <- rip
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4    &10
5    &7   <- rsp <- rbp
6    &5
7    &4
-    ???
```

Después de ejecutar lo que estaba haciendo `rip` instrucción pointer, se baja el stack pointer `rsp`. Aunque no se ve reflejado lo que se hizo en el stack debido a que esa operación 10×10, el resultado se guarda en el registro `rax` y ese no lo estamos viendo. Pero bueno, se baja el `rsp` al nivel `rbp` porque al entrar en una función recordemos que `rbp` base pointer no se mueve, ya que se encarga de almacenar la referencia para todas las variables locales dentro de la función.

Entonces ahora lo que toca hacer es un `pop rbp`. Entonces la dirección 7 que recordemos es del stack se almacenará en el base pointer `rbp`, lo que hará que se vaya hasta abajo pop rbp = mov rbp rsp && rsp +1.

### Paso 8 (continuación)
```c
0 int square(int num) {
1     return num * num;
2 }            <- rip
3
4 int main() {
5     square(10);
6     return 0;
7 }
```
```
0
1
2
3
4    &10
5    &7
6    &5   <- rsp
7    &4       <- rbp
-    ???
```

Tras esto el stack pointer `rsp` se suma una unidad, entonces se va de la posición 5 a la 6 bajando en el stack. Y como dijimos antes, al hacer un `pop rbp` recordar que pop saca a lo que apunta `rsp` y guarda el valor en el argumento. Entonces a `rbp` se le guardó la dirección de la posición 7 del stack, por eso regresó.

### Paso 9
```c
0 int square(int num) {
1     return num * num;
2 }
3
4 int main() {
5     square(10);  <- rip
6     return 0;
7 }
```
```
0
1
2
3
4    &10
5    &7
6    &5   rsp bajo por el pop
7    &4   <- rsp <- rbp
-    ???
```

Ahora lo que se hace al hacer el `return` es que se hace un `pop` al instrucción pointer. Es decir, el `rip` tendrá el valor de la dirección 5 (código) del stack porque es a lo que apunta el `rsp` ahora. El stack pointer `rsp` se va para abajo visualmente en el stack, porque en dígitos estamos sumando por el crecimiento para abajo.

Y así seguiría la ejecución del programa.

---

## Referencias

- Stack pointer (`rsp`)
- Base pointer (`rbp`)
- Instruction pointer (`rip`)
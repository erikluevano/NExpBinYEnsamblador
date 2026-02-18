# Clase 1 - Sintaxis Básica C

#C #sintaxis-C #typedef #struct #punteros #memoria

El curso de Elías comienza con un repaso a la sintaxis de C. En general es muy similar a Java.

## Tipos de datos básicos

En C no existe el String ni el Booleano. Aquí la forma en que se declaran en general todas:
```c
int main() {
    int var1 = 40;
    char var2[] = "ola";
    int var3 = 1;
    char var4 = 'c';
}
```

Podemos ver que el equivalente al string es un arreglo de char (un arreglo de caracteres) y el booleano se representa con un número. Si es 0 es falso, si es algo diferente a 0 es true.

## Ciclos

Para los ciclos también es muy similar a Java, son de esta forma:
```c
#include "stdio.h"
int main() {
    for (int i = 0; i < 30; i++){
        puts("ola");
    }
}
```

Y para while es:
```c
#include "stdio.h"
int main() {
    while (2) {
    }
}
```

## Funciones

La manera de hacer una función en C es igualmente casi como en Java:
```c
#include "stdio.h"
int sumar (int num1, int num2) {
    return num1 + num2;
}
int main() {
    int resultado = sumar(1, 2);   
    printf("%d\n", resultado); // En esta forma de imprimir, el "%d" indica que se imprimirá un número y lo pasamos ",->x"
}
```

Hay muchas cosas que podríamos pasar y formatos, por ejemplo 2 enteros y un string que al parecer sí existe de otra forma en C.

Por ejemplo, si queremos imprimir 2 decimales y un string:
```c
printf("%d %d, %s", resultado, resultado, "ola");
```

## Condicionales

Para la condición if, si solo tendrá dentro 1 línea no es necesario los llaves:
```c
#include "stdio.h"
int main() {
    if (resultado > 30)
        puts("Es mayor que 30 jijijija")
    else
        puts("naoooo menor, menor a 30 mi hermano")
}
```

## Estructuras (struct)

En C no existen las Clases, lo más similar es "struct" que funciona con esta sintaxis:
```c
#include "stdio.h"
struct Persona {
    char nombre[30];
    int edad;
    float altura;
}
int main() {
    struct Persona p = {
        .nombre = "Erik",
        .edad = 20,
        .altura = 1.75
    };    
}
```

Como tal, struct no es exactamente como una clase pues dentro de struct no es posible poner métodos. En cambio, se usan funciones:
```c
#include "stdio.h"
void saludar(struct Persona p){
    printf("Hola, mi nombre es: %s\n", p.nombre)
}
int main() {
    struct Persona p = {
        .nombre = "ErikAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .edad = 20,
        .altura = 1.75
    }; 
    saludar(p);   
}
```

## typedef

Como estar escribiendo struct Persona es largo, existe algo llamado typedef que es que a un tipo se le asigna un alias. Por ejemplo:
```c
#include "stdio.h"
typedef struct Persona { // Pasamos el tipo del que va a ser struct Persona
    char nombre[30];
    int edad;
    float altura;
} Persona; // Le pasamos como se llamará para no tener que poner struct

void saludar(Persona p){
    printf("Hola, mi nombre es: %s\n", p.nombre)
}
```

Y listo, ahorramos unos teclazos porque no.

## Punteros (pointers)

Ahora, para que no nos limite esto de `char nombre[30];` tener que especificar siempre, podemos hacer uso de algo llamado pointer:
```c
char *nombre;
```

Esto indica que este campo va a estar apuntando a caracteres.

Es decir, ese asterisco señala que ese campo va a ser una dirección de memoria que estará apuntando a un carácter, lo cual funciona para strings. Para imprimir un campo de ese string que se pasó sería:
```c
printf("%c\n", p.nombre[3]);
```

Entonces con esto ahora sabemos que los arreglos son exactamente iguales a un pointer. El pointer sirve para apuntar a memoria.

Ahora, una forma diferente de hacerlo con apuntador es sumando e indicando que lo que queremos ver es lo de adentro, a lo que apunta el apuntador:
```c
printf("%c\n", *(p.nombre+3));
```

El `*` indica que queremos ver el interior a lo que apunta. Apunta en un inicio a 'E' pero con +3 apuntamos a 'k'.
# Metodología de Análisis de Binarios (Enfoque Gato)

#reverse-engineering #binary-exploitation #IDA #pwntools #gdb #buffer-overflow #format-string

## Fase 1: Análisis Inicial del Binario

De primera mano analizamos el binario al ejecutarlo. Vemos qué nos pide o qué ocupa para funcionar. Por ejemplo, si ejecutamos `./programa` y nos dice `Usage: ./programa <archivo>`, ya sabemos que necesita un archivo como argumento. A raíz de eso, evaluamos las siguientes opciones: crear el archivo que solicita, explorar todo lo que se puede hacer con el programa (probando diferentes inputs como `AAAA`, `%x %x`, números largos), o verificar si la entrada nos puede dar una idea de vulnerabilidades como format string o buffer overflow.

## Fase 2: Descompilación y Análisis Estático

Luego de la ejecución inicial, podemos decompilar con IDA para ver mejor todo el funcionamiento del binario. Aspectos clave: renombramiento de variables (tener esto siempre en mente - cambiar `var_10` por algo como `password_buffer`), investigar sobre las funciones utilizadas que no conozcamos su funcionamiento (por ejemplo, si vemos `strncmp`, buscar qué hace exactamente), nos enfocamos en `main` obviamente, y de ahí vemos si hay condiciones para leer una flag o algo similar. Checamos las variables, todas las condiciones.

Emparejamos el código pseudocódigo con el ensamblador. Es una muy buena manera de ubicarse y comprender el flujo del programa. Por ejemplo, si en pseudocódigo vemos `if (input == 0x1337)` buscamos en el ensamblador el `cmp` correspondiente.

## Fase 3: Desarrollo del Exploit

Luego, si vemos que tenemos más o menos una idea de lo que hace, podemos hacer un exploit en Python con pwntools. **Regla de oro:** Debuggear siempre. Estas son las 3 maneras:

**Debuggeando con un breakpoint:**
```python
# Debuggeando con un breakpoint en: 0x80d926f
shell = gdb.debug("../imperial_archive", "b *0x80d926f\ncontinue")
```

**Correr normal local:**
```python
shell = process("../imperial_archive")
```

**Correr ya remoto cuando tenemos la solución:**
```python
shell = remote("play.h7tex.com", 34221)
```

## Estrategia de Explotación

Es recomendable hacer el exploit con funciones que logramos crear en base a lo que nos permite hacer el binario y lo que vimos en el IDA al decompilar. Por ejemplo:
```python
def send_username(payload):
    shell.recvuntil(b"Username: ")
    shell.sendline(payload)

def send_password(payload):
    shell.recvuntil(b"Password: ")
    shell.sendline(payload)
```

Esto para enviar en cada sección algún payload, o solo en las que vimos o detectamos una vulnerabilidad. Debemos debuggear de manera muy buena y ver todas las entradas que nos da el binario, ya que puede que haya un buffer en alguna (por ejemplo, un `gets()` sin límite) y podamos sobreescribir alguna dirección (como el return address con `b"A"*72 + p32(direccion_win)`) o algo más.

---

**Nota:** Estas notas continuarán cuando se me ocurra algo más...
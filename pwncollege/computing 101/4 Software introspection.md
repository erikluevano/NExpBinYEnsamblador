
# Trazado de Syscalls con strace

En este módulo comenzamos con strace:
```bash
strace /challenge/trace-me 
execve("/challenge/trace-me", ["/challenge/trace-me"], 0x7ffe5b3a2e10 /* 15 vars */) = 0
alarm(10165)                            = 0
exit(0)                                 = ?
+++ exited with 0 +++
```
```bash
hacker@introspecting~tracing-syscalls:~$ /challenge/submit-number 10165
CORRECT! Here is your flag:
pwn.college{g8oDLf_UyzrXhNm4zY19QsHnDgo.QXxcDO1wSM1ETM0EzW}
```

`strace` es una herramienta que busca las llamadas de sistema que hace un binario, sirve para debuggear, ve las llamadas y los argumentos que se le pasan.

En este caso realizó 3 llamadas: `execve`, `alarm`, `exit`, cada una con sus argumentos.

## Introducción a gdb

Después de eso una muy leve introducción a gdb. De gdb ya sé algunas cositas pero no tantas, en general ya sé cómo usarlo con el plugin de pwndebug y el de GEF.

Solo que aquí mencionaron la instrucción `starti` que es la que se encarga de ejecutar la primera instrucción del programa, es decir, iniciarlo.


Software Introspection - adicional

p de print en fgdb p $rdi

x simplemente printeara en hexadecimal

lo que hizimos en un nivel anterior doble dereferencia para mostrar el valor de los texto de los argumentos con los que el binario fue invocado, simplemente ha y que hacer:

x/a $rsp+16

+16 ya que +8 nos dariael nombre del binario y /a ya que a es pa que nos de el adress de lo que hay alli

luegio

x/s \<lo que dio\> /s es porque queremos ver un string que en este caso es la flag 
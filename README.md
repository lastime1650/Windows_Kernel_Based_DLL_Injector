# Windows_Kernel_Based_DLL_Injector
This is a DLL Injector with a kernel driver that runs on a Windows operating system.<br>
## The code is close to PoC.

<br>
<br>

# How it works? 
![initial](https://github.com/lastime1650/Windows_Kernel_Based_DLL_Injector/blob/main/images/image.png)

1. Get Eprocess
2. Get PEB struct by Eprocess
3. Get Dll Base
4. Get API Address by Dll Base ( Dll pe parsing )
5. DLL PATH ( kernel valid address ) copy to Target Process ( user valid address )
6. call to RtlCreateUserThread()
7. BOOM!

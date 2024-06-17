#Shellcode method<br>
Input process name, e.g notepad.exe
xor eax, eax clears the EAX register, setting it to 0. <br>
mov edx, eax sets EDX to 0. <br>
mov dword ptr [eax], 1 tries to write the value 1 to memory address 0x00000000, which causes an access violation and crashes the program. <br>

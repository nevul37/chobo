from pwn import *

p = process('./calc')

pause()

''' 360 to ret
+a-b
 => value[a+1] to b
 

'''

p.interactive()

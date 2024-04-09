import pyMeow as pm
from keystone import *
import keyboard

proc = pm.open_process("hl2.exe")

class Modules:
    server = pm.get_module(proc,"server.dll")["base"]

class Pointers:
    ply = Modules.server+0x4F615C

class Offsets:
    health = 0xE4

def write_nops(start,size):
    pm.w_bytes(proc,start,bytes([0x90]*size))


ks = Ks(KS_ARCH_X86, KS_MODE_32)
aob = "89 3E 5F B8 01 00 00 00 5E 8B"
ply_healthadr = pm.r_uint(proc,Pointers.ply)+Offsets.health
start_adr = pm.aob_scan_module(proc,"server.dll",aob)[0]
end_dist = 8
original_inst = pm.r_bytes(proc,start_adr,end_dist)

write_nops(start_adr,end_dist)


new_code = f"""
newmem:
    cmp esi,{hex(ply_healthadr)}  
    je playercase
    jmp enemycase
enemycase:
    mov dword ptr [esi],0 
    pop edi
    mov eax,0x1
    jmp return
playercase: 
    pop edi
    mov eax,0x1
    jmp return
return:
    push {hex(start_adr+end_dist)}
    ret
"""
encoding, count = ks.asm(new_code)
new_mem = pm.allocate_memory(proc,count)
pm.w_bytes(proc,new_mem,encoding)

jump_to_newmem = f"""
push {new_mem}
ret
"""
encoding, count = ks.asm(jump_to_newmem)
pm.w_bytes(proc, start_adr, encoding)


while not keyboard.is_pressed("k"):
    pass

pm.w_bytes(proc,start_adr,original_inst)





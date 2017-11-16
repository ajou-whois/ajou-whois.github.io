---
layout: post
title: "PCTF 2016 - Butterfly"
date: 2017-11-16 +0126
categories: [ctf, pwn]
tags: [ctf, pwn, exploit]
---
## I. 개요
 사실 얼마전부터 후이즈 블로그를 개설하게 되면서, 문제를 하나씩 풀어보면서 마크다운, 깃허브io 사용법을 익힐겸, 라이트업을 작성하기로 결정했다.
 그에 대한 첫 번째 라이트업은 바로 Plaid CTF 2016의 Butterfly라는 문제!!
 일단 문제 자체가 어렵거나 그런건 아니지만, 참신하게 접근할 수 있어서 작성해본다.

## II. 바이너리 분석 
  바이너리는 크게 어려운 것은 없다, 일단 다음 코드를 살펴보도록 하자.
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

  어렵다기보다는 그냥 왜이렇게 코드가 짧음? 이라는 소리가 먼저나오는 코드이다.
  일단, 프로그램의 흐름은 입력값을 fgets로 받고(그렇기 때문에 NULL바이트도 넣을 수 있다. 기억해둘 것) 이 값을 strtol()함수로 문자열을 정수로 바꾸는데, 이 함수는 뒤에 아무리 많은 문자열이 존재하더라도 숫자형태의 문자들만 정수형으로 치환해주기 때문에 뒤에는 값이 더들어갈 수 있다.
  그리고 그렇게 바뀐 주소는 마지막 3비트가 Right Shift되고, 그 결과값을 기준으로 rwx(0x7) 권한으로 mprotect로 권한이 제어된다.
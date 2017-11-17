---
layout: post
title: "PCTF 2016 - fixedpoint"
date: 2017-11-17 +1143
categories: [ctf, pwn]
tags: [ctf, pwn, exploit]
---

## I. 바이너리 분석
  이번에도 재미있는 CTF문제를 하나 들고왔다. 사실 이번 문제는 그렇게 공격이 어려운 문제는 아니었는데, 쉽게 Floating 데이터가 어떻게 관리가 되는지, 그리고 ShellCode를 만들줄 아는지에 대한 문제였다.<br />
  일단, Hex-Ray로 디컴파일을 한 결과는 다음과 같다.<br />
  <br />
  ```C
  int __cdecl main(int argc, const char **argv, const char **envp)
  {
  signed int v4; // [sp+24h] [bp-Ch]@2
  signed int i; // [sp+28h] [bp-8h]@1
  int (*v6)(void); // [sp+2Ch] [bp-4h]@1

  v6 = (int (*)(void))mmap(0, 0x8000u, 7, 34, -1, 0);
  for ( i = 0; i <= 0x1FFF && __isoc99_scanf((const char *)&unk_80485F0, &v4); ++i )
    *((float *)v6 + i) = (long double)v4 / 1337.0;
  write(1, "here we go\n", 0xBu);
  return v6();
  }
  ```
  소스코드가 매우 짧다.<br />
  미리 이야기를 하지만 포너블이나 익스플로잇 관련된 기술에 접근할 때는, 해당 프로그램 또는 소스코드가 무슨 역할을 하는 녀석인지 확실하게 알고 진행해야한다.<br />
  이 코드는 mmap으로 0x8000만큼의 사이즈를 가지는 메모리 영역을 rwx 모든 권한을 할당한 채로 새로 매핑한다는 뜻이다.<br />
  그렇게 새로 매핑된 주소는 v6라는 변수 안에 들어간다. 이 v6 변수는 함수 포인터로 사용이 되는데, 우리가 입력한 정수 값이 1337.0과 나눠진 결과를 float 데이터로 4바이트씩 저장한다.<br />
  그리고 마지막에 해당 주소를 call함으로써 우리가 생성한 쉘코드를 실행한다.<br />
  <br />
  비슷한 문제가 사실 DEFCON CTF 2017 예선때도 하나 나왔었는데, 그 당시에는 나는 파이썬에서 그런게 가능한줄도 모르고 직접 손으로 계산해서 쉘코드를 만들었었다.<br />
  일단, 우리는 대학 컴퓨터 프로그래밍 시간에도 배웠겠지만 floating pointer는 지수영역과 가수영역이 따로 나뉘어져 연산되고 관리된다는 것을 알고 있다.<br /><br />
  <img src="http://www.c-jump.com/bcc/common/Talk2/Cxx/IEEE_754_fp_standard/const_images/ieee.gif" />
  <br />
  <br />
  그렇기 때문에 사실상 직접 계산해서 쉘코드를 만드는 것은 많이 복잡한편이다.
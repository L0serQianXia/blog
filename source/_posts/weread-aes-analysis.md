---
title: 微信读书本地文件加密分析
typora-root-url: weread-aes-analysis
date: 2025-08-18 17:35:41
tags:
- re
- reverse
- weread
- aes
categories: Reverse
---

# 微信读书本地文件加密分析

## 前言

仅供交流学习

## 加密分析

拿一台已经root了的机子找到`/data/user/0/com.tencent.weread/databases/<用户ID>/books/`下，这里存在已经下载到本地的书籍

下面存在几个目录，目录的名字一般都是数字，目录下有许多文件后缀为`.res`或`.st`或`.ts.a`的文件

`.res`后缀的文件以压缩文件打开提示需要密码

jadx中查找这个后缀名，可以找到`getDownloadPath`方法， 寻找引用观察到一个`getCanonicalPath`方法，继续查找引用可以发现一个来自`readDataFormDisk`的调用

![image-20250818174101224](image-20250818174101224.png)

该方法中校验了文件的魔数，这个就是读取文件的方法

继续寻找引用，发现`covertChapterToHtml`方法，

![image-20250818174205417](image-20250818174205417.png)

看到下面的unzip方法，可知这里是解压缩的地方

定位到该方法的`unzipResponse`调用中

![image-20250818174258539](image-20250818174258539.png)

看到解压密码是传入的第二个参数，也就是`dataFormDisk`中

![image-20250818174339313](image-20250818174339313.png)可以看到这个`byteArray`从文件中读取，又进行了`EncryptUtils`中的处理

`EncryptUtils`中的方法如下：

![image-20250818184704637](image-20250818184704637.png)

这里提供了两个参数，用户ID和加密后的内容，而后调用了`nativeDecryptHeaderKey`，是native方法，到IDA中查看对应的so文件

关键逻辑如下：

![image-20250818184957191](image-20250818184957191.png)

以上是将vid补全到32位，接下来，根据程序内置的表映射了vid的每一位

![image-20250818185021588](image-20250818185021588.png)

![image-20250818185117052](image-20250818185117052.png)

这里实际上传入的是byte，识别为指针是ida的识别错误，对应表如下：

![image-20250818185139229](image-20250818185139229.png)

下面的解密调用：

![image-20250818185227502](image-20250818185227502.png)

注意到这里没有传入IV，观察解密函数

![image-20250818185708587](image-20250818185708587.png)

下面调用了`openssl`的AES解密函数，根据公开的函数定义，倒数第二个参数是iv

这里IDA将key的定义类型识别为了`unsigned __int8 *`，所以iv被反编译为`key+1`，实际上指向的是后16字节。而前16字节在`AES_set_decrypt_key`中被作为key使用

## 手工解密

回顾`readDataFormDisk`方法

![image-20250818174101224](image-20250818174101224.png)

第一次读取4字节魔数，然后再读取4字节作为循环次数，然后依据循环次数读取多个4字节，在这之后读取了4字节作为`readByteArray`的参数，这也是加密后的密码。

根据so中的解密逻辑，写出映射脚本：

![image-20250818192214322](image-20250818192214322.png)

随后我们输出，便得到了key和iv，前16字节为key，后16字节为iv

![image-20250818192257892](image-20250818192257892.png)

CyberChef中AES解密一下即可得到解压密码

（完）

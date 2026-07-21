---
title: 某VapeLiteV3.4.2破解版的账户窃取分析
typora-root-url: vapelite-342-cracked-backdoor-analysis
date: 2026-07-21 16:00:10
tags:
 - re
 - reverse
 - vapelite
 - backdoor
categories: Reverse
---

# 某Vape LiteV3.4.2破解版的账户窃取分析

在论坛中发现了该样本，帖子使用了Codex分析，但某绒的人工分析结果是无恶意行为，于是对其进行分析

原贴分析行为：

![image-20260821172817101](image-20260821172817101.png)

## 加载器分析

### 静态分析

Loader.exe

![image-20260721160604271](image-20260721160604271.png)

新鲜日期的64位程序，没有保护

根据Codex的分析，该文件中有个`a.class`

我们使用IDA分析该文件，定位到了主函数中，启动了一个线程，调用了`DefineClass`，但是这些指向的buf没有找到类文件的特征，甚至没有找到指向内容，于是决定动态调试

![image-20260821172947041](image-20260821172947041.png)

### dump class文件

搜索字符串找到对应引用位置，下断点运行

单步跟到框处函数处

![image-20260821173231701](image-20260821173231701.png)

该函数的返回值是明显的CLASS文件魔数特征，发现这里有一个循环，反复调用了该函数

在该循环条件终止时，定位到类文件对应内存空间位置

将这一块内存都dump出来

得到这样的文件：

![image-20260821173356021](image-20260821173356021.png)

按照魔术头分隔，用asm修复一下

得到7个类文件

![image-20260721182323279](image-20260721182323279.png)

## 类文件分析

### 静态分析

`a.class`中有一个不能反编译的方法，让我们详细看看它：

![image-20260721161607590](image-20260721161607590.png)

由于是ZKM25，翻了翻没有什么现有的反混淆器

于是顶着indy混淆手动翻一翻，毕竟`INVOKESPECIAL`这种用不了indy

![image-20260721162236076](image-20260721162236076.png)

观察到Socket创建

![image-20260721162322346](image-20260721162322346.png)

压缩文件的输出流，不过用的是字节流直接输出，意味着不落地

说明可能是创建压缩文件通过Socket传输到外部

### 动态调试

#### 反射调用a函数

把提取的jar作为库导入idea项目

创建一个default包的类，在这里调用`a.a`

由于ZKM混淆器的renamer使得存在命名重复签名不同的方法，从而不能直接调用，只能使用反射调用

```java
public static void main(String[] args) throws Exception {
    System.out.println(a.class);
    Method[] methods = a.class.getDeclaredMethods();
    for (Method method : methods) {
        method.setAccessible(true);
        if (method.getName().equals("a") && Modifier.isStatic(method.getModifiers()) && method.getParameters()[0].getType() == long.class) {
            System.out.println("ssss");
            
            method.invoke(null, 15186841654917L);
            
            System.out.println("hello");
        }
    }
}
```

这样可以定位到唯一的方法，从而调用指定方法。

ZKM混淆添加的这个方法参数是暴力测出来的，代码如下：

```java
while (true) {
    try {
        invoke = method.invoke(null, sbs[sb1]);
    } catch (InvocationTargetException e) {
        System.out.println(sb1++);
        continue;
    }
    System.out.println(sbs[sb1]);
}
```

如果传入的参数不正确，该方法不能正常运行，而是抛出一个异常

这里知道是从`Server.onMessage`方法中调用了该方法，所以用正则表达式`(-?\d+)L:?`提取`onMessage`方法中所有的long常量，约300多个，最终测得只有`15186841654917L`不会抛出异常

这并不安全，我们运行了一个未知的函数

#### 断点调试

对`a`类中的操作两个静态字段的静态函数下断点，发现`f`类是indy保护类，同样，对其中解密函数下断点，不需要断下字符串解密函数，因为在clinit中会有大量的字符串解密，而且很多不可读，在执行完之后，对String类的init方法，签名为char[]，或使用条件断点功能，设置断点生效时机

![image-20260721163638998](image-20260721163638998.png)

经过几次断下后，执行结束

逐个查看`f`中的静态字段，发现`b`中有东西

![image-20260721165258887](image-20260721165258887.png)

疑似调用了`currentTimeMillis`，我们知道这个是`System`的静态方法，获取当前时间戳

这意味着可能判断了时间是否过期/未到，重新检查字节码

![image-20260721165416782](image-20260721165416782.png)

发现了个疑似时间戳的常量，左边的分支直接执行到return

![image-20260721165529222](image-20260721165529222.png)

约为2026年8月5日，我们将系统时间调到该日期之后，重新执行代码

对Socket的构造方法下断点

![image-20260821170619325](image-20260821170619325.png)

导到本地，本地用python开一个服务器

`python -m http.server 45678`

调试过程中，发现解密了`File`的`exists`函数

![image-20260821170756417](image-20260821170756417.png)

于是在对应函数中下断点，这里解密过的字符串不会再次解密了，如果是重要函数一定要下断点，不然不会知道被调用了

![image-20260821170834421](image-20260821170834421.png)

发现判断`C:\Disable`是否存在，可能是某个标志位，不过我这里作为一个普通用户是不存在的

继续调试，注意到字符串解密：

![image-20260821170916997](image-20260821170916997.png)

调用`exits`方法判断了是否存在：

![image-20260821171003766](image-20260821171003766.png)

用`getenv`拼接出了`hmcl.json`

![image-20260821171145744](image-20260821171145744.png)

继续用`exists`判断：

![image-20260821171220555](image-20260821171220555.png)

hook到了获取用户名

![image-20260821171316616](image-20260821171316616.png)

为了获取hmcl的`accounts.json`文件

![image-20260821171601746](image-20260821171601746.png)

注意到调用了`putNextEntry`，结合静态分析中看到的`ZipOutputStream`构造方法，这里把`accounts.json`存到压缩包中

![image-20260821171651386](image-20260821171651386.png)

我们可以更快一步，直接对`write`方法下断点

同样方法发现了`readAllBytes`的调用

![image-20260821171900233](image-20260821171900233.png)

此处`write`方法断住，发现了`accounts.json`被装入压缩包

![image-20260821171943275](image-20260821171943275.png)

同样，对Feather的窃取：

![image-20260821172048658](image-20260821172048658.png)

对Lunar的窃取：

![image-20260821172106534](image-20260821172106534.png)

完成了对以上信息的寻找和窃取后，调用`toByteArray`方法转为字节流

![image-20260821172154482](image-20260821172154482.png)

解密了一个神秘字符串：

![image-20260821172210359](image-20260821172210359.png)

随后将这些数据发送给了服务器，数据包拦截：

**![image-20260821172501476](image-20260821172501476.png)**

用异或解密，密钥为`xiaojie1337`，发现了我的`accounts.json`文件

![image-20260821172556995](image-20260821172556995.png)

随后调用了`close`方法结束该函数的作用，调试结束

## 总结

这是一个有窃取HMCL、Feather、Lunar等账户信息行为的破解外挂，生效日期为2026年8月5日

另外，也许某绒病毒分析师可以尝试拥抱AI，我们都会有更美好的未来

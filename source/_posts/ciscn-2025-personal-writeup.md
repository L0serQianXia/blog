---
title: 2025年第19届CISCN&CCB初赛个人题解
typora-root-url: ciscn-2025-personal-writeup
date: 2025-12-29 16:25:28
tags:
- reverse
- crypto
- analysis
- CISCN
- CCB
- 2025
- writeup
- wp
- re
categories: Writeup
---

# 2025年第19届CISCN&CCB初赛个人题解

## 逆向工程

### babygame

#### 所用工具

GDRETools：https://github.com/GDRETools/gdsdecomp

CyberChef：https://cyberchef.org/

#### 操作内容

根据图标和启动动画判断是Godot引擎编写的小游戏，使用`GDRETools`（https://github.com/GDRETools/gdsdecomp）进行解包

在解包的目录下，找到scripts目录，下面有游戏中的所有脚本。发现一个脚本命名如下：`flag.gd`，内容如下图：

![image-20251228180626698](image-20251228180626698.png)

发现其中包含了`AES`算法的`ECB`模式加密代码，判断该脚本对应游戏中页面如下图：

![image-20251228180807208](image-20251228180807208.png)

按照脚本中所描述，对字符串`d458af702a680ae4d089ce32fc39945d`使用密钥为`FanAglFanAglOoO!`，进行`AES`算法的`ECB`模式解密即可得到flag

![image-20251228181023199](image-20251228181023199.png)

但使用`CyberChef`却无法得出正确明文，考虑到题目中的提示：

![image-20251228181112454](image-20251228181112454.png)

收集所有金币后，才可以验证flag，可能是在某时刻对key做了修改。搜索所有脚本文件，结果如下图：

![image-20251228181209973](image-20251228181209973.png)

发现`game_manager.gd`脚本中对key做了修改，修改key后再次解密，结果如下：

![image-20251228181305745](image-20251228181305745.png)

#### flag值

`flag{wOW~youAregrEaT!}`

### wasm-login

#### 所用工具

时间戳转换工具：https://tool.lu/timestamp/

CyberChef：https://cyberchef.org/

#### 操作内容

直接使用浏览器打开网页会发现提示跨域问题，不能允许访问，从而无法加载`WebAssembly`

![image-20251228183957213](image-20251228183957213.png)

根据网上的方法，将 `--disable-web-security --user-data-dir=C:\edgeDevData`添加到edge的参数中，即可关闭跨域校验

![image-20251228184109339](image-20251228184109339.png)

再次打开网页即可加载WebAssembly。

未查看题目附件细节时，会对题目描述一头雾水：

![image-20251228184256691](image-20251228184256691.png)

check值是什么？登录时间戳怎么获取？为什么给了相对具体的开发时间？

查看`index.html`的源码，发现如下注释：

![image-20251228184404698](image-20251228184404698.png)

提示了我们账号和密码，但是直接使用这个账号密码登录却返回登录失败

![image-20251228184445885](image-20251228184445885.png)

开发者工具中选中登录按钮，发现submit事件

![image-20251228184620392](image-20251228184620392.png)

跟进源码，发现按钮事件逻辑如下：

![image-20251228184714367](image-20251228184714367.png)

将输入的`username`和`password`传入了`wasm`中的`authenticate`函数，该函数大概返回一个`JSON`格式文本，并在控制台输出。随后将解析后的文本发送传入`simulateServerRequest`函数

固定输入用户名和密码为admin，多次提交验证，发现控制台输出如下：

![image-20251228185000035](image-20251228185000035.png)

提示我们`signature`可能与时间有关。

下面观察`simulateServerRequest`函数，如下图：

![image-20251228185051163](image-20251228185051163.png)

该函数将上文传进来的`JSON`又转为文本，并计算`MD5`散列值，得到16进制的结果存为变量`check`，并判断散列值是否以预置的字符串”`ccaf33e3512e31f3`“开头

这解答了我们的阅读题目时的疑问，程序判断登录是否成功是时间相关的，所以会给模糊的时间，并且check值就是指登录成功时，构造的`JSON`的`MD5`散列值

接下来，需要理解`password`和`signature`两个字段是怎么生成的

刚开始，我认为需要反编译`build`目录下的`release.wasm`文件，随后发现`release.wasm.map`文件中包含了编译前的源码，搜索如下图：

![image-20251228185607699](image-20251228185607699.png)

使用`CyberChef`如下功能进行格式化输出：

![image-20251228185914889](image-20251228185914889.png)

最后粘贴到本地文本编辑器并开启高亮可以得到很好的效果：

![image-20251228190002496](image-20251228190002496.png)

根据注释，密码是经过`Base64`编码的，但使用`Base64`解码并未得到明文：

![image-20251228190109286](image-20251228190109286.png)

查看`encode`函数实现，如下图：

![image-20251228190149255](image-20251228190149255.png)

直接看到了`Base64`换表，使用`CyberChef`再次解码

![image-20251228190250855](image-20251228190250855.png)

可以正常解码

下面查看`signature`是怎么生成的

![image-20251228190328387](image-20251228190328387.png)

调用了`hmacSHA256`函数，最后调用了`base64`编码函数返回

`hmacSHA256`函数如下：

![image-20251228190350678](image-20251228190350678.png)

比较复杂，试用python库提供的方法加密：

```python
import hmac
import hashlib
import base64

def Encrypt(word, key):
    return hmac.new(key.encode('utf-8'), word.encode('utf-8'), hashlib.sha256).hexdigest()
print(base64.b64encode(Encrypt('admin', str(1766160000000)).encode()))
```

输出结果如下：

![image-20251228190835445](image-20251228190835445.png)

长度明显大于题目加密后的`base64`文本。

最后计划使用暴破方法解决这个题目。

思路：在按钮事件中设置断点，断住后控制台中使用for语句跑循环，根据题目提示，正确的登录时间在`2025年12月21日00:00:00`到`2025年12月22日12:00:00`之间（2025年12月第三个周末到周一凌晨），hook `Date`的`now`函数，使其返回我们想要返回的时间就可以了

注意到登录时会有短暂的延迟，在`simulateServerRequest`函数中发现模拟延迟的地方

![image-20251228191447466](image-20251228191447466.png)

这里直接修改`index.html`中的代码即可，直接使该函数返回`true`或`false`

![image-20251228191559930](image-20251228191559930.png)

修改完成后刷新页面，开始编写脚本。

两个时间戳：

![image-20251228191838910](image-20251228191838910.png)

![image-20251228191850106](image-20251228191850106.png)

编写脚本如下：

```javascript
let start = 1766246400000
let end = 1766376000000

for (let i = start; i < end; i++)
{
	Date.now = function(){return i}
	const authResult = authenticate('admin', 'admin')
	const authData = JSON.parse(authResult);
	const result = simulateServerRequest(authData)
	if(result){
	 alert('登录成功！' + i);
	}
	else {
		//console.log(i)
	}
}
```

在`simulateServerRequest`返回`true`时，显示登录成功的时间戳

随后在提交事件处理函数内下断点，如下图：

![image-20251228192123418](image-20251228192123418.png)

断住后在控制台中粘贴写好的脚本，回车开始执行

![image-20251228192341837](image-20251228192341837.png)

经过了很长的一段时间之后，弹出提示：

![image-20251228192526317](image-20251228192526317.png)

登录时间戳为`1766334550699`

![image-20251228192547686](image-20251228192547686.png)

（登录成功的时间原来在周一凌晨，而且浏览器跑暴破还是太慢了，不过胜在简单）

由于没有做跑出时间戳就停止，需要重新打开网页，再次停在上面的断点中，断住后在控制台中输入如下：

```javascript
Date.now = function(){return 1766334550699}
```

![image-20251228192807167](image-20251228192807167.png)

令获取时间的函数，返回正确登录时的时间戳，回到源码页，单步，直到`simulateServerRequest`函数调用处，在这里步入，直到`check`变量被赋值

![image-20251228192931183](image-20251228192931183.png)

现在，我们得到了`check`的值为`ccaf33e3512e31f36228f0b97ccbc8f1`

#### flag值

`flag{ccaf33e3512e31f36228f0b97ccbc8f1}`

## 密码学

### EzFlag

纯逆向方法解答了属于是，不够密码

#### 所用工具

IDA

Detect It Easy

#### 操作内容

题目附件没有后缀名，信息如下：

![image-20251228193459925](image-20251228193459925.png)

64位ELF文件，IDA中F5生成伪代码如下：

![image-20251228193800895](image-20251228193800895.png)

可以看到要求用户输入的文本与预置文本`V3ryStr0ngp@ssw0rd`进行对比，如果不相同，则会提示用户`Wrong password!`

如果相同，则会输出`flag{}`格式的文本。

了解以上后，直接在虚拟机中运行

![image-20251228193934307](image-20251228193934307.png)

发现flag逐个字符输出，并且有间隔时间，在IDA中Patch掉伪代码中39行的`sleep_for`调用后，发现仅仅是前面快了点，到后面仍然不动了

使用IDA的远程调试，查看一下停在了哪里

![image-20251228194703389](image-20251228194703389.png)

手工调试发现`f`函数会消耗比较多的时间，进入该函数，逻辑如下图：

![image-20251228194816135](image-20251228194816135.png)

可以看到其中包含一个for循环，决定这个循环次数的是传入的参数`a1`，随着`main`函数中for循环内对`f`函数的调用次数增长，传入的参数也会成倍数增长。

到最后会达到一个极大的数字，正常执行程序不会在短时间内输出flag，因此一定存在一定的规律。

以下是手动记下的每次循环变量的值：

![扫描件_160D_1](/扫描件_160D_1.jpg)

格式如表格：

| `v4`（赋值后） | `v5` | `v4`（赋值前） |
| -------------- | ---- | -------------- |
| 1              | 0    | 1              |
| 2              | 1    | 1              |
| ...            | ...  | ...            |

可以看到，在最后`i=24`时（图中未标记），`v4`（赋值后）为1，`v5`为0，`v4`（赋值前）为1，与`i=0`时的状态相同，可判断24次为一个完整的循环。

根据小学数学，对于传入的参数，取余`24`得到的结果与传入参数是相同的效果，所以我们可以手动修改循环次数。

根据64位的调用约定，第一个参数通过`rdi`传递，在如图红框处下断点。在`a1`值较大时，手动做 `a1 % 24`并将结果放回

![image-20251228201426840](image-20251228201426840.png)

使用如下脚本帮助计算：

```python
def a(b):
	c = b % 24
	return hex(c)
```

根据调用约定，64位程序通过`rdi`传第一个参数，手动修改该寄存器的值即可

![image-20251228201014234](image-20251228201014234.png)

![image-20251228201746699](image-20251228201746699.png)

修改值后，F9运行程序，重复若干次后得到flag：

<img src="/image-20251228202124122.png" alt="image-20251228202124122" style="zoom:50%;" />

![image-20251228202034443](image-20251228202034443.png)

#### flag值

`flag{10632674-1d219-09f29-14769-f60219a24}`

## 流量分析

### SnakeBackdoor-1

#### 所用工具

WireShark

#### 操作内容

使用`WireShark`打开流量包，题目询问`攻击者爆破成功的后台密码是什么？`

可推测，一般为服务器后台，先过滤`http`数据包

![image-20251228202603216](image-20251228202603216.png)

发现大量对`/admin/login`的`POST`请求

暴破一般在密码正确后停止，直接拉到最下面

![image-20251228202647225](image-20251228202647225.png)

看到最后一条对`/admin/login`的`POST`请求，密码为`zxcvbnm123`

#### flag值

`flag{zxcvbnm123}`

### SnakeBackdoor-2

#### 操作内容

题目询问`攻击者通过漏洞利用获取Flask应用的 SECRET_KEY 是什么`

从登录后台的请求后逐个查看，发现可疑的模板注入点，如下图：

![image-20251228202815519](image-20251228202815519.png)

该条请求的响应包如下：

![image-20251228202907004](image-20251228202907004.png)

可以看到已经读取到了`config`，右键右边的数据区域，选择复制为ASCII文本，粘贴到文本编辑器

![image-20251228202959048](image-20251228202959048.png)

![image-20251228203021201](image-20251228203021201.png)

使用`CyberChef`处理后，更可观的观察到`SECRET_KEY`

`c6242af0-6891-4510-8432-e1cdf051f160`

#### flag值

`flag{c6242af0-6891-4510-8432-e1cdf051f160}`

### SnakeBackdoor-3

#### 操作内容

题目问`请分析注入Payload，给出该加密算法使用的密钥字符串(Key)`

继续观察模板注入点，发现如下数据包：

![image-20251228203145249](image-20251228203145249.png)

拷贝出来轻微整理一下如下：

![image-20251228203215208](image-20251228203215208.png)

使用`base64`编码处理了

`CyberChef`解码结果：

![image-20251228203316107](image-20251228203316107.png)

仍然有`base64`编码，还是逆序的，还使用`zlib`压缩了，使用如下配置处理：

```url
https://cyberchef.org/#recipe=Find_/_Replace(%7B'option':'Simple%20string','string':'%5C'))'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'exec((_)(b%5C''%7D,'',true,false,true,false)Reverse('Character')From_Base64('A-Za-z0-9%2B/%3D',true,false)Zlib_Inflate(0,0,'Adaptive',false,false)&ieol=FF
```

处理后如下：

![image-20251228203511668](image-20251228203511668.png)

使用`Replace Input with Output`按钮（输出框上方右侧倒数第二个）继续处理多次（非常多次）

得到如下结果：

![image-20251228203620256](image-20251228203620256.png)

看到了`RC4`的关键字，推测这就是密钥。

#### flag值

`flag{v1p3r_5tr1k3_k3y}`

### SnakeBackdoor-4

#### 操作内容

题目`攻击者上传了一个二进制后门，请写出木马进程执行的本体文件的名称`

分析第3题得到的后门脚本

![image-20251228203732432](image-20251228203732432.png)

看到后门请求的头部中有键`X-Token-Auth`，值固定为`3011aa21232beb7504432bfa90d32779`

该后门脚本还会获取请求中的的`data`参数，`unhex`后`rc4`解密，并作为命令执行，并将执行结果返回

经逐条查看，以下选中的请求都为后门请求

![image-20251228204001873](image-20251228204001873.png)

分析整理如下：

![image-20251228204106243](image-20251228204106243.png)

上述文本，等号前一行为data参数传入的执行命令，等号后一行为服务器执行结果返回。如果没有等号或者等号后一行留空，说明该命令没有执行结果返回

可以看到这里主要做的操作是从`192.168.1.201:8080`下载了压缩包`shell.zip`并保存到服务器本地的`/tmp/123.zip` 处

并使用密码`nf2jd092jd01`解压下载的压缩包

并将文件`/tmp/shell`重命名为`/tmp/python3.13`

最后执行了`/tmp/python3.13`

所以`python3.13`为木马进程执行的本体文件的名称

#### flag值

`flag{python3.13}`

### SnakeBackdoor-5

#### 操作内容

题目`请提取驻留的木马本体文件，通过逆向分析找出木马样本通信使用的加密密钥（hex，小写字母）`

`WireShark`中将`shell.zip`文件的返回作为hex流复制，并二进制粘贴到010 editor中创建新文件

![image-20251228204445825](image-20251228204445825.png)

保存到本地如下：

![image-20251228204533053](image-20251228204533053.png)

使用上一题分析的密码`nf2jd092jd01`解压

使用IDA静态分析

![image-20251228204735149](image-20251228204735149.png)

发现该恶意程序回连到`192.168.1.201`，并接受4字节的数据，随后根据收到的数据设置一个随机数种子，随后使用随机数函数生成key

使用wireshark过滤所有port为58782的tcp请求，如下图：

![image-20251228205029138](image-20251228205029138.png)

逐个获取内容，并写出如下的脚本：

```python
import socket

s = socket.socket()
host = socket.gethostname()
port = 58782
s.bind(('192.168.9.1', port))

s.listen(5)
while True:
    c, addr = s.accept()
    print("coonection:", addr )
    c.send(b'\x34\x95\x20\x46')
```

这里伪造了服务器，给虚拟机设置为与主机共享的虚拟网络，然后可以与主机上的伪造服务器连接

![image-20251228205312070](image-20251228205312070.png)

这里IDA调试，手动修改了服务器ip

![image-20251228205344010](image-20251228205344010.png)

调试获得密钥为`ac46fb610b313b4f32fc642d8834b456`

#### flag值

`flag{ac46fb610b313b4f32fc642d8834b456}`

### SnakeBackdoor-6

#### 操作内容

IDA可以分析出来这里是`SM4`常数

![image-20251228205607851](image-20251228205607851.png)

但是直接`CyberChef`直接解密不能解密，于是使用笨蛋方法，伪造服务器发请求让后门去解密

在`wireshark`中过滤所有的tcp请求，端口为58782

![image-20251228205029138](image-20251228205029138.png)

逐个分析请求，并且把内容复制到脚本中发给后门，让它解密

```python
import socket

s = socket.socket()
host = socket.gethostname()
port = 58782
s.bind(('192.168.9.1', port))

s.listen(5)
while True:
    c, addr = s.accept()
    print("coonection:", addr )
    c.send(b'\x34\x95\x20\x46')
    c.send(b'\x00\x00\x00\x10')
    c.send(b'\x49\xb3\x51\x85\x5f\x21\x1b\x85\xbd\x01\x2f\x80\xce\x8e\xd5\xb3') #pwd
c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('2cc5becb37ca595a89445461c6512efc'))# /tmp/app     

c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('b863696da0c6bb28da46e09069dd644f'))# id

c.send(b'\x00\x00\x00\x30')
c.send(bytes.fromhex('87e8faa921f3e67c530f1b6740a9d439794e426716d49f5e949d5d56f81ed54a97f6cc6752fcf7aa408a94e6a59029e7'))#uid=0(root) gid=0(root) groups=0(root)\n

c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('b7c88bb0d92308a57f83d08a90ae024c'))# ls -al;

c.send(b'\x00\x00\x09\x20')
c.send(bytes.fromhex('91fc3c4dc278b1afc5636adeca578f3fe37c16fa66fae433d0d7eb331e7926025ad84833f28fc2641bf05e058be36ed06b3ba79fb66a1ae4192c51152e87a1c6abf66f0a1038689d2137f94d6a686b946120ea2d6fbe312786411b701a353ab035de9c7dc81abfa0dfef55c14cd1f99e07cc2bccec85db48d820038d8c1273024cd80f99e761e2dc2ca5f79f97eb5e01c74a7807ba9f29d99338ea1962daba592f2f212ca8686cf37880755f82949cce1e38a7cd2c8f4a79e5a5b640375a94faa0dd2df11225df777845781f0562aab86e09effa9d6254ac8db8853036f680c37d9a047eafd0b65d7b8715cdd7f9becf3046afd113dc0b8b714b002cafc2482c4f240dab7cfa61ea30b3d4595b67563fde635bbd243f3ea8cca3d6bad779161939dd3acd3de84e9f0345f8e4c7b1dd0909922334bbbc0ccd412b8d8216337b515ad84833f28fc2641bf05e058be36ed08c073a5d9d24304eaf50c29d1f3cde1893acc5e4ba171ed4d1474d3f0046208ba565589ace3ecd59e248c22663b789ff5ff9eb73ea4fff8399159d10f689487d553333ce4ec0c0c568a5f532a015a6f1801f0d820a0b8a744b915248b842a2448d9b6d2d0493c7e8a32b86c05a26127a02bbb99ba83f410b1c2b9bbc1b5e39a5558f467eebd32b38a3e208c2534f74b450e412c2ab730ec45b224a2ba5255e24fd831db1d900c8a57967b8ad6993fb3a9b2de1d2d6093eb14a02ddd4cb29275b4cd80f99e761e2dc2ca5f79f97eb5e01ae78b840270ec94dd8eaeb7d15b9b74406f4e96257e0eec382482d4dcfb64257b9e83711e847957323fedb65b189afe150ae2213b7c9d2788dce7ba88cf8774a9bbe15c3832f0c136b1397209a7d6a9f37d3bc0a242f029d6a4feb9b26a55d786120ea2d6fbe312786411b701a353ab0c81a54b98f519ef41ce3775f5b2c26c7ad644797d69604a9fd412ae25a28aec737d3bc0a242f029d6a4feb9b26a55d786120ea2d6fbe312786411b701a353ab0158df499dc5f4de223e3dca72bbf66f48ac1fc75b1be3cc2e4de7d370f88778a006daefea44d62d389eff227e4d031124cd80f99e761e2dc2ca5f79f97eb5e01507836a14c3f3e83d0a317cd2ab8048eba52c6ca5e547ff797fca0cd47c62f4b7356b3bc38bc81e646000cf069b2be56d9fe59bcf4063d0a0363b9209c4f3860c90967283e1b364810145ed6e7525074a1a2527c05163cd8d49595c493a9bc5e5d480f143d8f892dfd8f90b3e8d3ea20352c9d0ad901cc079bf2a592ae4c58be125fff2fb31ecdcd95dc2fcdefdf1c6101dabec17b13f2d04eb8851a3115be66d1778dfb4003a9f705ad133b196c32404734c892cda46767181cf7a0a38fb8ac6e0a04a6bff4b1e8a7bfdabe5ddabbf62f934f8f91898a41dd0a0fd7c83eb55d27fe795766e9fcf20b8b885081848690e58d3748a157c7801a3d5c42db28cebf582760ac945ac0fc2b72edfc43c01c919b5a749a422da155198cbe9e3a2806a32a4e4a8590bbcf0496b0e13a8be7fbb69d55fc3541905d448499cd88edf0c58f59205e9f89a115e0ca9b5c3ebd9415c631acc7f6b9de54a40a9fa7d606f95e4cd62cd0cb2eb4feb350d04c46ce6f8b8d0eaf46208b3b4d4508812cd908bce78846ad5c20a6dbb14f7373dfce61976b85e58d3748a157c7801a3d5c42db28cebf75ec1d1089052336e2c805f6e1d401dc35b7bb0bf188e8a9c2e8567a3ae0ec3bf6b9c05a0b6a9673c89693fbe7894b0135481fbddaf394773fad605eae99f4600e956dd8d489eb2ed159c598fabec5b17c8df9c4b414a371aa84b77eefea1bb42418ea7fd3709e2ef4850ddae503e92a0b4ff34aa7020c999bac051005b26fa5a0f828b51e588aeca3e690e9c84ff682164a86379ddda02b1d92f0dee9a1d0cb9cbdf5432cc4b943ba474c4f5467500b0b31d077cf5047aa9384cf4b6757ca370a5e0604fcd15bfedaefe87179f97cf0efe63431c3b3540eb2e459cb8250fc1993bea701c61b61b7ffc13777b2d9f9dc57d229f0489d63280f8e8c73baeb70cada6aa30d3a91d0c8f4f2a26dd4e3e7ad0c99810245ae92a05893d4b74323a37247cc6c9c417f8082ccef101bd31acdc79c8a673396353a030358d2a3db37019672b8042929a68fea5ba9965e5145940355e00debe46e80b75dd31b646f39d4cb3e057bc64c8e3b39a7c6d3bfdd41a836ff87620ec931e8a490f0ad33048de50841a959f4baac6fb0e36b389f6f5ecb3925b04a5d37f37479c0ed02b23f38c64e44300433b5a0cbc4063760642bba08473e11ef2c7be2f6bc0ac99cca4792b17dfe4f3358455566bb4e3006a200a87466f4dafea0bfa7a420220ca5ec4f5e73d89784fce2cfc878df8f3609576975a58ce58d3748a157c7801a3d5c42db28cebf152ab441a154dfbd83e6e929e62be820e41688e06d47bde780960ef807b3fd78bdf05032d4aa84948b384d9afd9fc12c95169f9ee5c386f60e32374951be448e92d4853b4c8ae7fbc715f4562156ba86b5adc49e400e7c227c617a26bbd908a27896015cf6f8532e5c04b5030abe4f7f0f6c167ab0ea204e76fdfca5e6311fee6403bb60415e43af2a10de078a479a8c644709a3082176ffb04af8535796b3acf83bcd500f288a491101dcea576f1dd97ba6ce01d8f1de4e98135bf20f394129672538325aaded45fd604b388019b12df57ff11b010ba7c39dc7f04fd26b770806b46d91016bd16e126c8d3f6c874acfe42ee6bc7030e24c62e9901103458ebd44fced6e5064c2f19da84dfff4c62f6c1088c3bc411ab9ab0f7eb772b85958d94f1775cb597f36010c045326de15287a5ee634e93ce07e0ad0ea5c9cebc60308823d603ef85287de24fb532cbc577b8fd49553f3ca6067dd2b58467a749571247d6c20d005178494c3c9ec028297a8360248ecd4a8d4a9088a0b27faba386dca644709a3082176ffb04af8535796b3ac02f30c6c0d7cc594e2bcafb487e74f12157ce37c1553c6382b1689c659eaeb23672538325aaded45fd604b388019b12df57ff11b010ba7c39dc7f04fd26b770804245b989b54cced122e6e9e9551efd011a479cd8db04b5fdcdb0cb75ba0039c44fced6e5064c2f19da84dfff4c62f6c5f4161bc70501782795e73b2032071d9a205839af1b4b42d35f628f79847bf3cd80c3faa03cab06d8cbeae800ce724a7823d603ef85287de24fb532cbc577b8fa014e820aedef4bbd9685845951995982ccf1a4cef2497d36c1dd18bd968932e5e197f709a77d04aa112373cc4c1d0ab'))

c.send(b'\x00\x00\x00\x30')
c.send(bytes.fromhex('4331cfda21eeab8922fcc7acced16d1a17b02e8d2d9dfee48dc8f18e0dbbb2e4c4547e39d8c4aa2418d9fca52c9c4770'))#cat /flag | tr '1' 'l' | tr '0' 'O'

c.send(b'\x00\x00\x00\x30')
c.send(bytes.fromhex('7f4b0ef4806983f164af6f46b71d3fce1e3c0bd00c4dd162b72c156f0f3aecd2afcabf551e08380db6fd20316f8a2729'))#flag{6894c9ec-7l9b-46O5-82bf-4felde27738f}\n

c.send(b'\x00\x00\x00\x30')
c.send(bytes.fromhex('de7cc756e5c97fed18a72a95af102dac48dc0810752bd7755157e5909974cbe0ce87241e7f01e3169e7a763a22008029'))#echo \"hach by hahahah\" > /tmp/hacked

c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('7b82a7a9e2cacaa29b6e70cec2a3302a'))

c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('f958a8cea6721e88d1882e0f16e4da4b'))#exit

c.send(b'\x00\x00\x00\x10')
c.send(bytes.fromhex('7b82a7a9e2cacaa29b6e70cec2a3302a'))
```
这里把所有解密后内容放在了注释里，要注意这里读取flag的时候替换了字符，提交的时候需要替换回去

#### flag值

`flag{6894c9ec-719b-4605-82bf-4fe1de27738f}`

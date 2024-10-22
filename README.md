
# web信息打点


## 0x01 信息架构


语编程言：搜所引擎、文件后缀、搭建组合推算


中间件：端口扫描、看返回数据包


域名资产：收集、分析


操作系统：大小写、ttl值、指纹识别



```
WINDOWS NT/2000   TTL：128
WINDOWS 95/98     TTL：32
UNIX              TTL：255
LINUX             TTL：64
WIN7          	  TTL：64

```

社会工程学：钓鱼邮件、社会工程学攻击


资产监控：git资产监控


web应用：插件、应用、环境


## 0x02 域名


### 2\.1 真实ip获取


#### 2\.1\.1 真实ip介绍


在部分网站中部署有cdn加速当我们直接ping包或者访问的时候我们的ip 是cdn主机IP不是真实IP


#### 2\.1\.2 cdn


##### 2\.1\.2\.1 什么是cdn


* 内容分发网络（CDN）： 是指企业利用分布在不同区域的节点服务器群组成流量分配管理平台，为用户提供内容分散存储和高速缓存服务
* 在渗透测试过程中，经常会碰到网站有CDN的情况。CDN即内容分发网络，主要解决因传输距离和不同运营商节点造成的网络速度性能低下的问题。说的简单点，就是一组在不同运营商之间的对接点上的高速缓存服务器，把用户经常访问的静态数据资源直接缓存到节点服务器上，当用户再次请求时，会直接分发到离用户近的节点服务器上响应给用户，当用户有实际数据交互时才会从远程Web服务器上响应，这样可以大大提高网站的响应速度及用户体验。


##### 2\.1\.2\.2 cdn识别


* 超级ping


出现多个ip不一样的证明有cdn



```
ITDOG:https://www.itdog.cn/ping/https://www.itdog.cn/ping/
nodecook:https://www.nodecook.com/zh/ping
站长工具：http://ping.chinaz.com/
爱战网：https://ping.aizhan.com/
ITDOG:https://www.itdog.cn/ping/

```
* nslookup域名解析



```
nslookup 

```


### 2\.2 子域名


#### 2\.2\.1 挖掘


* 页面识别


通过网页页面 包含的链接精准收集子域名
* 测绘工具


通过测绘功工具来收集



```
微步：https://x.threatbook.com/3
360kuake:https://quake.360.cn
fofa:https://fofa.info/
钟馗之眼：https://fofa.info/
鹰图：https://hunter.qianxin.com/

```
* 域名挖掘工具



```
oneforall
Subfinder
lauer
DNSRecon
......

```
* 反查



```
ip138:https://site.ip138.com/
......

```
* 域名解析



```
ip138:https://site.ip138.com/

```


#### 2\.2\.2子域名综合查询工具



```
http://tool.chinaz.com/subdomain/
http://i.links.cn/subdomain/
http://subdomain.chaxun.la/
http://searchdns.netcraft.com/
https://www.virustotal.com/
https://x.threatbook.com/v5/mapping
https://ip138.com

```

### 2\.3 网站其他信息收集


#### 2\.3\.1 whois查询


在线工具



```
站长之家域名；http://whois.chinaz.com/

爱站网域名；https://whois.aizhan.com/

腾讯云域名；https://whois.cloud.tencent.com/

美橙互联域名；https://whois.cndns.com/

爱名网域名；https://www.22.cn/domain/

易名网域名；https://whois.ename.net/

中国万网域名；https://whois.aliyun.com/

西部数码域名；https://whois.west.cn/

新网域名WHOIS；http://whois.xinnet.com/domain/whois/index.jsp

纳网域名W；http://whois.nawang.cn/

中资源域名：https://www.zzy.cn/domain/whois.html

三五互联域名：https://cp.35.com/chinese/whois.php

新网互联域名：http://www.dns.com.cn/show/domain/whois/index.do

国外WHOIS信息查询：https://who.is/

域名反查：
https://mwhois.chinaz.com/
https://whois.chinaz.com/

icp备案查询：
https://beian.mlit.gov.cn/
https://icp.chinaz.com/
https://beian88.com/

```

#### 2\.3\.2 站点信息


##### 2\.3\.2\.1 堆栈建站


* MERN Stack (MongoDB, Express.js, React, Node.js)



```
MERN 堆栈是一个全栈 JavaScript 解决方案，适合构建现代化的 Web 应用程序。

```
* MongoDB: NoSQL 数据库，适合存储非结构化数据。



```
Express.js: 基于 Node.js 的轻量级 Web 应用框架。
React: Facebook 开发的用于构建用户界面的 JavaScript 库。
Node.js: 服务器端运行 JavaScript 的环境。

```
* MEAN Stack (MongoDB, Express.js, Angular, Node.js)



```
MEAN 堆栈与 MERN 类似，但使用 Angular 代替 React
Angular: Google 开发的用于构建动态 Web 应用的框架。

```
* LEMP Stack (Linux, Nginx, MySQL, PHP)



```
LEMP 堆栈与 LAMP 类似，只是使用了 Nginx 作为 Web 服务器。
Nginx: 一个高性能的HTTP和反向代理服务器，适合处理高并发请求。

```
* MEVN Stack (MongoDB, Express.js, Vue.js, Node.js)



```
 MEVN 堆栈也是全栈 JavaScript 解决方案，使用 Vue.js 替代 React 或 Angular。
Vue.js: 一种用于构建用户界面的渐进式框架。

```
* .NET Stack (Windows, IIS, SQL Server, ASP.NET)



```
.NET 栈主要面向 Windows 平台。

```
* Windows: 操作系统。



```
IIS: Internet Information Services，是 Windows 上的 Web 服务器组件。
SQL Server: 微软的关系型数据库管理系统。
ASP.NET: 微软的 Web 应用框架，支持多种编程语言。

```
* Ruby on Rails with PostgreSQL



```
Ruby on Rails: 一个用于快速开发 Web 应用的 MVC 框架。
PostgreSQL: 一个功能强大的开源对象关系数据库系统。

```
* Django with PostgreSQL or MySQL



```
Django: 一个高级的 Python Web 框架，鼓励快速开发并干净、务实的设计。
PostgreSQL/MySQL: 数据库管理系统。

```
* Java EE Stack (Apache Tomcat, MySQL, Java)



```
Apache Tomcat: Java Servlet 容器。
MySQL: 关系型数据库管理系统。
Java: 编程语言，Java EE 规范提供了企业级应用开发的标准。

```
* Flask or Django with SQLite or PostgreSQL (Python)



```
使用 Python 的轻量级框架 Flask 或者 Django，配合 SQLite 或 PostgreSQL 数据库。

```
* Flask: 轻量级 Web 应用框架。



```
SQLite: 轻量级嵌入式数据库引擎。

```
* ASP.NET Core (Cross\-Platform)



```
ASP.NET Core: 微软的跨平台 Web 框架，支持 Windows、Linux 和 macOS。
SQL Server/MySQL/PostgreSQL: 数据库选项。

```


##### 2\.3\.2\.2 软件建站


比如phpstudy、宝塔等搭建软件搭建的站点，各有其特征。


* 如何判断是否是软件建站
抓包，看server行，一般比较详细的就是使用搭建软件搭建，下面就是一个对比
* 判断建站软件
最好就是亲手用最新的改款搭建软件去搭一个，一般同版本的搭建软件给的中间件都是相同的，并且各有其特征。
例如宝塔搭建的网站，其8888端口一般就是其管理网站，可以使用8888端口去尝试访问
* 又例如phpstudy搭建的网站，一般会有一个phpmyadmin目录，尝试访问这种目录，如果正常跳转回显，那么基本上就是Phpstudy


服务器操作系统


* 通过ping包字段识别
* 指纹识别工具


##### 2\.3\.2\.3 浏览器语法搜索


谷歌浏览器常见语法



```
基本搜索语法
intitle: 查找页面标题中含有特定关键词的网页。
例：intitle:"index of"

inurl: 查找URL中含有特定关键词的网页。
例：inurl:"admin"

filetype: 查找特定类型的文件。
例：filetype:pdf "security report"
site: 限制搜索结果来自于指定的网站。
例：site:example.com

related: 找出与指定网站相关的其他网站。
例：related:example.com

cache: 查看谷歌缓存的页面版本。
例：cache:example.com

define: 查找词语的定义。
例：define:information

高级搜索语法
intext: 查找页面正文中包含特定文本的网页。
例：intext:"confidential"

link: 查找链接指向特定URL的网页。
例：link:example.com

info: 显示关于URL的一些基本信息。
例：info:example.com

allintitle: 页面标题中包含所有给定词组。
例：allintitle:"index of"

allinurl: URL中包含所有给定词组。
例：allinurl:"login"

allintext: 正文文本中包含所有给定词组。
例：allintext:"secret document"

组合使用
你可以组合使用上述语法来进一步细化搜索结果。例如：

intitle:"index of" filetype:pdf site:example.com
这条搜索语句将会寻找在example.com上标题包含index of并且是PDF格式的文件。

```

baidu浏览器常见语法



```
通用搜索语法
intitle: 搜索网页标题中包含的特定关键词。
例如：intitle:后台管理 可以找到标题中含有“后台管理”的网页。

inurl: 搜索URL中包含的特定关键词。
例如：inurl:/wp-admin/ 可以找到URL中含有“/wp-admin/”的页面。

filetype: 搜索特定类型的文件。
例如：filetype:pdf 安全报告 可以找到PDF格式的安全报告文件。

site: 限定搜索范围在特定的网站内。
例如：site:example.com 仅在example.com网站内搜索。

双引号 ("..."): 搜索完全匹配的短语。
例如："默认密码" 只会返回包含完整短语“默认密码”的网页。

减号 (-): 排除含有特定关键词的网页。
例如：登录页面 -test 排除含有“test”的登录页面。

常见的应用
寻找登录页面
inurl:/login
intitle:"登录页面"

查找配置文件或敏感文档
filetype:txt config
filetype:xml password

查找子域名
site:.example.com
结合子域名枚举工具，可以更加高效地查找未公开的子域名。
寻找开发环境或测试环境

intitle:"开发环境"

intitle:"测试服务器"

```

### 2\.4 端口及其对应服务信息


#### 2\.4\.1使用端口扫描工具


Nmap 是一个强大的网络探索工具，也是端口扫描工具，可以用来发现主机和服务。例如：



```
TCP SYN 扫描：nmap -sS -p- <target>，扫描所有 TCP 端口。
TCP 连接扫描：nmap -sT -p 80,443 <target>，扫描指定端口（如 HTTP 和 HTTPS）。
UDP 扫描：nmap -sU -p 161 <target>，扫描 UDP 端口（如 SNMP）。
服务版本探测：nmap -sV -p 80,443 <target>，探测服务版本。
操作系统探测：nmap -O <target>，探测操作系统类型。

```

#### 2\.4\.2 使用 Whois 查询


通过 Whois 查询可以获取目标域名的注册信息，包括 IP 地址等，从而进一步进行端口扫描。例如：



```
whois <domain>

```

#### 2\.4\.3 DNS 枚举


使用工具如 DNSRecon 或 Layer 子域名挖掘机来发现与目标域名相关的其他域名或子域名。



```
DNSRecon: dnsrecon -d <domain> -r <resolver>
Layer 子域名挖掘机: layer_subdomain_brute <options>

```

#### 2\.4\.4 使用在线端口扫描工具


有许多在线端口扫描服务可以直接在浏览器中使用，例如：



```
TooL.cc: https://tool.lu/port/
Postjson: https://tool.postjson.com/online-port-scanner.html

```

#### 2\.4\.5 手动使用命令行工具


Netcat: 可以用来测试单个端口是否开放。



```
nc -zv <target> <port>

```

Telnet: 也可以用来测试端口。



```
telnet <target> <port>

```

#### 2\.4\.6 使用自动化工具


Metasploit: 包含了许多用于端口扫描和服务探测的模块



```
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 
run

```

### 2\.5 目录扫描


#### 2\.5\.1 常见敏感目录



```
reboot.txt
sitemap.xml
网站备份文件/数据：在线压缩(文件)/帝国备份王(数据)
后台登录目录：/admin /.manage
安装包（源码）：非开源，商用/zip文件/install
文件上传的目录：/upload /upload.php
文件上传的目录-webshell
mysql的管理界面：web页面去管理/phpadmin
程序安装路径：/install
php探针：phpinfo/雅针探黑
文本编辑器
linux：用户—cat /etc/passwd 密码—cat/etc/shadow 执行sudo—cat /etc/sudoers
MacOS ：.DS_Store 文件夹自定义属性的隐藏文件（一定要删掉）
编辑器的临时文件：.swp
目录穿越 tomcat WEB-INF
其他非常规文件：secret.txtp / assword.txt

```

#### 2\.5\.2 工具扫描



```
御剑
dirb
Burp Suite
DirBrute
Dirsearch
Dirmap
wfuzz
铸剑

```

### 2\.6 抓包分析


#### 2\.6\.1 目的


* 理解通信行为：通过分析数据包，可以了解Web应用与外部系统的交互细节。
* 检测安全漏洞：识别数据包中的敏感信息泄露、认证机制薄弱等问题。
* 模拟攻击：基于捕获的数据包模拟攻击，验证系统的安全性。
* 问题诊断：帮助网络管理员和开发者诊断网络问题或应用故障。


#### 2\.6\.2 常见工具：


* Wireshark
* Fiddle
* Burp Suite
* tcpdump
* cURL


#### 2\.6\.3 分析数据包


* 使用显示过滤器：在捕获到的数据包中使用显示过滤器来查找感兴趣的特定数据包。
* 检查协议字段：仔细查看数据包中的协议字段，如HTTP请求头、响应头、Cookie等。
* 分析敏感信息：检查是否存在明文密码、API密钥等敏感信息。
* 查看异常行为：留意是否有异常的响应代码或不寻常的请求模式


## 0x03 源码


分类：CMS开源、闭源


### 3\.1 CMS识别


#### 3\.1\.1 识别方法


##### 3\.1\.1\.1 手动识别


* 通过页面特征和页脚信息识别


在页脚声明中部分会留下cms的名字
* 检查网站源代码


CMS通常会在网页的源代码中留下一些特定的标记，如HTML  标签中包含的`generator`属性此外，还可以检查特定的文件名或路径，例如`/wp-admin/`（WordPress）或`/admin/`（Joomla）等
* 文件和目录特征


不同的CMS会有各自独特的文件和目录结构。例如，WordPress可能会有`wp-content`目录，而Joomla可能会有`administrator`目录通过查找这些特定的文件或目录，可以识别出CMS的类型。
* JavaScript和CSS文件


CMS通常会在页面中加载特定的JavaScript和CSS文件。通过分析这些文件的名称和内容，也可以帮助识别CMS
* HTTP响应头信息


一些CMS会在HTTP响应头中包含特定的信息，比如`X-Powered-By`字段，这可以用来识别CMS类型2\.1\.1\.2


##### 3\.1\.1\.2 工具识别


* 云悉指纹识别
* 潮汐指纹识别
* 工具识别tidefinger
* 在线指纹识别
* wappalyzer 浏览器插件
* whatweb（本地）


### 3\.2 能识别CMS的


#### 3\.2\.1 CMS开源


如果目标网站是使用开源的CMS（内容管理系统）构建的，可以通过访问官方网站下载最新版本的源码。例如，WordPress、Drupal等都有官方发布的版本


#### 3\.2\.2 利用搜索引擎


通过搜索引擎使用特定的查询语句，有时候可以找到一些未受保护的源代码文件。例如，使用Google Hacking技巧，通过如`filetype:zip intext:source code`这样的搜索条件，有可能找到存放源码的压缩包文件。


#### 3\.2\.3 利用公开的代码仓库


开发人员有时会在公开的代码仓库如GitHub、Gitee 等平台上无意间上传了项目的源代码，这些源代码可能包含了敏感信息。通过搜索相关的关键字或者开发者的用户名，有可能找到有关的项目仓库。


### 3\.3不能识别CMS


* composer.json(PHP特性)
* git源码泄露：
* svn源码泄露：
* hg源码泄露：
* 网站备份压缩文件泄露：
* web\-INF/web.xml泄露:
* DS\_store文件泄露：
* SWP文件泄露：
* CVS泄露：
* bzr泄露：
* github源码泄露：


### 3\.4 黑源码：


* 互站


## 0x04 工商信息收集


### 4\.1 关注的基本信息


* 企业基本信息：包括公司名称、注册地址、法定代表人、注册资本、经营范围等。
* 股东信息：了解公司的所有权结构，识别主要股东及其持股比例。
* 财务信息：虽然财务信息通常较为敏感，通过公开渠道获取部分财务报告。
* 法律状态：包括公司的法律诉讼记录、行政处罚记录等。
* 技术信息：使用的软件、硬件和服务提供商等，这些信息有助于识别可能的技术漏洞。
* 域名信息：包括主域名、子域名、旁站等信息。
* 网络信息：包括IP地址、开放端口、网络设备等。
* 系统信息：操作系统版本、中间件信息、服务器配置等。
* 联系电话/电子邮箱：联系信息可用于社会工程学攻击或钓鱼测试。


### 4\.2 信息收集的方法


#### 4\.2\.1 被动信息收集


被动信息收集是在不与目标系统直接交互的情况下，通过公开渠道获取目标系统的相关信息。


* 常用的方法包括：搜索引擎：使用Google、Bing等搜索引擎查找与目标企业相关的信息。
* 网络空间搜索引擎：使用FOFA、Shodan、ZoomEye等工具搜索互联网上的设备和服务。
* Whois查询：通过Whois查询获取域名注册信息。
* 备案信息查询：通过ICP备案查询网站获取目标网站的备案信息。
* 社交媒体和专业网络：在LinkedIn、微博等平台上搜索目标公司的员工信息
* 企查查、天眼查、启信宝：这些平台提供全面的企业信息查询服务
* 国家企业信用信息公示系统：查询相关信息
* 地方工商局网站：部分地区工商局网站提供更详细的企业信息。
* 证券交易所网站：上市公司会在证券交易所网站发布年报、公告等信息。
* 内部群：姓名、职位、联系 方式、地址、邮箱、合作企业（包括社工）


### 4\.3 收集的信息整理


#### 4\.3\.1 基本信息整理


* 企业基本信息：名称、地址、联系方式等。
* 网络基础设施：IP地址、子网掩码、域名、开放端口、服务等。
* 技术信息：使用的软件、硬件、框架、版本号等。
* 员工信息：关键人员的名字、职位、联系信息等。
* 社会工程学信息：员工的习惯、社交账号、可能的社会工程学入口点等。
* 财务及法律信息：财务状况、法律纠纷等。
* 公开文档：报告、手册、白皮书等。


#### 4\.3\.2 详细标注


* 标签：为每条信息加上标签。
* 注释：对信息来源、收集时间和可信度等进行标注。


## 0x05 从软件收集web信息


### 5\.1 app信息收集


#### 5\.1\.2 反编译


先反编译查看源代码或者其他信息


#### 5\.1\.3AppInfoScanner使用


1. 运行(基础版)


* 扫描Android应用的APK文件、DEX文件、需要下载的APK文件下载地址、保存需要扫描的文件的目录



```
    python app.py android -i 文件地址（包括网络地址 ）

```

* 扫描iOS应用的IPA文件、Mach\-o文件、需要下载的IPA文件下载地址、保存需要扫描的文件目录



```
    python app.py ios -i 文件地址（包括网络地址 ）

```

* 扫描Web站点的文件、目录、需要缓存的站点URl



```
    python app.py web -i 文件地址（包括网络地址 ）

```

参数说明：



```
python app.py android -i :

对本地apk进行扫描
对url中包含的apk文件进行扫描
对本地url站点包括本地web和url包含站点进行扫描
-r
添加临时规则（关键字）
-s
关闭网络嗅探
-n
忽略所有的资源文件
-t
设置并发数量
-o
指定结果集或者文件输出目录
-p
对指定包名下的文件内容进行扫描只能是Android


```

### 5\.2 exe收集web信息


#### 5\.2\.1 应用基本信息收集


* 软件官网：访问软件官方网站，获取软件的版本信息、更新日志、用户手册等。
* 开发者信息：查找开发者或发行商的相关信息，了解他们是否有其他的软件产品或Web服务。
* 许可证和注册信息：如果软件需要许可证密钥，尝试获取相关信息。


#### 5\.2\.1 逆向工程与代码分析


* 反编译：使用 IDA Pro、Ghidra 或 OllyDbg 等工具反编译 .exe 文件，分析其内部逻辑。
* 字符串提取：使用 strings.exe 或类似工具从 .exe 文件中提取字符串，寻找可能指向 Web 服务的 URL 或 IP 地址。
* 依赖库：检查 .exe 文件所依赖的库文件，如 DLLs，分析它们的功能。


#### 5\.2\.3 网络通信分析


* 抓包工具：使用诸如 Wireshark、Fiddler、Burp Suite 或 Charles Proxy 这样的工具来拦截并分析应用程序与 Web 服务之间的通信。
* HTTPS 流量：确认应用程序是否使用了 HTTPS 协议，以及 SSL/TLS 版本和加密套件。
* API 端点：识别应用程序调用的 API 端点，分析请求方法、参数、响应格式等


## 0x06 工具信息收集


### 6\.1 finger



```
python finger.py -参数

```

finger追求极简命令参数只有以下几个:


* \-u 对单个URL进行指纹识别
* \-f 对指定文件中的url进行批量指纹识别
* \-i 对ip进行fofa数据查询采集其web资产
* \-if 对指定文件中的ip批量调用fofa进行数据查询采集其web资产
* \-fofa 调用fofa api进行资产收集
* \-quake 调用360 quake进行资产收集
* \-o 指定输出方式默认不选择的话是xlsx格式，支持json，xls。


### 6\.2 shuize(水泽)




| 语法 | 功能 |
| --- | --- |
| python3 ShuiZe.py \-d domain.com | 收集单一的根域名资产 |
| python3 ShuiZe.py \-\-domainFile domain.txt | 批量跑根域名列表 |
| python3 ShuiZe.py \-c 192\.168\.1\.0,192\.168\.2\.0,192\.168\.3\.0 | 收集C段资产 |
| python3 ShuiZe.py \-f url.txt | 对url里的网站漏洞检测 |
| python3 ShuiZe.py \-\-fofaTitle XXX大学 | 从fofa里收集标题为XXX大学的资产，然后漏洞检测 |
| python3 ShuiZe.py \-d domain.com \-\-justInfoGather 1 | 仅信息收集，不检测漏洞 |
| python3 ShuiZe.py \-d domain.com \-\-ksubdomain 0 | 不调用ksubdomain爆破子域名 |


### 6\.3 kunyu


命令



```
-info 查询用户信息
-searchhost  搜所host资产
-searchweb  搜索web资产
-seerchlcon <本地文件/远程文件地址>
-Seebug Thinkphp 查看thinkphp的漏洞历史


```

### 6\.4 灯塔（ARL）


* 域名资产发现和整理
* IP/IP 段资产整理
* 端口扫描和服务识别
* WEB 站点指纹识别
* 资产分组管理和搜索
* 任务策略配置
* 计划任务和周期任务
* Github 关键字监控
* 域名/IP 资产监控
* 站点变化监控
* 文件泄漏等风险检测
* nuclei PoC 调用
* [WebInfoHunter](https://github.com) 调用和监控


## 0x07 信息识别


### 7\.1 障碍


#### 7\.1\.1 常见阻碍


* 超级ping
* WAF:看图识别、wafw00f、waf在线识别
* 负载均衡：cdn
* 防火墙：系统自带、且还有外部物理防火墙，部分nmap可以识别


#### 7\.1\.2 CDN


##### 7\.1\.2\.1 cdn判断


* 超级ping 判断有无CDN
* 看网速响应：视频、图片文件
* 还可以使用Windows命令查询：nslookup，若目标存在多个IP的话，就很有可能有CDN服务
* 使用工具查询，工具地址如下
CDN Planet：[https://www.cdnplanet.com/tools/cdnfinder/](https://github.com)


##### 7\.1\.2\.2 CDN配置


* 腾讯云：[内容分发网络 CDN 从零开始配置 CDN\-快速入门\-文档中心\-腾讯云 (tencent.com)](https://github.com):[milou加速器](https://jiechuangmoxing.com)
* 阿里云：[新手指引\_CDN(CDN)\-阿里云帮助中心 (aliyun.com)](https://github.com)


##### 7\.1\.2\.3 CDN绕过


* 子域名


子域名查询：


在一些网站中有可能只加速了主站，而一些其它子域名和主站在同一个C段或者同服务器


利用子域名查询工具：



```
http://tool.chinaz.com/subdomain/
http://i.links.cn/subdomain/    
http://subdomain.chaxun.la/
http://searchdns.netcraft.com/
https://www.virustotal.com/
https://x.threatbook.com/v5/mapping
https://ip138.com 

```
* 国外访问


一些CDN只加速了部分地区，那么在为加速地区的访问就是真实的主机ip


可以利用在线工具进行超级ping来查看ip，如：



```
ipip在线工具
itdog在线工具
https://www.webpagetest.org/
https://dnscheck.pingdom.com/

```
* 邮件访问


在进行邮件发送时邮件的内容源码里面包含了主机的真实IP
* 主动连接漏洞：xss ssrf


通过漏洞来主动连接时，
* 遗留文件


在网站搭建时候的测试网站在许多时候会有测试文件，比如说phpinfo.php文件
* 查看DNS历史


在CDN服务启动以前他的真实ip可能被DNS服务记录到，那么此时它的DNS历史中可能存在主机真实ip



```
https://www.itdog.cn/dns/
https://x.threatbook.com/
https://site.ip138.com/

```
* 工具


筛选：当查找出来有相似ip时可以用工具来筛选


工具查找：


在线工具：



```
https://get-site-ip.com/

```
* 本地工具：


zmap



```
下载：https://github.com/zmap/zmap
教程：https://linux.cn/article-5860-1.html

```

fuckcdn


w8Fuckcd
* 后续操作：
更改 host文件绑定IP 指定访问


#### 7\.1\.3 waf


##### 7\.1\.3\.1 waf分类


* 云waf
* 硬件waf
* 软件waf
* 其他waf


##### 7\.1\.3\.2 namp识别WAF



```
nmap -p 80,443 --script=http-waf-detect <目标网址或IP>
nmap -p 80,443 --script=http-waf-fingerprint <目标网址或IP>

```

##### 7\.1\.3\.3 wafwoof识别waf


nmap默认有19个指纹，sqlmap默认有94个指纹，wafw00f默认有155个指纹



```
wafw00f [url]
-h, --help 显示此帮助消息并退出
-v, --verbose 启用详细程度-多个-v选项可增加详细程度
-a, --findall 检测所有的Waf，不会在检测到第一个Waf的时候停止
-r, --disableredirect 不要遵循3xx响应给出的重定向
-t TEST, --test=TEST 测试一个特定的WAF
-l, --list 列出我们能够检测到的所有WAF
-p PROXY, --proxy=PROXY
使用HTTP代理执行请求，例如：http://hostname:8080, socks5://hostname:1080
-V, --version 输出版本信息
-H HEADERSFILE, --headersfile=HEADERSFILE
传递自定义标头，例如覆盖默认的User-Agent字符串

```

##### 7\.1\.4\.4 看图识别


拦截页面来识别waf


### 7\.2 综合信息


#### 7\.2\.2 基础信息


域名信息：包括主域名和所有相关的子域名。
IP 地址：目标系统的公网 IP 地址。
物理位置：了解目标的地理位置可以帮助识别潜在的物理安全风险。


#### 7\.2\.2 网络基础设施


网络架构：了解目标网络的整体布局，包括内部网络结构、防火墙配置等。
开放端口：扫描目标系统上开放的所有端口。
服务版本：识别目标系统提供的服务及其版本号，这有助于发现已知漏洞。
操作系统：确定目标系统使用的操作系统类型和版本。
中间件：识别使用中的 Web 服务器、数据库服务器等中间件。


#### 7\.2\.3 应用程序信息


Web 应用程序：收集目标网站的 URL、使用的编程语言、框架等信息。
CMS 指纹：识别目标是否使用了 CMS（如 WordPress、Drupal 等）及其版本。
Web 框架：识别使用的 Web 开发框架（如 Django、Ruby on Rails 等）。
API 端点：发现 API 端点并尝试理解其功能。


#### 7\.1\.4 敏感信息


数据库信息：尝试发现数据库文件或配置文件的位置，如 database.ini 或 .env 文件。
备份文件：查找可能存在的备份文件或目录。
配置文件：寻找可能暴露的配置文件，这些文件可能包含用户名、密码等敏感信息。
敏感文件：如 .gitignore 文件，可能透露项目的结构或其他敏感信息。


#### 7\.2\.5 目录和服务信息


目录列表：尝试列出网站的目录结构。
敏感目录：寻找可能包含敏感信息的目录，如 /admin、/login 等。
未授权访问：查找可能存在未授权访问的 URL 或文件。


#### 7\.2\.6 社会工程


员工信息：通过社交媒体（如 LinkedIn）了解员工的角色和责任。
组织结构：了解公司的组织结构，包括部门设置、员工分工等。
供应链信息：识别目标企业的合作伙伴、供应商等。


#### 7\.2\.7 其他信息


历史漏洞：检查 CVE 数据库，了解目标系统是否有已知的安全漏洞。
证书信息：收集 SSL/TLS 证书信息，了解证书的有效期、颁发机构等。
电子邮件信息：通过邮件头信息来获取邮件服务器的 IP 地址等。
社交媒体账户：了解目标组织的官方社交媒体账户。



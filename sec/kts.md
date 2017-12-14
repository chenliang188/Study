# Kali tools summary

## Information Gathering - 信息收集
 
- acccheck:该工具基于SMB协议用来暴力破解Windows，它是根据smbClient这个二进制文件来构造的一小段代码，所以只对运行有smbClient这个文件的计算机终端上才有用 

  >The tool is designed as a password dictionary attack tool that targets windows authentication via the SMB protocol. It is really a wrapper script around the ‘smbclient’ binary, and as a result is dependent on it for its execution.

- ace-voip:ACE(Automated Corporate Enumerator)(自动化穷举工具）是一个简单但是很强大的工具，它可以模拟一个IP电话来得到目标IP电话的主人的姓名以及一些其他的信息。而VOIP的"Corporate Directory"特性可以让VOIP终端用户通过姓名直接呼叫到其VOIP手机。ACE这个工具就是让攻击者可以穷举列出"Corporate Directory"，这样进行攻击的时候就不仅仅是面对任意的IP地址或者一个声音片段了，而是知道了这个人的名字！ACE可以通过DHCP协议、TFTP协议、HTTP协议进行工作（下载 VOIP Corporate Directory),并输出为一个文本文档
  >ACE (Automated Corporate Enumerator) is a simple yet powerful VoIP Corporate Directory enumeration tool that mimics the behavior of an IP Phone in order to download the name and extension entries that a given phone can display on its screen interface. In the same way that the “corporate directory” feature of VoIP hardphones enables users to easily dial by name via their VoIP handsets, ACE was developed as a research idea born from “VoIP Hopper” to automate VoIP attacks that can be targeted against names in an enterprise Directory. The concept is that in the future, attacks will be carried out against users based on their name, rather than targeting VoIP traffic against random RTP audio streams or IP addresses. ACE works by using DHCP, TFTP, and HTTP in order to download the VoIP corporate directory. It then outputs the directory to a text file, which can be used as input to other VoIP assessment tools.

- Amap:Amap识别网络应用所使用的协议Amap。Amap是Kali Linux自带的一款信息收集工具。工作时，它首先向服务器的端口发送内置的触发包（tirgger），然后获取响应。通过分析响应包数据，来识别该端口的网络应用所使用的协议。由于它不通过端口号判断协议，所以即使该应用使用的是非标准端口，也不会被误导。这项功能类似于Nmap的-sV功能，但优点是Amap完全支持IPv6。

  >Amap was the first next-generation scanning tool for pentesters. It attempts to identify applications even if they are running on a different port than normal.
  
  >It also identifies non-ascii based applications. This is achieved by sending trigger packets, and looking up the responses in a list of response strings.

- arp-scan:arp-scan是一个用来进行系统发现的命令行工具。它可以构建并发送ARP请求到指定的IP地址，并且显示返回的任何响应。arp-scan可以显示本地网络中的所有连接的设备，即使这些设备有防火墙。设备可以屏蔽ping，但是并不能屏蔽ARP数据包。
  >地址解析协议，即ARP（Address Resolution Protocol），是根据IP地址获取物理地址的一个TCP/IP协议。主机发送信息时将包含目标IP地址的ARP请求广播到网络上的所有主机，并接收返回消息，以此确定目标的物理地址；收到返回消息后将该IP地址和物理地址存入本机ARP缓存中并保留一定时间，下次请求时直接查询ARP缓存以节约资源。地址解析协议是建立在网络中各个主机互相信任的基础上的，网络上的主机可以自主发送ARP应答消息，其他主机收到应答报文时不会检测该报文的真实性就会将其记入本机ARP缓存；由此攻击者就可以向某一主机发送伪ARP应答报文，使其发送的信息无法到达预期的主机或到达错误的主机，这就构成了一个ARP欺骗。ARP命令可用于查询本机ARP缓存中IP地址和MAC地址的对应关系、添加或删除静态对应关系等。相关协议有RARP、代理ARP。NDP用于在IPv6中代替地址解析协议。

- Automater:公共资源情报（OSINT）就是从公共信息中提取有用情报。它是美国中央情报局（CIA）的一种情报搜集手段，各国都在广泛利用这种方式。Kali Linux提供的Automater工具主要分析网址、IP和Md5哈希值。当用户输入要查询的信息，该工具就会到指定的几个网站进行搜索，然后反馈给用户。例如，输入一个IP地址，它反馈该IP对应国家/城市信息、经纬值、对应网站等信息。信息不一定全面，但往往会带来一些意外的信息。
  >Automater is a URL/Domain, IP Address, and Md5 Hash OSINT tool aimed at making the analysis process easier for intrusion Analysts. Given a target (URL, IP, or HASH) or a file full of targets Automater will return relevant results from sources like the following: IPvoid.com, Robtex.com, Fortiguard.com, unshorten.me, Urlvoid.com, Labs.alienvault.com, ThreatExpert, VxVault, and VirusTotal.

- bing-ip2hosts: 是一款利用微软开发的Bing搜索引擎来获取已知IP地址的相关信息的工具
  >Bing.com is a search engine owned by Microsoft formerly known as MSN Search and Live Search. It has a unique feature to search for websites hosted on a specific IP address. Bing-ip2hosts uses this feature to enumerate all hostnames which Bing has indexed for a specific IP address. This technique is considered best practice during the reconnaissance phase of a penetration test in order to discover a larger potential attack surface. Bing-ip2hosts is written in the Bash scripting language for Linux. This uses the mobile interface and no API key is required.

- braa:SNMP高速扫描器braa。SNMP（Simple Network Monitoring Protocol，简单网络管理协议）是网络设备管理标准协议。为了便于设备管理，现在联入网络的智能设备都支持该协议，并默认开启，如网络摄像头、网络打印机等。在大型网络中，测试人员为了快速了解网络设备信息，都会利用SNMP协议。在我们教程Kali Linux安全渗透教程新手版中，就讲解到SNMP枚举工具snmpwalk和snmpcheck。而braa是Kali提供的另外一款SNMP扫描工具。它支持大批量、高速扫描网络现有开启SNMP服务的设备，并可以批量修改SNMP对应的值。在使用的时候需要使用OID（对象标识符/物联网域名）指代目标值。
  >Braa is a mass snmp scanner. The intended usage of such a tool is of course making SNMP queries – but unlike snmpget or snmpwalk from net-snmp, it is able to query dozens or hundreds of hosts simultaneously, and in a single process. Thus, it consumes very few system resources and does the scanning VERY fast.

  Braa implements its OWN snmp stack, so it does NOT need any SNMP libraries like net-snmp. The implementation is very dirty, supports only several data types, and in any case cannot be stated ‘standard-conforming’! It was designed to be fast, and it is fast. For this reason (well, and also because of my laziness ;), there is no ASN.1 parser in braa – you HAVE to know the numerical values of OID’s (for instance .1.3.6.1.2.1.1.5.0 instead of system.sysName.0).

- CaseFile:收集及报告信息关系可视化关系分析工具,CaseFile是Maltego的姊妹工具，功能非常类似于Maltego。CaseFile主要针对数据进行离线分析，缺少Maltego的数据采集功能。它可以导入各类数据，包括Maltego导出的数据。用户可以为信息添加连接线、标签和注释，标记数据的关系。CaseFile以图形化的方式展现数据，方便分析人员找出隐含的数据关系。

  >CaseFile is the little brother to Maltego. It targets a unique market of ‘offline’ analysts whose primary sources of information are not gained from the open-source intelligence side or can be programmatically queried. We see these people as investigators and analysts who are working ‘on the ground’, getting intelligence from other people in the team and building up an information map of their investigation.

  >CaseFile gives you the ability to quickly add, link and analyze data having the same graphing flexibility and performance as Maltego without the use of transforms. CaseFile is roughly a third of the price of Maltego.

  >What does CaseFile do?

  >CaseFile is a visual intelligence application that can be used to determine the relationships and real world links between hundreds of different types of information.
  >It gives you the ability to quickly view second, third and n-th order relationships and find links otherwise undiscoverable with other types of intelligence tools.
  >CaseFile comes bundled with many different types of entities that are commonly used in investigations allowing you to act quickly and efficiently. CaseFile also has the ability to add custom entity types allowing you to extend the product to your own data sets.

  >What can CaseFile do for me?

  >CaseFile can be used for the information gathering, analytics and intelligence phases of almost all types of investigates, from IT Security, Law enforcement and any data driven work. It will save you time and will allow you to work more accurately and smarter.
  >CaseFile has the ability to visualise datasets stored in CSV, XLS and XLSX spreadsheet formats.
  >We are not marketing people. Sorry.
  >CaseFile aids you in your thinking process by visually demonstrating interconnected links between searched items.
  >If access to “hidden” information determines your success, CaseFile can help you discover it.

- CDPSnarf:目前安全研究人员更多关注系统和应用层面的漏洞，关注低层协议漏洞的人寥寥无几，甚至是知之甚少。虽然其中深层原因比较复杂，我不想过多评论，但这一现状对安全业界而言，多少还是令我有些吃惊的。在每个人都大谈攻击面的当下，居然大家都选择性忽视了那么重要的一个短板。cdpsnarf是专门针对二层的思科发现协议的信息收集工具，通过它可以被动收集思科设备的系统版本信息等，为后续渗透提供可选择的路径。此工具本身虽然功能简单，但要想正确使用，你必须对CDP协议原理具有基本的了解，同时这对日后的CDP欺骗攻击也是必备的基础。本次内容，我结合GNS3模拟器生成思科路由器，现场抓包分析CDP协议数据包。
  >CDPSnarf is a network sniffer exclusively written to extract information from CDP packets.
  >It provides all the information a “show cdp neighbors detail” command would return on a Cisco router and even more.

  >A feature list follows:
    - Time intervals between CDP advertisements
    - Source MAC address
    - CDP Version
    - TTL
    - Checksum
    - Device ID
    - Software version
    - Platform
    - Addresses
    - Port ID
    - Capabilities
    - Duplex
    - Save packets in PCAP dump file format
    - Read packets from PCAP dump files
    - Debugging information (using the “-d” flag)
    - Tested with IPv4 and IPv6
- cisco-torch:Cisco Torch 是一款集成扫描、电子指纹识别、漏洞利用的针对Cisco设备的强大工具。它可以多线程在后台进行扫描，效率非常高，另外，它的扫描是在多个协议层的，可以发现在网络中运行有Telnet、SSH、Web、NEP和SNMP服务的Cisco设备，并可以根据其开启的服务进行攻击。Cisco路由器安全扫描器，用于检测使用默认telnet/enable密码的Cisco设备。
  >Cisco Torch mass scanning, fingerprinting, and exploitation tool was written while working on the next edition of the “Hacking Exposed Cisco Networks”, since the tools available on the market could not meet our needs.

  >The main feature that makes Cisco-torch different from similar tools is the extensive use of forking to launch multiple scanning processes on the background for maximum scanning efficiency. Also, it uses several methods of application layer fingerprinting simultaneously, if needed. We wanted something fast to discover remote Cisco hosts running Telnet, SSH, Web, NTP and SNMP services and launch dictionary attacks against the services discovered.
- Cookie Cadger:对不安全GET请求确认信息泄露工具,Cookie cadger是一款用Java写的抓包工具，你在windows系统上也可以用它。
  >Cookie Cadger helps identify information leakage from applications that utilize insecure HTTP GET requests.

  >Web providers have started stepping up to the plate since Firesheep was released in 2010. Today, most major websites can provide SSL/TLS during all transactions, preventing cookie data from leaking over wired Ethernet or insecure Wi-Fi. But the fact remains that Firesheep was more of a toy than a tool. Cookie Cadger is the first open-source pen-testing tool ever made for intercepting and replaying specific insecure HTTP GET requests into a browser.

  >Cookie Cadgers Request Enumeration Abilities

  >Cookie Cadger is a graphical utility which harnesses the power of the Wireshark suite and Java to provide a fully cross-platform, entirely open- source utility which can monitor wired Ethernet, insecure Wi-Fi, or load a packet capture file for offline analysis.
- copy-router-config:利用SNMP协议从思科设备上copy配置信息
  >Copies configuration files from Cisco devices running SNMP.
- DMitry:Dmitry是一个由C语言编写的UNIX/(GNU)Linux命令行工具，它可用于收集主机相关信息，比如子域名、Email地址、系统运行时间信息。
  >DMitry (Deepmagic Information Gathering Tool) is a UNIX/(GNU)Linux Command Line Application coded in C. DMitry has the ability to gather as much information as possible about a host. Base functionality is able to gather possible subdomains, email addresses, uptime information, tcp port scan, whois lookups, and more.

  >The following is a list of the current features:

    - An Open Source Project.
    - Perform an Internet Number whois lookup.
    - Retrieve possible uptime data, system and server data.
    - Perform a SubDomain search on a target host.
    - Perform an E-Mail address search on a target host.
    - Perform a TCP Portscan on the host target.
    - A Modular program allowing user specified modules
- dnmap:DNmap是一款基于Nmap的分布式框架，使用客户端/服务端架构，服务器接收命令并发送至客户端进行Nmap安全扫描，扫描完毕后，客户端返回扫描结果。
  >dnmap is a framework to distribute nmap scans among several clients. It reads an already created file with nmap commands and send those commands to each client connected to it.

  >The framework use a client/server architecture. The server knows what to do and the clients do it. All the logic and statistics are managed in the server. Nmap output is stored on both server and client.

  >Usually you would want this if you have to scan a large group of hosts and you have several different internet connections (or friends that want to help you).
- dnsenum：dnsenum 是一款非常强大的 域名信息收集工具，它是由参与backtrack 开发项目的程序员所设计，设计者名叫Fillp (barbsie) Waeythens ，该名开发者是一个精通web渗透测试的安全人员，并对DNS信息收集有着非常丰富的经验。dnsenum的目的是尽可能收集一个域的信息，它能够通过谷歌或者字典文件猜测可能存在的域名，以及对一个网段进行反向查询。它可以查询网站的主机地址信息、域名服务器、mx record（函件交换记录），在域名服务器上执行axfr请求，通过谷歌脚本得到扩展域名信息（google hacking），提取自域名并查询，计算C类地址并执行whois查询，执行反向查询，把地址段写入文件。
  >Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.

  >OPERATIONS:

    - Get the host’s addresse (A record).
    - Get the namservers (threaded).
    - Get the MX record (threaded).
    - Perform axfr queries on nameservers and get BIND VERSION (threaded).
    - Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
    - Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
    - Calculate C class domain network ranges and perform whois queries on them (threaded).
    - Perform reverse lookups on netranges ( C class or/and whois netranges) (threaded).
    - Write to domain_ips.txt file ip-blocks.
- dnsmap:渗透测试工作的起点几乎都始于一个域名，如何通过一个平平无奇的域名，去发现目标机构的所有活动主机、开放端口、应用服务，乃至整个潜在的攻击面，这是渗透测试信息收集阶段最关键的任务之一。dnsmap是一个功能专一的域名信息收集工具，它基于字典对目标域名进行主机和子域名的爆破，虽然缺乏丰富的功能特性支持，但dnsmap一直以其稳定快速的运行效果，证明自己是一款优秀的信息收集工具。

  >dnsmap was originally released back in 2006 and was inspired by the fictional story “The Thief No One Saw” by Paul Craig, which can be found in the book “Stealing the Network – How to 0wn the Box”.

  >dnsmap is mainly meant to be used by pentesters during the information gathering/enumeration phase of infrastructure security assessments. During the enumeration stage, the security consultant would typically discover the target company’s IP netblocks, domain names, phone numbers, etc …

  >Subdomain brute-forcing is another technique that should be used in the enumeration stage, as it’s especially useful when other domain enumeration techniques such as zone transfers don’t work (I rarely see zone transfers being publicly allowed these days by the way).
- DNSRecon:对于一个网站来说，主域名对应的网站往往是防护最好的。而二级域名之类的子域名往往存在防护的弱点。而主域名和二级域名往往存在共有的设置。获取二级域名对应站点的权限，往往有助于主站的渗透测试。所以，检查一个网站的安全，需要获取该域名所有的子域名和对应的站点。Kali Linux提供的DNSRecon工具提供丰富的域名扫描功能，能获取多种域名相关信息。其中的一项功能就是支持字典方式暴力破解子域名。PS1：分析经典工具的好处，就是知道大神都在用什么功能，做哪些工作。PS2：经典工具时不时会带来一些额外的惊喜。该工具的GitHub代码托管（https://github.com/darkoperator/dnsrecon）提供最常用的20000和5000个子域名列表文件。
  >DNSRecon provides the ability to perform:

    - Check all NS Records for Zone Transfers
    - Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT)
    - Perform common SRV Record Enumeration. Top Level Domain (TLD) Expansion
    - Check for Wildcard Resolution
    - Brute Force subdomain and host A and AAAA records given a domain and a wordlist
    - Perform a PTR Record lookup for a given IP Range or CIDR
    - Check a DNS Server Cached records for A, AAAA and CNAME Records provided a list of host records in a text file to check
    - Enumerate Common mDNS records in the Local Network Enumerate Hosts and Subdomains using Google

- dnstracer:dnstracer用于获取给定主机名从给定域名服务器（DNS）的信息，并跟随DNS服务器链得到权威结果。DNS解析分为递归查询和迭代查询两种类型，通常从客户端到本地缓存服务器之间只有递归查询，因此在DNS完整的树形结构中，我们从客户端是很难看到整个域名解析的迭代过程，这在发生DNS域名劫持时，会给工程师分析问题带来了不小的麻烦。但dnstracer等工具的出现弥补了这个不足，它使普通PC用户也可以从DNS的根服务器开始，逐级解析每一级域名的查询过程，从而发现每一个域名服务器是否已被劫持。2014年曾发生com域名服务器被劫持的事件，导致国内用户长达数周无法访问微软、苹果等国外站点，这时dnstracer将可以快速为你定位问题。
  >dnstracer determines where a given Domain Name Server (DNS) gets its information from for a given hostname, and follows the chain of DNS servers back to the authoritative answer.
- dnswalk:：利用DNS区域传送漏洞,可以快速的判定出某个特定zone的所有主机，收集域信息，选择攻击目标，找出未使用的IP地址，黑客可以绕过基于网络的访问控制。dnswalk大概算不上一个常规渗透测试场景下会用到的工具，它更多的是被安全工程师和审计人员所使用，它的功能是用于检查DNS区域文件配置中的错误和问题，从而避免因DNS服务器配置不当，而造成的功能、性能以及安全性的问题。其具体工作过程基于区域传输来获得区域文件，并对其实施检查，因此axfr是其能够正常工作的前提条件。
  >dnswalk is a DNS debugger. It performs zone transfers of specified domains, and checks the database in numerous ways for internal consistency, as well as accuracy.
- DotDotPwn: dotdotpwn是一款模糊判断工具，它可以发现目标系统潜在的风险目录。目标系统可以是HTTP网站，也可以是FTP、TFTP服务器。该工具内置常见的风险目录和文件名，用户只需要指定目标系统，就可以自动遍历获取目标的目录结构。该工具非常适合具有LFI（本地包含）漏洞的网站。DotDotPwn是一个非常灵活的智能模糊器，用于发现软件中的遍历目录漏洞，例如HTTP/FTP/TFTP服务器，Web平台的应用程序（如CMS，ERP，博客等）。此外，它有一个独立于协议的模块，用于将所需的有效负载发送到指定的主机和端口。 另一方面，它也可以使用STDOUT模块以脚本方式使用。DotDotPwn是用perl编程语言编写的，可以在* NIX或Windows平台下运行，它是BackTrack Linux（BT4 R2）中包含的第一个墨西哥人开发的工具。此版本支持的模糊模块：HTTP HTTP URL FTP TFTP Payload (Protocol independent) STDOUT 


  >It’s a very flexible intelligent fuzzer to discover traversal directory vulnerabilities in software such as HTTP/FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs, etc.

  >Also, it has a protocol-independent module to send the desired payload to the host and port specified. On the other hand, it also could be used in a scripting way using the STDOUT module.

  >It’s written in perl programming language and can be run either under *NIX or Windows platforms. It’s the first Mexican tool included in BackTrack Linux (BT4 R2).

  >Fuzzing modules supported in this version:

    - HTTP
    - HTTP URL
    - FTP
    - TFTP
    - Payload (Protocol independent)
    - STDOUT
- enum4linux:enum.exe的Linux替代软件，用于枚举Windows和Samba主机中的数据。Enum4linux是一个用于枚举来自Windows和Samba系统的信息的工具。 它试图提供与以前从www.bindview.com可用的enum.exe类似的功能。  它是用Perl编写的，基本上是一个包装Samba工具smbclient，rpclient，net和nmblookup。  主要特性：RID循环（当Windows 2000上的RestrictAnonymous设置为1时） 用户列表（当Windows 2000上的RestrictAnonymous设置为0时） 组成员信息列表 共享枚举 检测主机是否在工作组或域中 识别远程操作系统 密码策略检索（使用polenum）
  >A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts.

  >Overview:

  >Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com.

  >It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.

  >The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.

  >Key features:

    - RID cycling (When RestrictAnonymous is set to 1 on Windows 2000)
    - User listing (When RestrictAnonymous is set to 0 on Windows 2000)
    - Listing of group membership information
    - Share enumeration
    - Detecting if host is in a workgroup or a domain
    - Identifying the remote operating system
    - Password policy retrieval (using polenum)
- enumIAX:Asterisk Exchange protocol暴力破解工具
  >enumIAX is an Inter Asterisk Exchange protocol username brute-force enumerator. enumIAX may operate in two distinct modes; Sequential Username Guessing or Dictionary Attack.
- EyeWitness:网站截图工具EyeWitness。在网页分析和取证中，往往需要大批量的网站截图。Kali Linux提供了一款网站批量截图工具EyeWitness。该工具不仅支持网址列表文件，还支持Nmap和Nessus报告文件。在Web请求的时候，测试人员可以指定不同的UA，并进行循环访问，以获取不同平台的网页显示效果。对于非标准Web端口，用户也可以额外批量添加端口。同时，该工具还支持对RDP、VNC服务进行截图。
  >EyeWitness is designed to take screenshots of websites, RDP services, and open VNC servers, provide some server header info, and identify default credentials if possible.
- Faraday:渗透测试集成环境Faraday,Kali Linux集成了海量的渗透测试工具。但是这些工具在使用的时候，还是分离的。虽然用户可以通过Shell、日志/报告导入导出功能等方式，进行整合，但是仍然不便于分析。Faraday提出了IPE（Integrated Penetration Environment，渗透测试集成环境）的概念。它是一款类似编程IDE的工具，他将大量的工具整合在一起。用户只需要在内置的终端进行操作，Faraday就会分析执行结果，自动进行整合，便于用户进行分析。在该软件的商业版本中，渗透测试还可以进行多人协作，共用扫描结果和分析报告，避免成员之间的重复工作。
 
  >Faraday introduces a new concept – IPE (Integrated Penetration-Test Environment) a multiuser Penetration test IDE. Designed for distribution, indexation and analysis of the data generated during a security audit.

  >The main purpose of Faraday is to re-use the available tools in the community to take advantage of them in a multiuser way.

  >Designed for simplicity, users should notice no difference between their own terminal application and the one included in Faraday. Developed with a specialized set of functionalities that help users improve their own work. Do you remember yourself programming without an IDE? Well, Faraday does the same as an IDE does for you when programming, but from the perspective of a penetration test.
- Fierce:Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains.该工具是一个域名扫描综合性工具。它可以快速获取指定域名的DNS服务器，并检查是否存在区域传输（Zone Transfer）漏洞。如果不存在该漏洞，会自动执行暴力破解，以获取子域名信息。对获取的IP地址，它还会遍历周边IP地址，以获取更多的信息。最后，还会将IP地址进行分段统计，以便于后期其他工具扫描，如NMAP。
  > Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains.  It's really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for.  This does not perform exploitation and does not scan the whole internet indiscriminately.  It is meant specifically to locate likely targets both inside and outside a corporate network.  Because it uses DNS primarily you will often find mis-configured networks that leak internal address space. That's especially useful in targeted malware.
- Firewalk（need Test）：Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a given IP forwarding device will pass.Firewalk使用类似traceroute的技术来分析IP包的响应，从而测定网关的访问控制列表和绘制网络图的工具。Firewalk使用类似于路由跟踪(traceroute-like)的IP数据包分析方法，来测定一个特殊的数据包是否能够从攻击者的主机传送到位于数据包过滤设备后的目标主机。这种技术能够用于探测网关上打开(‘open’)或允许通过(‘pass through’)的端口。更进一步地，它能够测定带有各种控制信息的数据包是否能通过给定网关
  >Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a given IP forwarding device will pass. Firewalk works by sending out TCP or UDP packets with a TTL one greater than the targeted gateway. If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED message. If the gateway hostdoes not allow the traffic, it will likely drop the packets on the floor and we will see no response.

  >To get the correct IP TTL that will result in expired packets one beyond the gateway we need to ramp up hop-counts. We do this in the same manner that traceroute works. Once we have the gateway hopcount (at that point the scan is said to be `bound`) we can begin our scan.

  >It is significant to note the fact that the ultimate destination host does not have to be reached. It just needs to be somewhere downstream, on the other side of the gateway, from the scanning host.
- fragroute:能够截取、修改和重写向外发送的报文，实现大部分在了Secure Networks Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection中叙述的IDS欺骗绕过技术，包括IP、TCP层的数据包碎片以及数据包数据重叠等。
  >fragroute intercepts, modifies, and rewrites egress traffic destined for a specified host, implementing most of the attacks described in the Secure Networks “Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection” paper of January 1998.

  >It features a simple ruleset language to delay, duplicate, drop, fragment, overlap, print, reorder, segment, source-route, or otherwise monkey with all outbound packets destined for a target host, with minimal support for randomized or probabilistic behaviour.

  >This tool was written in good faith to aid in the testing of network intrusion detection systems, firewalls, and basic TCP/IP stack behaviour. Please do not abuse this software.
- fragrouter
  >Fragrouter is a network intrusion detection evasion toolkit. It implements most of the attacks described in the Secure Networks “Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection” paper of January 1998.

  >This program was written in the hopes that a more precise testing methodology might be applied to the area of network intrusion detection, which is still a black art at best.

  >Conceptually, fragrouter is just a one-way fragmenting router – IP packets get sent from the attacker to the fragrouter, which transforms them into a fragmented data stream to forward to the victim.
- Ghost Phisher:无线网或者以太网安全评估和攻击软件-伪造服务钓鱼工具Ghost Phisher是一款支持有线网络和无线网络的安全审计工具。它通过伪造服务的方式，来收集网络中的有用信息。它不仅可以伪造AP，还可以伪造DNS服务、DHCP服务、HTTP服务。同时，它还可以构建陷阱，进行会话劫持、ARP攻击，最后还可以收集各种授权信息。该工具使用Python编写，并提供界面操作，所以使用非常方便。
  >Ghost Phisher is a Wireless and Ethernet security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to emulate access points and deploy.

  >Ghost Phisher currently supports the following features:

    - HTTP Server
    - Inbuilt RFC 1035 DNS Server
    - Inbuilt RFC 2131 DHCP Server
    - Webpage Hosting and Credential Logger (Phishing)
    - Wifi Access point Emulator
    - Session Hijacking (Passive and Ethernet Modes)
    - ARP Cache Poisoning (MITM and DOS Attacks)
    - Penetration using Metasploit Bindings
    - Automatic credential logging using SQlite Database
    - Update Support
- GoLismero:GoLismero是一款开源的安全测试框架。目前，它的测试目标主要为网站。该框架采用插件模式，实现用户所需要的功能。GoLismero默认自带了导入、侦测、扫描、攻击、报告、UI六大类插件。通过这些插件，用户可以对目标网站进行DNS检测、服务识别、GEOIP扫描、Robots文件扫描、目录暴力枚举等几十项功能。通过插件方式，GoLismero还可以调用其他工具，如Exploit-DB、PunkSPIDER、Shodan、SpiderFoot、theHarvester。
  >GoLismero is an open source framework for security testing. It’s currently geared towards web security, but it can easily be expanded to other kinds of scans.

  >The most interesting features of the framework are:

    - Real platform independence. Tested on Windows, Linux, *BSD and OS X.
    - No native library dependencies. All of the framework has been written in pure Python.
    - Good performance when compared with other frameworks written in Python and other scripting languages.
    - Very easy to use.
    - Plugin development is extremely simple.
    - The framework also collects and unifies the results of well known tools: sqlmap, xsser, openvas, dnsrecon, theharvester
    - Integration with standards: CWE, CVE and OWASP.
    - Designed for cluster deployment in mind (not available yet).
- goofile：使用此工具可以在给定的域中搜索特定的文件类型。
  >https://tools.kali.org/information-gathering/goofile
- hping3:是用于生成和解析TCPIP协议数据包的开源工具。创作者是Salvatore Sanfilippo。目前最新版是hping3，支持使用tcl脚本自动化地调用其API。hping是安全审计、防火墙测试等工作的标配工具。hping优势在于能够定制数据包的各个部分，因此用户可以灵活对目标机进行细致地探测。
  >hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn’t only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features.

  >While hping was mainly used as a security tool in the past, it can be used in many ways by people that don’t care about security to test networks and hosts. A subset of the stuff you can do using hping:

    - Firewall testing
    - Advanced port scanning
    - Network testing, using different protocols, TOS, fragmentation
    - Manual path MTU discovery
    - Advanced traceroute, under all the supported protocols
    - Remote OS fingerprinting
    - Remote uptime guessing
    - TCP/IP stacks auditing
    - hping can also be useful to students that are learning TCP/IP.
- ident-user-enum:身份识别协议(Ident protocol,IDENT)是一种Internet协议，用于识别使用特定TCP端口的用户身份。服务器开启该服务后，会默认监听113端口。用户可以向该端口发送请求包，查询服务器上使用特定TCP端口的用户名。由于该协议不对发起请求的用户进行识别，所以存在泄漏敏感信息的风险。Kali Linux提供针对该漏洞的工具ident-user-enum。对于渗透测试人员，可以使用端口扫描工具获取服务器的端口。然后，再借助该工具获取监听端口的程序的执行者用户身份。通过这种方式，渗透测试人员既可以获取可用的用户列表，进行后期的密码爆破，也可以获取以管理员身份运行的服务，以便后期注入利用。
  
  >ident-user-enum is a simple PERL script to query the ident service (113/TCP) in order to determine the owner of the process listening on each TCP port of a target system.
  >This can help to prioritise target service during a pentest (you might want to attack services running as root first). Alternatively, the list of usernames gathered can be used for password guessing attacks on other network services.
- InSpy:领英Linkedin是一个知名职业社交媒体网站。通过该网站，渗透测试人员可以获取公司内部组成和员工信息。Kali Linux提供一款专用的信息收集工具InSpy。该工具使用Python语言编写。它可以根据技术分类，搜索公司相关的工作岗位信息。它还可以根据部门搜索员工信息。为了方便安全人员进行数据分析，该工具支持HTML、CSV和JSON格式输出。
  >InSpy is a Python-based LinkedIn enumeration tool with two functionalities: TechSpy and EmpSpy. TechSpy crawls LinkedIn job listings for technologies used by the target company. InSpy attempts to identify technologies by matching job descriptions to keywords from a newline-delimited file.EmpSpy crawls LinkedIn for employees working at the provided company. InSpy searches for employees by title and/or department from a newline-delimited file. InSpy may also create emails for the identified employees if the user specifies an email format.
- InTrace:被动路由跟踪工具InTrace InTrace是一款类似于Traceroute的路由跟踪工具。但它不同的是，他不主动发送数据包，而是通过监听当前主机和目标主机的数据包，进行分析，从而获取路由信息。这样既可以进行网络侦查，又可以绕过防火墙的限制，避免被防火墙发现。该工具使用非常简单，只要开启监听，然后等待获取和目标主机的数据包，然后就可以获取路由跟踪信息了。PS：使用的时候需要指定端口。该端口号必须在TCP连接中使用到。否则，就无法捕获对应的数据包。
  >InTrace is a traceroute-like application that enables users to enumerate IP hops exploiting existing TCP connections, both initiated from local network (local system) or from remote hosts. It could be useful for network reconnaissance and firewall bypassing.
- iSMTP:SMTP用户枚举、内部欺骗和转发
  >Test for SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.
- lbd：负载均衡探测器lbd 大型网站为了解决海量访问问题，往往采用负载均衡技术，将用户的访问分配到不同的服务器上。网站的负载均衡可以从DNS和HTTP两个环节进行实施。在进行Web渗透测试的时候，需要先了解网站服务器结构，以确定后期的渗透策略。Kali Linux提供工具lbd来获取网站的负载均衡信息。该工具可以根据DNS域名解析、HTTP服务的header和响应差异，来识别均衡方式。PS：由于用户所使用的线路不同，获取的输出结果不同。大家可以把运行结果和其他人的做比较，以发现目标网站的更多服务器。
- Maltego Teeth:Maltego是一个开源的漏洞评估工具，它主要用于论证一个网络内单点故障的复杂性和严重性。该工具能够聚集来自内部和外部资源的信息，并且提供一个清晰的漏洞分析界面。
  >Maltego is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. Maltego’s unique advantage is to demonstrate the complexity and severity of single points of failure as well as trust relationships that exist currently within the scope of your infrastructure.

  >The unique perspective that Maltego offers to both network and resource based entities is the aggregation of information posted all over the internet – whether it’s the current configuration of a router poised on the edge of your network or the current whereabouts of your Vice President on his international visits, Maltego can locate, aggregate and visualize this information.

  >Maltego offers the user with unprecedented information. Information is leverage. Information is power. Information is Maltego.

  >What does Maltego do?

  >Maltego is a program that can be used to determine the relationships and real world links between:

    - People
    - Groups of people (social networks)
    - Companies
    - Organizations
    - Web sites
    - Internet infrastructure such as:
    - Domains
    - DNS names
    - Netblocks
    - IP addresses
    - Phrases
    - Affiliations
    - Documents and files
    - These entities are linked using open source intelligence.
    - Maltego is easy and quick to install – it uses Java, so it runs on Windows, Mac and Linux.
    - Maltego provides you with a graphical interface that makes seeing these relationships instant and accurate – making it possible to see hidden connections.
    - Using the graphical user interface (GUI) you can see relationships easily – even if they are three or four degrees of separation away.
    - Maltego is unique because it uses a powerful, flexible framework that makes customizing possible. As such, Maltego can be adapted to your own, unique requirements.
  >What can Maltego do for me?

    - Maltego can be used for the information gathering phase of all security related work. It will save you time and will allow you to work more accurately and smarter.
    - Maltego aids you in your thinking process by visually demonstrating interconnected links between searched items.
    - Maltego provide you with a much more powerful search, giving you smarter results.
    - If access to “hidden” information determines your success, Maltego can help you discover it.
- masscan:Masscan号称是最快的互联网端口扫描器，最快可以在六分钟内扫遍互联网。masscan的扫描结果类似于nmap(一个很著名的端口扫描器)，在内部，它更像scanrand, unicornscan, and ZMap，采用了异步传输的方式。它和这些扫描器最主要的区别是，它比这些扫描器更快。而且，masscan更加灵活，它允许自定义任意的地址范和端口范围。
  >This is the fastest Internet port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second.
  
  >It produces results similar to nmap, the most famous port scanner. Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission. The major difference is that it’s faster than these other scanners. In addition, it’s more flexible, allowing arbitrary address ranges and port ranges.

  >NOTE: masscan uses a custom TCP/IP stack. Anything other than simple port scans will cause conflict with the local TCP/IP stack. This means you need to either use the -S option to use a separate IP address, or configure your operating system to firewall the ports that masscan uses.
- Metagoofil:Metagoofil是由Christian Martorella编写的功能强大的元数据收集工具。它可以自动在搜素引擎中检索和分析文件，还具有提供Mac地址，用户名列表等其他功能。
  >Metagoofil is an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) belonging to a target company.

  >Metagoofil will perform a search in Google to identify and download the documents to local disk and then will extract the metadata with different libraries like Hachoir, PdfMiner? and others. With the results it will generate a report with usernames, software versions and servers or machine names that will help Penetration testers in the information gathering phase.
- Miranda:UPNP网关发现工具Miranda,MirandaUPNP 是各种各样的智能设备、无线设备和个人电脑等实现遍布全球的对等网络连接（P2P）的结构。例如，迅雷软件就支持UPNP结构，从而加快软件下载速度。为了提高P2P类程序的网速，很多人都会打开路由器中的UPNP功能。 而Miranda是Kali提供的一款基于Python语言的UPNP客户端工具。它可以用来发现、查询和操作UPNP设备，尤其是网关设置。当路由器开启UPNP功能，存在相应的漏洞，就可以通过Miranda进行渗透和控制。
  >Miranda is a Python-based Universal Plug-N-Play client application designed to discover, query and interact with UPNP devices, particularly Internet Gateway Devices (aka, routers). It can be used to audit UPNP-enabled devices on a network for possible vulnerabilities. Some of its features include:

    - Interactive shell with tab completion and command history
    - Passive and active discovery of UPNP devices
    - Customizable MSEARCH queries (query for specific devices/services)
    - Full control over application settings such as IP addresses, ports and headers
    - Simple enumeration of UPNP devices, services, actions and variables
    - Correlation of input/output state variables with service actions
    - Ability to send actions to UPNP services/devices
    - Ability to save data to file for later analysis and collaboration
    - Command logging
  >Miranda was built on and for a Linux system and has been tested on a Linux 2.6 kernel with Python 2.5. However, since it is written in Python, most functionality should be available for any Python-supported platform. Miranda has been tested against IGDs from various vendors, including Linksys, D-Link, Belkin and ActionTec. All Python modules came installed by default on a Linux Mint 5 (Ubuntu 8.04) test system.
- nbtscan-unixwiz:NBNS是NetBIOS Name Service的缩写，表示NetBIOS名称解析服务。NETBIOS是一种网络协议，用于实现消息通信和资源共享。利用该服务，可以基于NETBIOS协议获取计算机名称，从而进一步判断共享资源。Kali Linux提供了专用工具nbtscan-unixwiz。它可以直接扫描单个或者多个计算机名称或者IP地址，然后搜索开放的文件共享服务。
  >This is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network, and this is a first step in finding of open shares. It is based on the functionality of the standard Windows tool nbtstat, but it operates on a range of addresses instead of just one.
- Nmap:Nmap是一款网络扫描和主机检测的非常有用的工具。Nmap是不局限于仅仅收集信息和枚举，同时可以用来作为一个漏洞探测器或安全扫描器。它可以适用于winodws,linux,mac等操作系统。Nmap是一款非常强大的实用工具,可用于：检测活在网络上的主机（主机发现;检测主机上开放的端口（端口发现或枚举;检测到相应的端口（服务发现）的软件和版本检测操作系统，硬件地址，以及软件版本;检测脆弱性的漏洞（Nmap的脚本）
  >Nmap (“Network Mapper”) is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping).

  >Nmap was named “Security Product of the Year” by Linux Journal, Info World, LinuxQuestions.Org, and Codetalker Digest. It was even featured in twelve movies, including The Matrix Reloaded, Die Hard 4, Girl With the Dragon Tattoo, and The Bourne Ultimatum.

  >Nmap is …

    - Flexible: Supports dozens of advanced techniques for mapping out networks filled with IP filters, firewalls, routers, and other obstacles. This includes many port scanning mechanisms (both TCP & UDP), OS detection, version detection, ping sweeps, and more. See the documentation page.
    - Powerful: Nmap has been used to scan huge networks of literally hundreds of thousands of machines.
    - Portable: Most operating systems are supported, including Linux, Microsoft Windows, FreeBSD, OpenBSD, Solaris, IRIX, Mac OS X, HP-UX, NetBSD, Sun OS, Amiga, and more.
    - Easy: While Nmap offers a rich set of advanced features for power users, you can start out as simply as “nmap -v -A targethost”. Both traditional command line and graphical (GUI) versions are available to suit your preference. Binaries are available for those who do not wish to compile Nmap from source.
    - Free: The primary goals of the Nmap Project is to help make the Internet a little more secure and to provide administrators/auditors/hackers with an advanced tool for exploring their networks. Nmap is available for free download, and also comes with full source code that you may modify and redistribute under the terms of the license.
    - Well Documented: Significant effort has been put into comprehensive and up-to-date man pages, whitepapers, tutorials, and even a whole book! Find them in multiple languages here.
    - Supported: While Nmap comes with no warranty, it is well supported by a vibrant community of developers and users. Most of this interaction occurs on the Nmap mailing lists. Most bug reports and questions should be sent to the nmap-dev list, but only after you read the guidelines. We recommend that all users subscribe to the low-traffic nmap-hackers announcement list. You can also find Nmap on Facebook and Twitter. For real-time chat, join the #nmap channel on Freenode or EFNet.
    - Acclaimed: Nmap has won numerous awards, including “Information Security Product of the Year” by Linux Journal, Info World and Codetalker Digest. It has been featured in hundreds of magazine articles, several movies, dozens of books, and one comic book series. Visit the press page for further details.
    - Popular: Thousands of people download Nmap every day, and it is included with many operating systems (Redhat Linux, Debian Linux, Gentoo, FreeBSD, OpenBSD, etc). It is among the top ten (out of 30,000) programs at the Freshmeat.Net repository. This is important because it lends Nmap its vibrant development and user support communities.
- ntop:Ntop是一种监控网络流量工具，用ntop显示网络的使用情况比其他一些网络管理软件更加直观、详细。Ntop甚至可以列出每个节点计算机的网络带宽利用率。
  >ntop is a tool that shows the network usage, similar to what the popular top Unix command does. ntop is based on pcapture (ftp://ftp.ee.lbl.gov/pcapture.tar.Z) and it has been written in a portable way in order to virtually run on every Unix platform.

  >ntop can be used in both interactive or web mode. In the first case, ntop displays the network status on the user’s terminal whereas in web mode a web browser (e.g. netscape) can attach to ntop (that acts as a web server) and get a dump of the network status. In the latter case, ntop can be seen as a simple RMON-like agent with an embedded web interface.

  >ntop uses libpcap, a system-independent interface for user-level packet capture.
- OSRFramework:OSRFramework is an open source research framework in Python that helps you in the task of user profiling making use of different OSINT tools. The framework itself is designed reminiscent to the Metasploit framework. It also has a web-based GUI which does the work for you if you like to work without the command line. These are the modules that are currently implemented in the OSRFramework
  >OSRFramework is a GNU AGPLv3+ set of libraries developed by i3visio to perform Open Source Intelligence tasks. They include references to a bunch of different applications related to username checking, DNS lookups, information leaks research, deep web search, regular expressions extraction and many others. At the same time, by means of ad-hoc Maltego transforms, OSRFramework provides a way of making these queries graphically as well as several interfaces to interact with like OSRFConsole or a Web interface.
  > a collection of scripts that can enumerate users, domains, and more across over 200 separate services.
- p0f:p0f是一款被动探测工具，能够通过捕获并分析目标主机发出的数据包来对主机上的操作系统进行鉴别，即使是在系统上装有性能良好的防火墙的情况下也没有问题。。目前最新版本为3.09b。同时p0f在网络分析方面功能强大，可以用它来分析NAT、负载均衡、应用代理等。p0f是万能的被动操作系统指纹工具。p0f对于网络攻击非常有用，它利用SYN数据包实现操作系统被动检测技术，能够正确地识别目标系统类型。和其他扫描软件不同，它不向目标系统发送任何的数据，只是被动地接受来自目标系统的数据进行分析。因此，一个很大的优点是：几乎无法被检测到，而且p0f是专门系统识别工具，其指纹数据库非常详尽，更新也比较快，特别适合于安装在网关中。工作原理：当被动地拦截原始的TCP数据包中的数据，如可以访问数据包流经的网段，或数据包发往，或数据包来自你控制的系统；就能收集到很多有用的信息：TCP SYN 和SYN/ACK数据包就能反映TCP的链接参数，并且不同的TCP协议栈在协商这些参数的表现不同。P0f不增加任何直接或间接的网络负载，没有名称搜索、没有秘密探测、没有ARIN查询，什么都没有。某些高手还可以用P0f检测出主机上是否有防火墙存在、是否有NAT、是否存在负载平衡器等等！P0f是继Nmap和Xprobe2之后又一款远程操作系统被动判别工具。
  
  >P0f is a tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications (often as little as a single normal SYN) without interfering in any way. Version 3 is a complete rewrite of the original codebase, incorporating a significant number of improvements to network-level fingerprinting, and introducing the ability to reason about application-level payloads (e.g., HTTP).
  
  >Some of p0f’s capabilities include:
    
    - Highly scalable and extremely fast identification of the operating system and software on both endpoints of a vanilla TCP connection – especially in settings where NMap probes are blocked, too slow, unreliable, or would simply set off alarms.
    - Measurement of system uptime and network hookup, distance (including topology behind NAT or packet filters), user language preferences, and so on.
    - Automated detection of connection sharing / NAT, load balancing, and application-level proxying setups.
    - Detection of clients and servers that forge declarative statements such as X-Mailer or User-Agent.
  >The tool can be operated in the foreground or as a daemon, and offers a simple real-time API for third-party components that wish to obtain additional information about the actors they are talking to.
  
  >Common uses for p0f include reconnaissance during penetration tests; routine network monitoring; detection of unauthorized network interconnects in corporate environments; providing signals for abuse-prevention tools; and miscellanous forensics.

- Parsero:网站robots.txt探测工具Parsero,robots.txt文件是网站根目录下的一个文本文件。robots.txt是搜索引擎中访问网站的时候要查看的第一个文件。当搜索引擎访问一个站点时，它会首先检查该站点根目录下是否存在robots.txt。如果存在，搜索引擎就会按照该文件中的内容来确定访问的范围；如果该文件不存在，则会够访问网站上所有没有被口令保护的所有页面。网站为了防止搜索引擎访问一些重要的页面，会把其所在的目录放入robots.txt文件中。所以，探测该文件，也可以获取网站的重要信息。Kali Linux提供一个小工具Parsero，可以探测指定网站的robots.txt文件，并确认实际可访问性。PS：该工具需要用户使用apt-get命令手动安装。
  >Parsero is a free script written in Python which reads the Robots.txt file of a web server and looks at the Disallow entries. The Disallow entries tell the search engines what directories or files hosted on a web server mustn’t be indexed. For example, “Disallow: /portal/login” means that the content on www.example.com/portal/login it’s not allowed to be indexed by crawlers like Google, Bing, Yahoo… This is the way the administrator have to not share sensitive or private information with the search engines.

  >But sometimes these paths typed in the Disallows entries are directly accessible by the users without using a search engine, just visiting the URL and the Path, and sometimes they are not available to be visited by anybody… Because it is really common that the administrators write a lot of Disallows and some of them are available and some of them are not, you can use Parsero in order to check the HTTP status code of each Disallow entry in order to check automatically if these directories are available or not.

  >Also, the fact the administrator write a robots.txt, it doesn’t mean that the files or directories typed in the Dissallow entries will not be indexed by Bing, Google, Yahoo… For this reason, Parsero is capable of searching in Bing to locate content indexed without the web administrator authorization. Parsero will check the HTTP status code in the same way for each Bing result.
- Recon-ng:Recon-ng是一个全面的web探测框架，它由python编写，有着独立的模块、数据库交互功能、交互式帮助提示和命令补全的特性。它提供了一个强大的开源web探测机制，帮助测试人员快速彻底地进行探测。Recon-ng框架简介Recon-ng的使用和模式与主流的metasploit框架有点类似，这减少了用户学习利用该框架的难度。当然，Recon-ng也有着自己的特点，其为基于web的开源探测工具。如果你想要进行exp利用，请使用metasploit框架。如果你想进行社工，请使用社工工具包。如果你想进行被动探测，请使用Recon-ng。至于主动检测工具的例子，大家可以看看谷歌安全团队的Skipfish。Recon-ng是一个完全模块化的框架，新的python开发者也能很容易地进行模块贡献。每一个模块都是“module”类的子类，“module”类是一个定制的“cmd”解释器，内置提供了常用任务（如标准输出、数据库交互、进行web请求和API key管理）的简单接口。可以说，基本所有复杂的工作都已经被作者完成。我们想要构建新的模块会非常简单，仅仅需要几分钟。

  >Recon-ng约有80个recon模块，2个发现模块，2个exp利用模块，7个报告模块和2个导入模块：

    - cache_snoop – DNS缓存录制
    - interesting_files – 敏感文件探测
    - command_injector – 远程命令注入shell接口
    - xpath_bruter – Xpath注入爆破
    - csv_file – 高级csv文件导入
    - list – List文件导入
    - point_usage – Jigsaw – 统计信息提取用法
    - purchase_contact – Jigsaw – 简单的联系查询
    - search_contacts – Jigsaw联系枚举
    - jigsaw_auth – Jigsaw认证联系枚举
    - linkedin_auth – LinkedIn认证联系枚举
    - github_miner – Github资源挖掘
    - whois_miner – Whois数据挖掘
    - bing_linkedin – Bing Linkedin信息采集
    - email_validator – SalesMaple邮箱验证
    - mailtester – MailTester邮箱验证
    - mangle – 联系分离
    - unmangle –联系反分离
    - hibp_breach –Breach搜索
    - hibp_paste – Paste搜索
    - pwnedlist – PwnedList验证
    - migrate_contacts – 域名数据迁移联系
    - facebook_directory – Facebook目录爬行
    - fullcontact – FullContact联系枚举
    - adobe – Adobe Hash破解
    - bozocrack – PyBozoCrack Hash 查询
    - hashes_org – Hashes.org Hash查询
    - leakdb – leakdb Hash查询
    - metacrawler – 元数据提取
    - pgp_search – PGP Key Owner查询
    - salesmaple – SalesMaple联系获取
    - whois_pocs – Whois POC获取
    - account_creds – PwnedList – 账户认证信息获取
    - api_usage – PwnedList – API使用信息
    - domain_creds – PwnedList – Pwned域名认证获取
    - domain_ispwned – PwnedList – Pwned域名统计获取
    - leak_lookup – PwnedList – 泄露信息查询
    - leaks_dump – PwnedList –泄露信息获取
    - brute_suffix – DNS公共后缀爆破
    - baidu_site – Baidu主机名枚举
    - bing_domain_api – Bing API主机名枚举
    - bing_domain_web – Bing主机名枚举
    - brute_hosts – DNS主机名爆破
    - builtwith – BuiltWith枚举
    - google_site_api – Google CSE主机名枚举
    - google_site_web – Google主机名枚举
    - netcraft – Netcraft主机名枚举
    - shodan_hostname – Shodan主机名枚举
    - ssl_san – SSL SAN查询
    - vpnhunter – VPNHunter查询
    - yahoo_domain – Yahoo主机名枚举
    - zone_transfer – DNS域文件收集
    - ghdb – Google Hacking数据库
    - punkspider – PunkSPIDER漏洞探测
    - xssed – XSSed域名查询
    - xssposed – XSSposed域名查询
    - migrate_hosts – 域名数据迁移host
    - bing_ip – Bing API旁站查询
    - freegeoip –FreeGeoIP ip定位查询
    - ip_neighbor – My-IP-Neighbors.com查询
    - ipinfodb – IPInfoDB GeoIP查询
    - resolve – 主机名解析器
    - reverse_resolve – 反解析
    - ssltools – SSLTools.com主机名查询
    - geocode – 地理位置编码
    - reverse_geocode – 反地理位置编码
    - flickr – Flickr地理位置查询
    - instagram – Instagram地理位置查询
    - picasa – Picasa地理位置查询
    - shodan – Shodan地理位置查询
    - twitter – Twitter地理位置查询
    - whois_orgs – Whois公司信息收集
    - reverse_resolve – 反解析
    - shodan_net – Shodan网络枚举
    - census_2012 – Internet Census 2012 查询
    - sonar_cio – Project Sonar查询
    - migrate_ports – 主机端口数据迁移
    - dev_diver – Dev Diver Repository检查
    - linkedin – Linkedin联系获取
    - linkedin_crawl – Linkedin信息抓取
    - namechk – NameChk.com用户名验证
    - profiler – OSINT HUMINT信息收集
    - twitter – Twitter操作
    - github_repos – Github代码枚举
    - gists_search – Github Gist搜索
    - github_dorks – Github Dork分析
    - csv – CSV文件生成
    - html – HTML报告生成
    - json – JSON报告生成
    - list – List生成
    - pushpin – PushPin报告生成
    - xlsx – XLSX文件创建
    - xml – XML报告生成
- SET: https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf
  >The Social-Engineer Toolkit is an open-source penetration testing framework designed for Social-Engineering. SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of the time.

    - 1BEGINNING WITH THE SOCIAL ENGINEER TOOLKIT.............2
    - 2SET MENU’S..............8
    - 3SPEAR-PHISHING ATTACK VECTOR............14
    - 4JAVA APPLET ATTACK VECTOR....20
    - 5FULL SCREEN ATTACK VECTOR...27
    - 6METASPLOIT BROWSER EXPLOIT METHOD.........................29
    - 7CREDENTIAL HARVESTERATTACK METHOD......................34
    - 8TABNABBING ATTACK METHOD...38
    - 9WEB JACKING ATTACK METHOD.................41
    - 10MULTI-ATTACK WEB VECTOR.....44
    - 11INFECTIOUS MEDIA GENERATOR..............54
    - 12TEENSY USB HID ATTACK VECTOR...........59
    - 13SMS SPOOFING ATTACK VECTOR.............66
    - 14WIRELESS ATTACK VECTOR........68
    - 15QRCODE ATTACK VECTOR..........70
    - 16FAST-TRACK EXPLOITATION.......71
    - 17SET INTERACTIVE SHELL AND RATTE.......72
    - 18SET AUTOMATION.........................76
    - 19FREQUENTLY ASKED QUESTIONS.............81
    - 20CODE SIGNING CERTIFICATES....81
    - 21DEVELOPING YOUR OWN SET MODULES...........................82

- SMBMap:枚举整个域中的 Samba 共享
  >SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks.
- smtp-user-enum:使用了smtp-user-enum对给定列表中的IP地址进行SMTP用户枚举
  >smtp-user-enum is a tool for enumerating OS-level user accounts on Solaris via the SMTP service (sendmail). Enumeration is performed by inspecting the responses to VRFY, EXPN and RCPT TO commands. It could be adapted to work against other vulnerable SMTP daemons, but this hasn’t been done as of v1.0.
- snmp-check
  >Like to snmpwalk, snmp-check allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring. Distributed under GPL license and based on “Athena-2k” script by jshaw.

  >Features
  >snmp-check supports the following enumerations:

    - contact
    - description
    - detect write access (separate action by enumeration)
    - devices
    - domain
    - hardware and storage informations
    - hostname
    - IIS statistics
    - IP forwarding
    - listening UDP ports
    - location
    - motd
    - mountpoints
    - network interfaces
    - network services
    - processes
    - routing information
    - software components
    - system uptime
    - TCP connections
    - total memory
    - uptime
    - user accounts
- SPARTA:SPARTA是Kali Linux自带的一款图形化网络扫描工具。它集成了NMAP、Nikto、hydra、nbtscan等几十种工具。用户只需要输入要扫描的IP或者IP段，SPARTA就会借助NMAP进行主机发现，查找可用端口。然后，根据端口判断对应的服务，搜集服务对应的信息，并进行漏洞扫描等。用户只需要通过鼠标点击的方式，就可以直接调用集成的几十种工具。同时，用户还可以修改配置文件，对SPARTA进行定制，添加更多的工具，并修改扫描策略和方式。
  >SPARTA is a python GUI application that simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase. It allows the tester to save time by having point-and-click access to their toolkit and by displaying all tool output in a convenient way. If less time is spent setting up commands and tools, more time can be spent focusing on analysing results.
- sslcaudit:SSL应用客户端测试工具
  >The goal of sslcaudit project is to develop a utility to automate testing SSL/TLS clients for resistance against MITM attacks. It might be useful for testing a thick client, a mobile application, an appliance, pretty much anything communicating over SSL/TLS over TCP.
- SSLsplit：SSL中间人攻击工具
  >SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.

  >SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6. For SSL and HTTPS connections, SSLsplit generates and signs forged X509v3 certificates on-the-fly, based on the original server certificate subject DN and subjectAltName extension. SSLsplit fully supports Server Name Indication (SNI) and is able to work with RSA, DSA and ECDSA keys and DHE and ECDHE cipher suites. SSLsplit can also use existing certificates of which the private key is available, instead of generating forged ones. SSLsplit supports NULL-prefix CN certificates and can deny OCSP requests in a generic way. SSLsplit removes HPKP response headers in order to prevent public key pinning.
- sslstrip:SSL剥离工具sslstrip.在日常上网过程中，用户只是在地址栏中输入网站域名，而不添加协议类型，如HTTP和HTTPS。这时，浏览器会默认在域名之前添加http://，然后请求网站。如果网站采用HTTPS协议，就会发送一个302重定向状态码和一个HTTPS的跳转网址，让浏览器重新请求。浏览器收到后，会按照新的网址，进行访问，从而实现数据安全加密。由于存在一次不安全的HTTP的请求，所以整个过程存在安全漏洞。sslstrip工具就是利用这个漏洞，实施攻击。渗透测试人员通过中间人攻击方式，将目标的数据转发到攻击机。sslstrip将跳转网址的HTTPS替换为HTTP，发给目标。目标以HTTP方式重新请求，而sslstrip将HTTP替换为HTTPS，请求对应的网站。这样就形成了，目标和ssltrip之间以HTTP明文方式传输，而sslstrip和服务器以HTTPS加密方式传输。这样，渗透人员就可以轻松获取明文数据了。
  >sslstrip is a tool that transparently hijacks HTTP traffic on a network, watch for HTTPS links and redirects, and then map those links into look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
- SSLyze:SSLyze是一款利用python编写的工具，它可以分析服务器的SSL配置，能够快速、全面的协助测试人员发现SSL服务器的配置错误。
  >SSLyze is a Python tool that can analyze the SSL configuration of a server by connecting to it. It is designed to be fast and comprehensive, and should help organizations and testers identify mis-configurations affecting their SSL servers.

  >Key features include:

    - Multi-processed and multi-threaded scanning (it’s fast)
    - SSL 2.0/3.0 and TLS 1.0/1.1/1.2 compatibility
    - Performance testing: session resumption and TLS tickets support
    - Security testing: weak cipher suites, insecure renegotiation, CRIME, Heartbleed and more
    - Server certificate validation and revocation checking through OCSP stapling
    - Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP, RDP and FTP
    - Support for client certificates when scanning servers that perform mutual authentication
    - XML output to further process the scan results
- Sublist3r:子域名枚举工具Sublist3r通过搜集子域名信息，可以找到目标的关联网站，找寻相应的漏洞。Kali Linux提供一款基于OSINT的枚举工具Sublist3r。该工具会搜索多个数据来源，如Google、Yahoo、Bing、Baidu、Ask、Netcraft、Virustotal。同时，该工具也支持暴力枚举功能。对搜索到的子域名，用户还可以检测特定端口的开放情况，便于后期的渗透
  >Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS.
- THC-IPV6:THC-IPV6是一套完整的工具包，可用来攻击IPV6和ICMP6协议的固有弱点，THC-IPV6包含了易用的库文件，可二次开发。THC-IPV6由先进的主机存活扫描工具，中间人攻击工具，拒绝服务攻击工具构成。
  >A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
- theHarvester:theHarvester是一个社会工程学工具，它通过搜索引擎、PGP服务器以及SHODAN数据库收集用户的email，子域名，主机，雇员名，开放端口和banner信息。这款工具可以帮助渗透测试工作者在渗透测试的早期阶段对目标进行互联网资料采集，同时也可以帮助人们了解自己的个人信息在网络上是否存在。
  >The objective of this program is to gather emails, subdomains, hosts, employee names, open ports and banners from different public sources like search engines, PGP key servers and SHODAN computer database.

  >This tool is intended to help Penetration testers in the early stages of the penetration test in order to understand the customer footprint on the Internet. It is also useful for anyone that wants to know what an attacker can see about their organization.

  >This is a complete rewrite of the tool with new features like:

    - Time delays between request
    - All sources search
    - Virtual host verifier
    - Active enumeration (DNS enumeration, Reverse lookups, TLD expansion)
    - Integration with SHODAN computer database, to get the open ports and banners
    - Save to XML and HTML
    - Basic graph with stats
    - New sources
- TLSSLed:现在SSL和TLS被广泛应用服务器的数据加密中，如网站的HTTPS服务。所以，在渗透测试中如何快速检测服务器的SSL和TLS配置寻找安全漏洞，就显得很重要。 Kali Linux提供专用检测工具TLSSLed。该工具是基于sslscan的脚本工具，使用非常简单。用户可以一次性执行所有检测任务，并且会生成详细的日志文件。它可以检测支持的协议类型、空密码和弱密码以及强密码等功能。
  >TLSSLed is a Linux shell script whose purpose is to evaluate the security of a target SSL/TLS (HTTPS) web server implementation. It is based on sslscan, a thorough SSL/TLS scanner that is based on the openssl library, and on the “openssl s_client” command line tool. The current tests include checking if the target supports the SSLv2 protocol, the NULL cipher, weak ciphers based on their key length (40 or 56 bits), the availability of strong ciphers (like AES), if the digital certificate is MD5 signed, and the current SSL/TLS renegotiation capabilities.
- twofi:Generate custom word lists based on Twitter searches. Search for either keywords or for known users tweets.
  >When attempting to crack passwords custom word lists are very useful additions to standard dictionaries. An interesting idea originally released on the “7 Habits of Highly Effective Hackers” blog was to use Twitter to help generate those lists based on searches for keywords related to the list that is being cracked. This idea has been expanded into twofi which will take multiple search terms and return a word list sorted by most common first.
- URLCrazy:Typo域名是一类的特殊域名。用户将正确的域名错误拼写产生的域名被称为Typo域名。例如，www.baidu.com错误拼写为www.bidu.com，就形成一个Typo域名。对于热门网站的Typo域名会产生大量的访问量，通常都会被人抢注，以获取流量。而黑客也会利用Typo域名构建钓鱼网站。 Kali Linux提供对应的检测工具urlcrazy。该工具统计了常见的几百种拼写错误。它可以根据用户输入的域名，自动生成Typo域名；并且会检验这些域名是否被使用，从而发现潜在的风险。同时，它还会统计这些域名的热度，从而分析危害程度。
  >Generate and test domain typos and variations to detect and perform typo squatting, URL hijacking, phishing, and corporate espionage.

  >Features

    - Generates 15 types of domain variants
    - Knows over 8000 common misspellings
    - Supports cosmic ray induced bit flipping
    - Multiple keyboard layouts (qwerty, azerty, qwertz, dvorak)
    - Checks if a domain variant is valid
    - Test if domain variants are in use
    - Estimate popularity of a domain variant
- Wireshark:是一个免费开源的网路封包分析软体。网路封包分析软体的功能是截取网路封包，并尽可能显示出最为详细的网路封包资料。在过去，网路封包分析软体是非常昂贵，或是专门属于营利用的软体，Wireshark的出现改变了这一切。在GNU通用公共许可证的保障范围底下，使用者可以以免费的代价取得软体与其程式码，并拥有针对其原始码修改及客制化的权利。Wireshark是目前全世界最广泛的网路封包分析软体之一。
  >Wireshark is the world’s foremost network protocol analyzer. It lets you see what’s happening on your network at a microscopic level. It is the de facto (and often de jure) standard across many industries and educational institutions. Wireshark development thrives thanks to the contributions of networking experts across the globe. It is the continuation of a project that started in 1998.

  >Wireshark has a rich feature set which includes the following:

    - Deep inspection of hundreds of protocols, with more being added all the time
    - Live capture and offline analysis
    - Standard three-pane packet browser
    - Multi-platform: Runs on Windows, Linux, OS X, Solaris, FreeBSD, NetBSD, and many others
    - Captured network data can be browsed via a GUI, or via the TTY-mode TShark utility
    - The most powerful display filters in the industry
    - Rich VoIP analysis
    - Capture files compressed with gzip can be decompressed on the fly
    - Live data can be read from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI, and others (depending on your platform)
    - Coloring rules can be applied to the packet list for quick, intuitive analysis
    - Output can be exported to XML, PostScript®, CSV, or plain text
    - Decryption support for many protocols, including IPsec, ISAKMP, Kerberos, SNMPv3, SSL/TLS, WEP, and WPA/WPA2
    - Read/write many different capture file formats: tcpdump (libpcap), Pcap NG, Catapult DCT2000, Cisco Secure IDS iplog, Microsoft Network Monitor, Network * General Sniffer® (compressed and uncompressed), Sniffer® Pro, and NetXray®, Network Instruments Observer, NetScreen snoop, Novell LANalyzer, RADCOM WAN/LAN Analyzer, Shomiti/Finisar Surveyor, Tektronix K12xx, Visual Networks Visual UpTime, WildPackets EtherPeek/TokenPeek/AiroPeek, and many others
- WOL-E:检测网络中的Macbook神器
  >WOL-E is a suite of tools for the Wake on LAN feature of network attached computers, this is now enabled by default on many Apple computers. These tools include:

    - Bruteforcing the MAC address to wake up clients
    - Sniffing WOL attempts on the network and saving them to disk
    - Sniffing WOL passwords on the network and saving them to disk
    - Waking up single clients (post sniffing attack)
    - Scanning for Apple devices on the network for WOL enabling
    - Sending bulk WOL requests to all detected Apple clients
- Xplico: Xplico的目标是提取互联网流量并捕获应用数据中包含的信息。 举个例子，Xplico可以在pcap文件中提取邮件内容(通过POP，IMAP，SMTP协议)，所有的HTTP内容，每个VoIP的访问(SIP)，FTP，TFTP等等，但是Xplico不是一个网络协议分析工具。Xplico的目标是提取互联网流量并捕获应用数据中包含的信息。举个例子，Xplico可以在pcap文件中提取邮件内容(通过POP，IMAP，SMTP协议)，所有的HTTP内容，每个VoIP的访问(SIP)，FTP，TFTP等等，但是Xplico不是一个网络协议分析工具。Xplico是一个开源的网络取证分析工具(NFAT)。功能包括：

  - 协议支持：HTTP, SIP, IMAP, POP, SMTP, TCP, UDP, IPv6, … ;
  - 针对每个应用协议都有端口独立协议识别(PIPI);
  - 多线程;
  - 支持使用SQLite数据库或者Mysql数据库甚至文件进行数据和信息的输出;
  - 每个数据都由Xplico重新组装，并被关联到能够唯一识别流量的XML文件。Pcap包含重组数据;
  - 支持实时查询细节(能否真的实现取决于流量大小、协议类型和计算机性能-TAM, CPU, HD访问时间等...);
  - 为任何数据包和soft ACK认证使用ACK确认进行TCP重组;
  - 反向DNS查找是查找包含在输入文件(pcap)中的DNS数据包，而不是查找来自外部的DNS服务器;
  - 对输入数据的大小或者输入文件的数量没有限制(仅仅限制了HD的大小);
  - 支持IPv4和IPv6;
  - 模块化。每个Xplico部件都是一个模块。输入接口、协议解码器、输出接口都实现了模块化;
  - 轻松创建任何调度，使用最合适、最有效的方法实现数据分离。

##  Vulnerability Analysis - 漏洞分析

- BBQSQL:BBQSQL是一个用Python写的SQL盲注框架。对于棘手的SQL注入漏洞攻击非常有用。bbqsql也是一个半自动的工具，对于那些难以触发SQL注入有比较多的定制。该工具与数据库类型无关并且非常灵活。它也有一个直观的用户界面，使攻击设置更容易。Python Gevent也被实现，使bbqsql速度非常快。http://www.mottoin.com/90324.html
  >Blind SQL injection can be a pain to exploit. When the available tools work they work well, but when they don’t you have to write something custom. This is time-consuming and tedious. BBQSQL can help you address those issues.

  >BBQSQL is a blind SQL injection framework written in Python. It is extremely useful when attacking tricky SQL injection vulnerabilities. BBQSQL is also a semi-automatic tool, allowing quite a bit of customization for those hard to trigger SQL injection findings. The tool is built to be database agnostic and is extremely versatile. It also has an intuitive UI to make setting up attacks much easier. Python gevent is also implemented, making BBQSQL extremely fast.

  >Similar to other SQL injection tools you provide certain request information.

  >Must provide the usual information:

    - URL
    - HTTP Method
    - Headers
    - Cookies
    - Encoding methods
    - Redirect behavior
    - Files
    - HTTP Auth
    - Proxies
    - Then specify where the injection is going and what syntax we are injecting.
- BED:暴力漏洞检测工具，一个缓冲区溢出检测工具，归属与系统漏洞挖掘工具库，溢出漏洞挖掘工具集
  >BED Bruteforce Exploit Detector Tool is a program which is designed to check daemons for potential buffer overflows, format strings et. al.
- cisco-auditing-tool:一个很小的安全审计工具，扫描Cisco路由器的一般性漏洞，例如默认密码，SNMP community字串和一些老的IOS bug
  >Perl script which scans cisco routers for common vulnerabilities.
- cisco-global-exploiter:思科全局漏洞扫描发现
  >Cisco Global Exploiter (CGE), is an advanced, simple and fast security testing tool.
- cisco-ocs:Cisco路由器安全扫描器
  >A mass Cisco scanning tool.
- cisco-torch:Cisco Torch 是一款集成扫描、电子指纹识别、漏洞利用的针对Cisco设备的强大工具。它可以多线程在后台进行扫描，效率非常高，另外，它的扫描是在多个协议层的，可以发现在网络中运行有Telnet、SSH、Web、NEP和SNMP服务的Cisco设备，并可以根据其开启的服务进行攻击。
  >Cisco Torch mass scanning, fingerprinting, and exploitation tool was written while working on the next edition of the “Hacking Exposed Cisco Networks”, since the tools available on the market could not meet our needs.

  >The main feature that makes Cisco-torch different from similar tools is the extensive use of forking to launch multiple scanning processes on the background for maximum scanning efficiency. Also, it uses several methods of application layer fingerprinting simultaneously, if needed. We wanted something fast to discover remote Cisco hosts running Telnet, SSH, Web, NTP and SNMP services and launch dictionary attacks against the services discovered.
- copy-router-config:利用SNMP协议从思科设备上copy配置信息 
- DBPwAudit:DBPwAudit是一个Java数据库密码审计工具，是一个可以执行在线审计密码质量的数据库引擎。该应用程序可以通过复制新的JDBC驱动程序到JDBC目录来添加额外的数据库驱动程序。
  >DBPwAudit is a Java tool that allows you to perform online audits of password quality for several database engines. The application design allows for easy adding of additional database drivers by simply copying new JDBC drivers to the jdbc directory. Configuration is performed in two files, the aliases.conf file is used to map drivers to aliases and the rules.conf tells the application how to handle error messages from the scan.

  >The tool has been tested and known to work with:

    - Microsoft SQL Server 2000/2005
    - Oracle 8/9/10/11
    - IBM DB2 Universal Database
    - MySQL
  >The tool is pre-configured for these drivers but does not ship with them, due to licensing issues.
- Doona:BED的一个分支
  >Doona is a fork of the Bruteforce Exploit Detector Tool (BED). BED is a program which is designed to check daemons for potential buffer overflows, format string bugs etc.
  >Doona is Australian for duvet. It adds a significant number of features/changes to BED.
- DotDotPwn:DotDotPwn是一个非常灵活的智能模糊器，用于发现软件中的遍历目录漏洞，例如HTTP/FTP/TFTP服务器，Web平台的应用程序（如CMS，ERP，博客等）。此外，它有一个独立于协议的模块，用于将所需的有效负载发送到指定的主机和端口。 另一方面，它也可以使用STDOUT模块以脚本方式使用。DotDotPwn是用perl编程语言编写的，可以在* NIX或Windows平台下运行，它是BackTrack Linux（BT4 R2）中包含的第一个墨西哥人开发的工具。此版本支持的模糊模块：HTTP HTTP URL FTP TFTP Payload (Protocol independent) STDOUT
  >It’s a very flexible intelligent fuzzer to discover traversal directory vulnerabilities in software such as HTTP/FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs, etc.

  >Also, it has a protocol-independent module to send the desired payload to the host and port specified. On the other hand, it also could be used in a scripting way using the STDOUT module.

  >It’s written in perl programming language and can be run either under *NIX or Windows platforms. It’s the first Mexican tool included in BackTrack Linux (BT4 R2).

  >Fuzzing modules supported in this version:

    - HTTP
    - HTTP URL
    - FTP
    - TFTP
    - Payload (Protocol independent)
    - STDOUT****
- HexorBase:数据库密码爆破HexorBase,数据库服务是服务器上最常见的一类服务。由于数据库保存大量的敏感信息，所以它的安全非常重要。测试数据库服务安全的重要方式，就是检查口令的强壮度。Kali Linux提供了HexorBase工具。该工具是少有的图形界面工具，它支持MySQL、Oracle、PostgreSQL、SQLite和SQL Server五大主流数据库。它允许安全人员指定用户字典和密码字典，然后实施字典攻击。同时，它还提供对应的图形界面客户端，允许安全人员使用破解出的用户名和密码，对数据库进行远程管理。
  >HexorBase is a database application designed for administering and auditing multiple database servers simultaneously from a centralized location, it is capable of performing SQL queries and bruteforce attacks against common database servers (MySQL, SQLite, Microsoft SQL Server, Oracle, PostgreSQL ). HexorBase allows packet routing through proxies or even metasploit pivoting antics to communicate with remotely inaccessible servers which are hidden within local subnets.
- Inguma:Inguma是一个使用python编写的渗透测试套件。Ingum具有一个模块化的框架，包括的模块有主机发现、信息收集、目标fuzz、暴力破解用户名/密码和exploit。不过目前Inguma的exploit模块能力比较有限
  >Inguma is a penetration testing toolkit entirely written in python. The framework includes modules to discover hosts, gather information about, fuzz targets, brute force user names and passwords and, of course, exploits.

  >While the current exploitation capabilities in Inguma may be limited, this program provides numerous tools for information gathering and target auditing.
- jSQL:一款轻量级安全测试工具，可以检测SQL注入漏洞。
  >jSQL Injection is a lightweight application used to find database information from a distant server. jSQL is free, open source and cross-platform (Windows, Linux, Mac OS X, Solaris).
- Lynis:一款功能非常强大的开源审查工具，面向类似Unix/Linux的操作系统。它可以扫描系统，查找安全信息、一般的系统信息、已安装软件及可用软件信息、配置错误、安全问题、没有设密码的用户帐户、错误的文件许可权限以及防火墙审查等。
  >Lynis is an open source security auditing tool. Its main goal is to audit and harden Unix and Linux based systems. It scans the system by performing many security control checks. Examples include searching for installed software and determine possible configuration flaws.

  >Many tests are part of common security guidelines and standards, with on top additional security tests. After the scan a report will be displayed with all discovered findings. To provide you with initial guidance, a link is shared to the related Lynis control.
- Nmap:Nmap是一款网络扫描和主机检测的非常有用的工具。Nmap是不局限于仅仅收集信息和枚举，同时可以用来作为一个漏洞探测器或安全扫描器。它可以适用于winodws,linux,mac等操作系统。Nmap是一款非常强大的实用工具,可用于：检测活在网络上的主机（主机发现）;检测主机上开放的端口（端口发现或枚举）;检测到相应的端口（服务发现）的软件和版本检测操作系统，硬件地址，以及软件版本;检测脆弱性的漏洞（Nmap的脚本）
  >Nmap (“Network Mapper”) is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping).

  >Nmap was named “Security Product of the Year” by Linux Journal, Info World, LinuxQuestions.Org, and Codetalker Digest. It was even featured in twelve movies, including The Matrix Reloaded, Die Hard 4, Girl With the Dragon Tattoo, and The Bourne Ultimatum.

  >Nmap is …

    - Flexible: Supports dozens of advanced techniques for mapping out networks filled with IP filters, firewalls, routers, and other obstacles. This includes many port scanning mechanisms (both TCP & UDP), OS detection, version detection, ping sweeps, and more. See the documentation page.
    - Powerful: Nmap has been used to scan huge networks of literally hundreds of thousands of machines.
    - Portable: Most operating systems are supported, including Linux, Microsoft Windows, FreeBSD, OpenBSD, Solaris, IRIX, Mac OS X, HP-UX, NetBSD, Sun OS, Amiga, and more.
    - Easy: While Nmap offers a rich set of advanced features for power users, you can start out as simply as “nmap -v -A targethost”. Both traditional command line and graphical (GUI) versions are available to suit your preference. Binaries are available for those who do not wish to compile Nmap from source.
    - Free: The primary goals of the Nmap Project is to help make the Internet a little more secure and to provide administrators/auditors/hackers with an advanced tool for exploring their networks. Nmap is available for free download, and also comes with full source code that you may modify and redistribute under the terms of the license.
    - Well Documented: Significant effort has been put into comprehensive and up-to-date man pages, whitepapers, tutorials, and even a whole book! Find them in multiple languages here.
    - Supported: While Nmap comes with no warranty, it is well supported by a vibrant community of developers and users. Most of this interaction occurs on the Nmap mailing lists. Most bug reports and questions should be sent to the nmap-dev list, but only after you read the guidelines. We recommend that all users subscribe to the low-traffic nmap-hackers announcement list. You can also find Nmap on Facebook and Twitter. For real-time chat, join the #nmap channel on Freenode or EFNet.
    - Acclaimed: Nmap has won numerous awards, including “Information Security Product of the Year” by Linux Journal, Info World and Codetalker Digest. It has been featured in hundreds of magazine articles, several movies, dozens of books, and one comic book series. Visit the press page for further details.
    - Popular: Thousands of people download Nmap every day, and it is included with many operating systems (Redhat Linux, Debian Linux, Gentoo, FreeBSD, OpenBSD, etc). It is among the top ten (out of 30,000) programs at the Freshmeat.Net repository. This is important because it lends Nmap its vibrant development and user support communities.
- ohrwurm:是一个小而简单的RTP模糊器已在少数SIP电话的试验成功
  >ohrwurm is a small and simple RTP fuzzer that has been successfully tested on a small number of SIP phones. Features:

    - reads SIP messages to get information of the RTP port numbers
    - reading SIP can be omitted by providing the RTP port numbers, sothat any RTP traffic can be fuzzed
    - RTCP traffic can be suppressed to avoid that codecs
    - learn about the “noisy line”
    - special care is taken to break RTP handling itself
    - the RTP payload is fuzzed with a constant BER
    - the BER is configurable
    - requires arpspoof from dsniff to do the MITM attack
    - requires both phones to be in a switched LAN (GW operation only works partially)
- openvas:是开放式漏洞评估系统，其核心部件是一个服务器，包括一套望楼漏洞测试程序，可以检测远程系统和应用程序中的安全问题。OpenVAS Server仅支持Linux系统。OpenVAS Client 没有特殊的要求。其中Openvas server 是核心部分，负责为Openvas Client提供登陆，查询等功能，包括一整套随时更新的扫描插件（Plugins），用户可以通过OpenVAS NVT Feed Service保持与官方扫描插件的自动更新。同时OpenVAS Server 负责根据OpenVAS Client发起的请求，对指定的Target Systems（一系列主机）进行扫描，这些主机可以包括Linux，Windows，或是其他的操作系统。
  >OpenVAS is a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution. The framework is part of Greenbone Networks’ commercial vulnerability management solution from which developments are contributed to the Open Source community since 2009.

  >The actual security scanner is accompanied with a regularly updated feed of Network Vulnerability Tests (NVTs), over 50,000 in total.

  >All OpenVAS products are Free Software. Most components are licensed under the GNU General Public License (GNU GPL).
- Oscanner:Oracle系统评估框架
  >Oscanner is an Oracle assessment framework developed in Java. It has a plugin-based architecture and comes with a couple of plugins that currently do:

    - Sid Enumeration
    - Passwords tests (common & dictionary)
    - Enumerate Oracle version
    - Enumerate account roles
    - Enumerate account privileges
    - Enumerate account hashes
    - Enumerate audit information
    - Enumerate password policies
    - Enumerate database links
    - The results are given in a graphical java tree.
- Powerfuzzer:Powerfuzzer是Kali Linux自带的一款Web模糊测试工具。该工具基于各种开源模糊测试工具构建，集成了大量安全信息。该工具高度智能化，它能根据用户输入的网址进行自动识别XSS、SQL注入、CRLF、HTTP500等漏洞。同时，用户可以指定用户和密码等身份验证信息，也可以指定Cookie信息。同时，用户可以直接指定该工具是否使用代理。由于该工具开发较早，对非ASCII编码（如包含中文的网站）网站支持不好，分析中文网站容易出现异常错误。
  >Powerfuzzer is a highly automated and fully customizable web fuzzer (HTTP protocol based application fuzzer) based on many other Open Source fuzzers available and information gathered from numerous security resources and websites. It was designed to be user friendly, modern, effective and working.

  >Currently, it is capable of identifying these problems:

    - Cross Site Scripting (XSS)
    - Injections (SQL, LDAP, code, commands, and XPATH)
    - CRLF
    - HTTP 500 statuses (usually indicative of a possible misconfiguration/security flaw incl. buffer overflow)
    - Designed and coded to be modular and extendable. Adding new checks should simply entail adding new methods.
- sfuzz:黑盒模糊测试工具
  >simple fuzz is exactly what it sounds like – a simple fuzzer. don’t mistake simple with a lack of fuzz capability. this fuzzer has two network modes of operation, an output mode for developing command line fuzzing scripts, as well as taking fuzzing strings from literals and building strings from sequences.

  >simple fuzz is built to fill a need – the need for a quickly configurable black box testing utility that doesn’t require intimate knowledge of the inner workings of C or require specialized software rigs. the aim is to just provide a simple interface, clear inputs/outputs, and reusability.

  >Features:

    - simple script language for creating test cases
    - support for repeating strings as well as fixed strings (‘sequences’ vs. ‘literals’)
    - variables within test cases (ex: strings to be replaced with different strings)
    - tcp and udp payload transport (icmp support tbd)
    - binary substitution support (see basic.a11 for more information)
    - plugin support (NEW!) see plugin.txt for more information.
    - previous packet contents inclusion
- SidGuesser：用字典探测oracle数据库存在的sid
  >Guesses sids/instances against an Oracle database according to a predefined dictionary file. The speed is slow (80-100 guesses per second) but it does the job.
- SIPArmyKnife：SIP瑞士军刀是一个模糊器的搜索跨站脚本，SQL注入，登录注入，格式化字符串，缓冲区溢出等。
  >SIP Army Knife is a fuzzer that searches for cross site scripting, SQL injection, log injection, format strings, buffer overflows, and more.
- sqlmap:SQLmap是一款用来检测与利用SQL注入漏洞的免费开源工具，有一个非常棒的特性，即对检测与利用的自动化处理（数据库指纹、访问底层文件系统、执行命令）。
  >sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

  >Features:

    - Full support for MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase and SAP MaxDB database management systems.
    - Full support for six SQL injection techniques: boolean-based blind, time-based blind, error-based, UNION query, stacked queries and out-of-band.
    - Support to directly connect to the database without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
    - Support to enumerate users, password hashes, privileges, roles, databases, tables and columns.
    - Automatic recognition of password hash formats and support for cracking them using a dictionary-based attack.
    - Support to dump database tables entirely, a range of entries or specific columns as per user’s choice. The user can also choose to dump only a range of characters from each column’s entry.
    - Support to search for specific database names, specific tables across all databases or specific columns across all databases’ tables. This is useful, for instance, to identify tables containing custom application credentials where relevant columns’ names contain string like name and pass.
    - Support to download and upload any file from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to execute arbitrary commands and retrieve their standard output on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to establish an out-of-band stateful TCP connection between the attacker machine and the database server underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user’s choice.
    - Support for database process’ user privilege escalation via Metasploit’s Meterpreter getsystem command.
- Sqlninja:一个专门针对Microsoft SQL Server的sql注入工具,可找到远程SQL服务器的标志和特征(版本、用户执行的查询、用户特权、xp_cmdshell的可用性、身份验证模式等),“sa”口令的强力攻击,如果找到口令后，就将特权提升到“sa”,如果原始的xp_cmdshell被禁用后，就创建一个定制的xp_cmdshell。使用纯粹的ASCII GET/POST请求来上载netcat.exe程序(以及其它任何可执行的程序)，因此并不需要FTP连接。为了找到目标网络的防火墙所允许的端口，可以实施针对目标SQL　服务器的TCP/UDP端口扫描。逃避技术，这是为了使注入式代码“模糊”不清，并且混淆/绕过基于签名的IPS和应用层防火墙。采用“盲目执行”攻击模式，在其它模式失效时，可以用于发布命令并执行诊断。在sqlninja生成的SQL代码上，执行的是自动化的URL编码，这使得用户可以更精细地控制漏洞利用的字符串。如果得到权限为sa，可以结合msf进一步对目标主机进行渗透。
  >Fancy going from a SQL Injection on Microsoft SQL Server to a full GUI access on the DB? Take a few new SQL Injection tricks, add a couple of remote shots in the registry to disable Data Execution Prevention, mix with a little Perl that automatically generates a debug script, put all this in a shaker with a Metasploit wrapper, shake well and you have just one of the attack modules of sqlninja!

  >Sqlninja is a tool targeted to exploit SQL Injection vulnerabilities on a web application that uses Microsoft SQL Server as its back-end.

  >Its main goal is to provide a remote access on the vulnerable DB server, even in a very hostile environment. It should be used by penetration testers to help and automate the process of taking over a DB Server when a SQL Injection vulnerability has been discovered.
- sqlsus:sqlsus是使用Perl语言编写的MySQL注入和接管工具。它可以获取数据库结构，实施注入查询，下载服务器的文件，爬取可写目录并写入后门，以及复制数据库文件等功能。它提供Inband和盲注两种注入模式，获取数据库权限。使用时，用户首先使用该工具生成一个配置文件。在配置文件中，设置注入路径以及注入的各项参数，然后再加载该文件，实施渗透测试。
  >sqlsus is an open source MySQL injection and takeover tool, written in perl.

  >Via a command line interface, you can retrieve the database(s) structure, inject your own SQL queries (even complex ones), download files from the web server, crawl the website for writable directories, upload and control a backdoor, clone the database(s), and much more…
  >Whenever relevant, sqlsus will mimic a MySQL console output.

  >sqlsus focuses on speed and efficiency, optimizing the available injection space, making the best use (I can think of) of MySQL functions.
  >It uses stacked subqueries and an powerful blind injection algorithm to maximize the data gathered per web server hit.
  >Using multi-threading on top of that, sqlsus is an extremely fast database dumper, be it for inband or blind injection.

  >If the privileges are high enough, sqlsus will be a great help for uploading a backdoor through the injection point, and takeover the web server.

  >It uses SQLite as a backend, for an easier use of what has been dumped, and integrates a lot of usual features (see below) such as cookie support, socks/http proxying, https.
- THC-IPV6:THC-IPV6是一套完整的工具包，可用来攻击IPV6和ICMP6协议的固有弱点，THC-IPV6包含了易用的库文件，可二次开发。THC-IPV6由先进的主机存活扫描工具，中间人攻击工具，拒绝服务攻击工具构成。
  >A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
- tnscmd10g:Oracle服务器通常都配置TNS，用来管理和配置客户端和数据库的连接。每个Oracle服务器都会运行一个TNS监听器进程tnslsnr用来处理客户端和服务器的数据传输。该接口默认工作在TCP 1521端口。由于该监听器在验证请求的身份之前，可以对部分命令进行响应，所以造成一定程度的漏洞。Kali Linux提供的tnscmd10g工具可以利用该漏洞。使用该工具，用户可以获取数据库的版本信息、服务信息、配置信息，甚至可以关闭TNS服务，导致客户端无法连接服务器。
  >A tool to prod the oracle tnslsnr process on port 1521/tcp.
- unix-privesc-check:unix-privesc-check是Kali Linux自带的一款提权漏洞检测工具。它是一个Shell文件，可以检测所在系统的错误配置，以发现可以用于提权的漏洞。该工具适用于安全审计、渗透测试和系统维护等场景。它可以检测与权限相关的各类文件的读写权限，如认证相关文件、重要配置文件、交换区文件、cron job文件、设备文件、其他用户的家目录、正在执行的文件等等。如果发现可以利用的漏洞，就会给出提示warning。unix-privesc-check并不会检测所有提权漏洞的潜在情况。它只是快速进行检测，并以简洁的方式给出提权漏洞相关的建议，大大减少用户在文件权限检测方面的枯燥工作的量。
  >Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases). It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).
- Yersinia:Yersinia 是国外的一款专门针对交换机的攻击工具。它现在的最新版本是0.7.1。Yersinia主要是针对交换机上运行的一些网络协议进行的攻击，截至到现在，可以完成的攻击协议见下面的列表，针对这些网络协议，Yersinia攻击的实现方式也是这个软件最大的特点是，他可以根据攻击者的需要和网络协议自身存在的漏洞，通过伪造一些特定的协议信息或协议包来实现对这些网络协议的破坏以达到攻击目的。
  >Yersinia is a framework for performing layer 2 attacks. It is designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. Attacks for the following network protocols are implemented in this particular release:

    - Spanning Tree Protocol (STP)
    - Cisco Discovery Protocol (CDP)
    - Dynamic Trunking Protocol (DTP)
    - Dynamic Host Configuration Protocol (DHCP)
    - Hot Standby Router Protocol (HSRP)
    - 802.1q
    - 802.1x
    - Inter-Switch Link Protocol (ISL)
    - VLAN Trunking Protocol (VTP)

## Web Applications - Web应用

- apache-users:Apache用户目录枚举工具apache-users,Apache服务器提供UserDir模块，允许在网站为不同的用户设置对应的目录。这样，用户可以使用http://example.com/~user/的方式访问对应的网站目录。Kali Linux提供apache-users工具用来暴力枚举用户，找出对应的目录，以便后期获取网站结构。该工具使用Perl语言编写，支持字典破解、SSL加密、非默认端口、多线程等功能。

  >This Perl script will enumerate the usernames on any system that uses Apache with the UserDir module.
- Arachni:一个多功能、模块化、高性能的Ruby框架，旨在帮助渗透测试人员和管理员评估web应用程序的安全性。同时Arachni开源免费，可安装在windows、linux以及mac系统上，并且可导出评估报告。可以扫描的漏洞类型比较多，都是一个个的模块。
  >Arachni is an Open Source, feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications.

  >It is smart, it trains itself by learning from the HTTP responses it receives during the audit process and is able to perform meta-analysis using a number of factors in order to correctly assess the trustworthiness of results and intelligently identify false-positives.

  >It is versatile enough to cover a great deal of use cases, ranging from a simple command line scanner utility, to a global high performance grid of scanners, to a Ruby library allowing for scripted audits, to a multi-user multi-scan web collaboration platform.
- BBQSQL:BBQSQL是一个用Python写的SQL盲注框架。对于棘手的SQL注入漏洞攻击非常有用。bbqsql也是一个半自动的工具，对于那些难以触发SQL注入有比较多的定制。该工具与数据库类型无关并且非常灵活。它也有一个直观的用户界面，使攻击设置更容易。Python Gevent也被实现，使bbqsql速度非常快。http://www.mottoin.com/90324.html
  >Blind SQL injection can be a pain to exploit. When the available tools work they work well, but when they don’t you have to write something custom. This is time-consuming and tedious. BBQSQL can help you address those issues.

  >BBQSQL is a blind SQL injection framework written in Python. It is extremely useful when attacking tricky SQL injection vulnerabilities. BBQSQL is also a semi-automatic tool, allowing quite a bit of customization for those hard to trigger SQL injection findings. The tool is built to be database agnostic and is extremely versatile. It also has an intuitive UI to make setting up attacks much easier. Python gevent is also implemented, making BBQSQL extremely fast.

  >Similar to other SQL injection tools you provide certain request information.

  >Must provide the usual information:

    - URL
    - HTTP Method
    - Headers
    - Cookies
    - Encoding methods
    - Redirect behavior
    - Files
    - HTTP Auth
    - Proxies
    - Then specify where the injection is going and what syntax we are injecting.
- BlindElephant:是一款Web应用程序指纹识别工具。该工具可以读取目标网站的特定静态文件，计算其对应的哈希值，然后和预先计算出的哈希值做对比，从而判断目标网站的类型和版本号。目前，该工具支持15种常见的Web应用程序的几百个版本。同时，它还提供WordPress和Joomla的各种插件。该工具还允许用户自己扩展，添加更多的版本支持。

  >The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable.
- Burp Suite:Burp Suite是Web应用程序测试的最佳工具之一，其多种功能可以帮我们执行各种任务.请求的拦截和修改,扫描web应用程序漏洞,以暴力破解登陆表单,执行会话令牌等多种的随机性检查。
  >Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, through to finding and exploiting security vulnerabilities.

  >Burp gives you full control, letting you combine advanced manual techniques with state-of-the-art automation, to make your work faster, more effective, and more fun.
- CutyCapt:linux命令行抓取网页快照图片
  >CutyCapt is a small cross-platform command-line utility to capture WebKit’s rendering of a web page into a variety of vector and bitmap formats, including SVG, PDF, PS, PNG, JPEG, TIFF, GIF, and BMP.
- DAVTest:WebDAV是基于Web服务的扩展服务。它允许用户像操作本地文件一样，操作服务器上的文件。借助该功能，用户很方便的在网络上存储自己的文件。为了方便用户使用，通常会提供给用户较大的文件权限，如上传、修改甚至是执行权限。Kali Linux提供了一款WebDAV服务漏洞利用工具DAVTest。该工具会自动检测权限，寻找可执行文件的权限。一旦发现，用户就可以上传内置的后门工具，对服务器进行控制。同时，该工具可以上传用户指定的文件，便于后期利用。
  >DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable.

  >DAVTest supports:

    - Automatically send exploit files
    - Automatic randomization of directory to help hide files
    - Send text files and try MOVE to executable name
    - Basic and Digest authorization
    - Automatic clean-up of uploaded files
    - Send an arbitrary file
- deblaze:针对FLASH远程调用等的枚举，一般在xss或者较深入的web安全中可能会用到
  >Through the use of the Flex programming model and the ActionScript language, Flash Remoting was born. Flash applications can make request to a remote server to call server side functions, such as looking up accounts, retrieving additional data and graphics, and performing complex business operations. However, the ability to call remote methods also increases the attack surface exposed by these applications. This tool will allow you to perform method enumeration and interrogation against flash remoting end points. Deblaze came about as a necessity during a few security assessments of flash based websites that made heavy use of flash remoting. I needed something to give me the ability to dig a little deeper into the technology and identify security holes. On all of the servers I’ve seen so far the names are not case sensitive, making it much easier to bruteforce. Often times HTTP POST requests won’t be logged by the server, so bruteforcing may go unnoticed on poorly monitored systems.

  >Deblaze provides the following functionality:

    - Brute Force Service and Method Names
    - Method Interrogation
    - Flex Technology Fingerprinting
- DIRB:Web内容扫描器,比如可以用来发现后台登陆地址
  >DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the response.

  >DIRB comes with a set of preconfigured attack wordlists for easy usage but you can use your custom wordlists. Also DIRB sometimes can be used as a classic CGI scanner, but remember is a content scanner not a vulnerability scanner.

  >DIRB main purpose is to help in professional web application auditing. Specially in security related testing. It covers some holes not covered by classic web vulnerability scanners. DIRB looks for specific web objects that other generic CGI scanners can’t look for. It doesn’t search vulnerabilities nor does it look for web contents that can be vulnerables.
- DirBuster:是一个多线程的基于Java的应用程序设计暴力扫描Web /应用服务器上的目录和文件名 。寻找敏感的目录文件和文 件夹在Web应用程序渗透测试始终是一个相当艰巨的工作。 现在我们往往看不到这些默认安装的文件/目录，在昔日找出敏感的页面真的被挑战。在这种情况下，DirBuster有助于发现那些未知的和敏感的文件名 和目录。这可以证明是一个伟大的信息，开始在一个真正的Web渗透测试。 
  >DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these. However tools of this nature are often as only good as the directory and file list they come with. A different approach was taken to generating this. The list was generated from scratch, by crawling the Internet and collecting the directory and files that are actually used by developers! DirBuster comes a total of 9 different lists, this makes DirBuster extremely effective at finding those hidden files and directories. And if that was not enough DirBuster also has the option to perform a pure brute force, which leaves the hidden directories and files nowhere to hide.
- fimap:文件包含漏洞检测工具fimap,在Web应用中，文件包含漏洞（FI）是常见的漏洞。根据包含的文件不同，它分为本地文件包含漏洞（LFI）和远程文件包含漏洞（RFL）。利用该漏洞，安全人员可以获取服务器的文件信息，执行恶意脚本，获取服务器控制权限。Kali Linux提供文件漏洞包含漏洞检测专项工具fimap。该工具可以对单一目标、多个目标进行扫描，甚至可以通过谷歌网站搜索可能的漏洞网站。它可以自动判断文件包含漏洞，对于没有错误信息返回的，还可以进行盲测。它还支持截断功能，来利用该漏洞。同时，该工具提供插件，以增强该工具的功能。
  >fimap is a little python tool which can find, prepare, audit, exploit and even google automaticly for local and remote file inclusion bugs in webapps. fimap should be something like sqlmap just for LFI/RFI bugs instead of sql injection. It’s currently under heavy development but it’s usable.
- FunkLoad:FunkLoad是一个功能和负载的Web测试仪，主要的用于Web项目（进行回归测试），性能测试，负载测试（如音量的测试或寿命测试），压力测试的 功能。它也可以用来编写Web代理脚本的任何Web重复性的任务。 FunkLoad 是一个网站项目的功能、性能测试工具。
  >FunkLoad is a functional and load web tester, written in Python, whose main use cases are:

    - Functional testing of web projects, and thus regression testing as well.
    - Performance testing: by loading the web application and monitoring your servers it helps you to pinpoint bottlenecks, giving a detailed report of performance measurement.
    - Load testing tool to expose bugs that do not surface in cursory testing, like volume testing or longevity testing.
    - Stress testing tool to overwhelm the web application resources and test the application recoverability.
    - Writing web agents by scripting any web repetitive task.
- Gobuster:子域名/目录暴力工具Gobuster,Gobuster是Kali Linux默认安装的一款暴力扫描工具。它是使用Go语言编写的命令行工具，具备优异的执行效率和并发性能。该工具支持对子域名和Web目录进行基于字典的暴力扫描。不同于其他工具，该工具支持同时多扩展名破解，适合采用多种后台技术的网站。实施子域名扫描时，该工具支持泛域名扫描，并允许用户强制继续扫描，以应对泛域名解析带来的影响。
  >Gobuster is a tool used to brute-force:

    - URIs (directories and files) in web sites.
    - DNS subdomains (with wildcard support).
- Grabber:小型Web应用扫描工具Grabber。Grabber是Kali Linux集成的一款Web应用扫描工具。该工具适合中小Web应用，如个人博客、论坛等。该工具使用Python语言编写，支持常见的漏洞检测，如XSS、SQL注入、文件包含、备份文件检测、Ajax检测、Crytal Ball检测等功能。该工具只进行扫描，不实施漏洞利用。由于功能简单，所以使用非常方便，用户只要指定扫描目标和检测项目后，就可以进行扫描了。

  >Grabber is a web application scanner. Basically it detects some kind of vulnerabilities in your website. Grabber is simple, not fast but portable and really adaptable. This software is designed to scan small websites such as personals, forums etc. absolutely not big application: it would take too long time and flood your network.

  >Features:

    - Cross-Site Scripting
    - SQL Injection (there is also a special Blind SQL Injection module)
    - File Inclusion
    - Backup files check
    - Simple AJAX check (parse every JavaScript and get the URL and try to get the parameters)
    - Hybrid analysis/Crystal ball testing for PHP application using PHP-SAT
    - JavaScript source code analyzer: Evaluation of the quality/correctness of the JavaScript with JavaScript Lint
    - Generation of a file [session_id, time(t)] for next stats analysis.
- hURL:编码/解码和进制转化工具hURL。在安全应用中，各种编码方式被广泛应用，如URL编码、HTML编码、BASE64等。而在数据分析时候，各种进制的转化也尤为频繁。为了方便解决这类问题，Kali Linux提供了一个专用小工具hURL。该工具能实现常见的编码和解码操作，如URL、双URL、BASE64、HTML、ROT13。同时，它支持二进制、八进制、十进制、十六进制的互相转化。此外，它还提供常见的哈希加密，如SHA1、SHA224、SHA256、SHA384、SHA512、MD5。为了便于用户实施反汇编，它还提供了入栈转化、网络字节码转化等功能。
  >hURL is a small utility that can encode and decode between multiple formats.
- jboss-autopwn:这个JBOSS脚本会在目标JBOSS服务器上部署一个JSP Shell，部署成功后，渗透测试人员可以获得一个交互式会话，可以进行命令执行等工作。
  >This JBoss script deploys a JSP shell on the target JBoss AS server. Once deployed, the script uses its upload and command execution capability to provide an interactive session.

  >Features include:

    - Multiplatform support – tested on Windows, Linux and Mac targets
    - Support for bind and reverse bind shells
    - Meterpreter shells and VNC support for Windows targets
- joomscan:Joomla!网站扫描工具joomscan,Joomla!是一款知名的PHP语言编写的CMS系统。很多网站都使用Joomla!搭建而成。Kali Linux集成了一款Joomla!网站扫描工具joomscan。该工具不仅可以对网站所使用的Joomla!版本、防火墙进行探测，还可以探测已知的漏洞，并生成文本或网页形式的报告。在使用之前，用户应该先使用自带的check和update命令升级该工具，以获取最新的扫描工具和漏洞数据库。

  >Joomla! is probably the most widely-used CMS out there due to its flexibility, user-friendlinesss, extensibility to name a few. So, watching its vulnerabilities and adding such vulnerabilities as KB to Joomla scanner takes ongoing activity. It will help web developers and web masters to help identify possible security weaknesses on their deployed Joomla! sites.

  >The following features are currently available:

    - Exact version Probing (the scanner can tell whether a target is running version 1.5.12)
    - Common Joomla! based web application firewall detection
    - Searching known vulnerabilities of Joomla! and its components
    - Reporting to Text & HTML output
    - Immediate update capability via scanner or svn
- jSQL:一款轻量级安全测试工具，可以检测SQL注入漏洞。
  >jSQL Injection is a lightweight application used to find database information from a distant server. jSQL is free, open source and cross-platform (Windows, Linux, Mac OS X, Solaris).
- Maltego Teeth:Maltego是一个开源的漏洞评估工具，它主要用于论证一个网络内单点故障的复杂性和严重性。该工具能够聚集来自内部和外部资源的信息，并且提供一个清晰的漏洞分析界面。
  >Maltego is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. Maltego’s unique advantage is to demonstrate the complexity and severity of single points of failure as well as trust relationships that exist currently within the scope of your infrastructure.

  >The unique perspective that Maltego offers to both network and resource based entities is the aggregation of information posted all over the internet – whether it’s the current configuration of a router poised on the edge of your network or the current whereabouts of your Vice President on his international visits, Maltego can locate, aggregate and visualize this information.

  >Maltego offers the user with unprecedented information. Information is leverage. Information is power. Information is Maltego.

  >What does Maltego do?

  >Maltego is a program that can be used to determine the relationships and real world links between:

    - People
    - Groups of people (social networks)
    - Companies
    - Organizations
    - Web sites
    - Internet infrastructure such as:
    - Domains
    - DNS names
    - Netblocks
    - IP addresses
    - Phrases
    - Affiliations
    - Documents and files
    - These entities are linked using open source intelligence.
    - Maltego is easy and quick to install – it uses Java, so it runs on Windows, Mac and Linux.
    - Maltego provides you with a graphical interface that makes seeing these relationships instant and accurate – making it possible to see hidden connections.
    - Using the graphical user interface (GUI) you can see relationships easily – even if they are three or four degrees of separation away.
    - Maltego is unique because it uses a powerful, flexible framework that makes customizing possible. As such, Maltego can be adapted to your own, unique requirements.
  >What can Maltego do for me?

    - Maltego can be used for the information gathering phase of all security related work. It will save you time and will allow you to work more accurately and smarter.
    - Maltego aids you in your thinking process by visually demonstrating interconnected links between searched items.
    - Maltego provide you with a much more powerful search, giving you smarter results.
    - If access to “hidden” information determines your success, Maltego can help you discover it.
- PadBuster:一个自动执行Padding Oracle Attack攻击的工具
  >PadBuster is a Perl script for automating Padding Oracle Attacks. PadBuster provides the capability to decrypt arbitrary ciphertext, encrypt arbitrary plaintext, and perform automated response analysis to determine whether a request is vulnerable to padding oracle attacks.
- Paros: Paros proxy是一个对Web应用程序的漏洞进行评估的代理程序，它支持动态地查看/编辑 HTTP/HTTPS信息，可以改变cookies和表单字段中的内容。它包括一个Web通信记录程序、Web爬虫程序（Web Spider），Hash计算器，还有一个可以测试常见的Web应用程序攻击（如SQL注入式攻击和跨站脚本攻击）的扫描器。
  >A Java based HTTP/HTTPS proxy for assessing web application vulnerability. It supports editing/viewing HTTP messages on-the-fly. Other featuers include spiders, client certificate, proxy-chaining, intelligent scanning for XSS and SQL injections etc.
- Parsero:网站robots.txt探测工具Parsero,robots.txt文件是网站根目录下的一个文本文件。robots.txt是搜索引擎中访问网站的时候要查看的第一个文件。当搜索引擎访问一个站点时，它会首先检查该站点根目录下是否存在robots.txt。如果存在，搜索引擎就会按照该文件中的内容来确定访问的范围；如果该文件不存在，则会够访问网站上所有没有被口令保护的所有页面。网站为了防止搜索引擎访问一些重要的页面，会把其所在的目录放入robots.txt文件中。所以，探测该文件，也可以获取网站的重要信息。Kali Linux提供一个小工具Parsero，可以探测指定网站的robots.txt文件，并确认实际可访问性。PS：该工具需要用户使用apt-get命令手动安装。
  >Parsero is a free script written in Python which reads the Robots.txt file of a web server and looks at the Disallow entries. The Disallow entries tell the search engines what directories or files hosted on a web server mustn’t be indexed. For example, “Disallow: /portal/login” means that the content on www.example.com/portal/login it’s not allowed to be indexed by crawlers like Google, Bing, Yahoo… This is the way the administrator have to not share sensitive or private information with the search engines.

  >But sometimes these paths typed in the Disallows entries are directly accessible by the users without using a search engine, just visiting the URL and the Path, and sometimes they are not available to be visited by anybody… Because it is really common that the administrators write a lot of Disallows and some of them are available and some of them are not, you can use Parsero in order to check the HTTP status code of each Disallow entry in order to check automatically if these directories are available or not.

  >Also, the fact the administrator write a robots.txt, it doesn’t mean that the files or directories typed in the Dissallow entries will not be indexed by Bing, Google, Yahoo… For this reason, Parsero is capable of searching in Bing to locate content indexed without the web administrator authorization. Parsero will check the HTTP status code in the same way for each Bing result.
- plecost:WordPress插件扫描工具plecost,WordPress是PHP语言开发的博客平台。该平台允许用户通过插件方式扩展博客功能。由于部分插件存在漏洞，给整个网站带来安全风险。Kali Linux提供一款专用WordPress插件扫描工具plecost。该工具能够识别7000多种PHP插件。它默认会依次扫描所有的插件，识别插件版本号，并提示可能关联的CVE漏洞。该工具提供丰富的选项，允许用户控制扫描范围和方式，实现快速扫描。同时，该工具提供类似sqlmap的功能，允许用户通过Google搜素引擎发现存在漏洞的博客网站。
 


  >WordPress finger printer tool, plecost search and retrieve information about the plugins versions installed in WordPress systems. It can analyze a single URL or perform an analysis based on the results indexed by Google. Additionally displays CVE code associated with each plugin, if there. Plecost retrieves the information contained on Web sites supported by WordPress, and also allows a search on the results indexed by Google.
- Powerfuzzer:Web模糊测试工具Powerfuzzer,Powerfuzzer是Kali Linux自带的一款Web模糊测试工具。该工具基于各种开源模糊测试工具构建，集成了大量安全信息。该工具高度智能化，它能根据用户输入的网址进行自动识别XSS、SQL注入、CRLF、HTTP500等漏洞。同时，用户可以指定用户和密码等身份验证信息，也可以指定Cookie信息。同时，用户可以直接指定该工具是否使用代理。由于该工具开发较早，对非ASCII编码（如包含中文的网站）网站支持不好，分析中文网站容易出现异常错误。

  >Powerfuzzer is a highly automated and fully customizable web fuzzer (HTTP protocol based application fuzzer) based on many other Open Source fuzzers available and information gathered from numerous security resources and websites. It was designed to be user friendly, modern, effective and working.

  >Currently, it is capable of identifying these problems:

    - Cross Site Scripting (XSS)
    - Injections (SQL, LDAP, code, commands, and XPATH)
    - CRLF
    - HTTP 500 statuses (usually indicative of a possible misconfiguration/security flaw incl. buffer overflow)
    - Designed and coded to be modular and extendable. Adding new checks should simply entail adding new methods.
- ProxyStrike:Web会话安全分析工具ProxyStrike,在Web应用中，客户端发出一次请求，服务器响应一次。这构成一个完整的会话。通过分析请求和响应的数据，可以发现Web应用存在的漏洞。Kali Linux提供一款专用工具ProxyStrike。该工具提供HTTP代理功能，可以跟踪HTTP会话信息，并进行分析统计。同时，该工具也提供拦截功能，安全人员可以对每个会话进行分析和修改，以获取服务器的不同响应。该工具还通过插件模式，提供安全扫描功能。该工具默认集成SQL注入和XSS两个插件。在捕获会话的同时，该工具会自动进行安全检测，以发现目标服务器存在的漏洞。安全人员也可以使用该工具对目标网站进行爬取，以搜集更多的网站资源，并同时进行安全检测。
  >ProxyStrike is an active Web Application Proxy. It’s a tool designed to find vulnerabilities while browsing an application. It was created because the problems we faced in the pentests of web applications that depends heavily on Javascript, not many web scanners did it good in this stage, so we came with this proxy.

  >Right now it has available Sql injection and XSS plugins. Both plugins are designed to catch as many vulnerabilities as we can, it’s that why the SQL Injection plugin is a Python port of the great DarkRaver “Sqlibf”.

  >The process is very simple, ProxyStrike runs like a proxy listening in port 8008 by default, so you have to browse the desired web site setting your browser to use ProxyStrike as a proxy, and ProxyStrike will analyze all the paremeters in background mode. For the user is a passive proxy because you won’t see any different in the behaviour of the application, but in the background is very active. :)

  >Some features:

    - Plugin engine (Create your own plugins!)
    - Request interceptor
    - Request diffing
    - Request repeater
    - Automatic crawl process
    - Http request/response history
    - Request parameter stats
    - Request parameter values stats
    - Request url parameter signing and header field signing
    - Use of an alternate proxy (tor for example ;D )
    - Sql attacks (plugin)
    - Server Side Includes (plugin)
    - Xss attacks (plugin)
    - Attack logs
    - Export results to HTML or XML
- Recon-ng:Recon-ng是一个全面的web探测框架，它由python编写，有着独立的模块、数据库交互功能、交互式帮助提示和命令补全的特性。它提供了一个强大的开源web探测机制，帮助测试人员快速彻底地进行探测。Recon-ng框架简介:Recon-ng的使用和模式与主流的metasploit框架有点类似，这减少了用户学习利用该框架的难度。当然，Recon-ng也有着自己的特点，其为基于web的开源探测工具。如果你想要进行exp利用，请使用metasploit框架。如果你想进行社工，请使用社工工具包。如果你想进行被动探测，请使用Recon-ng。至于主动检测工具的例子，大家可以看看谷歌安全团队的Skipfish。Recon-ng是一个完全模块化的框架，新的python开发者也能很容易地进行模块贡献。每一个模块都是“module”类的子类，“module”类是一个定制的“cmd”解释器，内置提供了常用任务（如标准输出、数据库交互、进行web请求和API key管理）的简单接口。可以说，基本所有复杂的工作都已经被作者完成。我们想要构建新的模块会非常简单，仅仅需要几分钟。

  >Recon-ng约有80个recon模块，2个发现模块，2个exp利用模块，7个报告模块和2个导入模块：
    - cache_snoop – DNS缓存录制
    - interesting_files – 敏感文件探测
    - command_injector – 远程命令注入shell接口
    - xpath_bruter – Xpath注入爆破
    - csv_file – 高级csv文件导入
    - list – List文件导入
    - point_usage – Jigsaw – 统计信息提取用法
    - purchase_contact – Jigsaw – 简单的联系查询
    - search_contacts – Jigsaw联系枚举
    - jigsaw_auth – Jigsaw认证联系枚举
    - linkedin_auth – LinkedIn认证联系枚举
    - github_miner – Github资源挖掘
    - whois_miner – Whois数据挖掘
    - bing_linkedin – Bing Linkedin信息采集
    - email_validator – SalesMaple邮箱验证
    - mailtester – MailTester邮箱验证
    - mangle – 联系分离
    - unmangle –联系反分离
    - hibp_breach –Breach搜索
    - hibp_paste – Paste搜索
    - pwnedlist – PwnedList验证
    - migrate_contacts – 域名数据迁移联系
    - facebook_directory – Facebook目录爬行
    - fullcontact – FullContact联系枚举
    - adobe – Adobe Hash破解
    - bozocrack – PyBozoCrack Hash 查询
    - hashes_org – Hashes.org Hash查询
    - leakdb – leakdb Hash查询
    - metacrawler – 元数据提取
    - pgp_search – PGP Key Owner查询
    - salesmaple – SalesMaple联系获取
    - whois_pocs – Whois POC获取
    - account_creds – PwnedList – 账户认证信息获取
    - api_usage – PwnedList – API使用信息
    - domain_creds – PwnedList – Pwned域名认证获取
    - domain_ispwned – PwnedList – Pwned域名统计获取
    - leak_lookup – PwnedList – 泄露信息查询
    - leaks_dump – PwnedList –泄露信息获取
    - brute_suffix – DNS公共后缀爆破
    - baidu_site – Baidu主机名枚举
    - bing_domain_api – Bing API主机名枚举
    - bing_domain_web – Bing主机名枚举
    - brute_hosts – DNS主机名爆破
    - builtwith – BuiltWith枚举
    - google_site_api – Google CSE主机名枚举
    - google_site_web – Google主机名枚举
    - netcraft – Netcraft主机名枚举
    - shodan_hostname – Shodan主机名枚举
    - ssl_san – SSL SAN查询
    - vpnhunter – VPNHunter查询
    - yahoo_domain – Yahoo主机名枚举
    - zone_transfer – DNS域文件收集
    - ghdb – Google Hacking数据库
    - punkspider – PunkSPIDER漏洞探测
    - xssed – XSSed域名查询
    - xssposed – XSSposed域名查询
    - migrate_hosts – 域名数据迁移host
    - bing_ip – Bing API旁站查询
    - freegeoip –FreeGeoIP ip定位查询
    - ip_neighbor – My-IP-Neighbors.com查询
    - ipinfodb – IPInfoDB GeoIP查询
    - resolve – 主机名解析器
    - reverse_resolve – 反解析
    - ssltools – SSLTools.com主机名查询
    - geocode – 地理位置编码
    - reverse_geocode – 反地理位置编码
    - flickr – Flickr地理位置查询
    - instagram – Instagram地理位置查询
    - picasa – Picasa地理位置查询
    - shodan – Shodan地理位置查询
    - twitter – Twitter地理位置查询
    - whois_orgs – Whois公司信息收集
    - reverse_resolve – 反解析
    - shodan_net – Shodan网络枚举
    - census_2012 – Internet Census 2012 查询
    - sonar_cio – Project Sonar查询
    - migrate_ports – 主机端口数据迁移
    - dev_diver – Dev Diver Repository检查
    - linkedin – Linkedin联系获取
    - linkedin_crawl – Linkedin信息抓取
    - namechk – NameChk.com用户名验证
    - profiler – OSINT HUMINT信息收集
    - twitter – Twitter操作
    - github_repos – Github代码枚举
    - gists_search – Github Gist搜索
    - github_dorks – Github Dork分析
    - csv – CSV文件生成
    - html – HTML报告生成
    - json – JSON报告生成
    - list – List生成
    - pushpin – PushPin报告生成
    - xlsx – XLSX文件创建
    - xml – XML报告生成
- Skipfish:Web应用主动侦测工具Skipfish,Skipfish是Kali Linux附带的一个主动Web应用侦测工具。该工具会首先尽可能获取所有网站路径，进行访问，然后根据返回的内容，检测是否存在漏洞。该工具采用字典爆破和网页爬行两种方式获取网站。一旦获取网页内容，该工具会自动分析网页内容，扩充字典，从而提高爆破效率。同时，该工具提供特征码文件，对网页内容进行分析，以发现潜在漏洞。用户可以根据需要，扩充预置的特征文件，加强扫描功能。
  >Skipfish is an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks. The final report generated by the tool is meant to serve as a foundation for professional web application security assessments.

  >Key features:

    - High speed: pure C code, highly optimized HTTP handling, minimal CPU footprint – easily achieving 2000 requests per second with responsive targets.
    - Ease of use: heuristics to support a variety of quirky web frameworks and mixed-technology sites, with automatic learning capabilities, on-the-fly wordlist creation, and form autocompletion.
    - Cutting-edge security logic: high quality, low false positive, differential security checks, capable of spotting a range of subtle flaws, including blind injection vectors.
- sqlmap:SQLmap是一款用来检测与利用SQL注入漏洞的免费开源工具，有一个非常棒的特性，即对检测与利用的自动化处理（数据库指纹、访问底层文件系统、执行命令）。
  >sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

  >Features:

    - Full support for MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase and SAP MaxDB database management systems.
    - Full support for six SQL injection techniques: boolean-based blind, time-based blind, error-based, UNION query, stacked queries and out-of-band.
    - Support to directly connect to the database without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
    - Support to enumerate users, password hashes, privileges, roles, databases, tables and columns.
    - Automatic recognition of password hash formats and support for cracking them using a dictionary-based attack.
    - Support to dump database tables entirely, a range of entries or specific columns as per user’s choice. The user can also choose to dump only a range of characters from each column’s entry.
    - Support to search for specific database names, specific tables across all databases or specific columns across all databases’ tables. This is useful, for instance, to identify tables containing custom application credentials where relevant columns’ names contain string like name and pass.
    - Support to download and upload any file from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to execute arbitrary commands and retrieve their standard output on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to establish an out-of-band stateful TCP connection between the attacker machine and the database server underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user’s choice.
    - Support for database process’ user privilege escalation via Metasploit’s Meterpreter getsystem command.
- Sqlninja:一个专门针对Microsoft SQL Server的sql注入工具,可找到远程SQL服务器的标志和特征(版本、用户执行的查询、用户特权、xp_cmdshell的可用性、身份验证模式等),“sa”口令的强力攻击,如果找到口令后，就将特权提升到“sa”,如果原始的xp_cmdshell被禁用后，就创建一个定制的xp_cmdshell。使用纯粹的ASCII GET/POST请求来上载netcat.exe程序(以及其它任何可执行的程序)，因此并不需要FTP连接。为了找到目标网络的防火墙所允许的端口，可以实施针对目标SQL　服务器的TCP/UDP端口扫描。逃避技术，这是为了使注入式代码“模糊”不清，并且混淆/绕过基于签名的IPS和应用层防火墙。采用“盲目执行”攻击模式，在其它模式失效时，可以用于发布命令并执行诊断。在sqlninja生成的SQL代码上，执行的是自动化的URL编码，这使得用户可以更精细地控制漏洞利用的字符串。如果得到权限为sa，可以结合msf进一步对目标主机进行渗透。
  >Fancy going from a SQL Injection on Microsoft SQL Server to a full GUI access on the DB? Take a few new SQL Injection tricks, add a couple of remote shots in the registry to disable Data Execution Prevention, mix with a little Perl that automatically generates a debug script, put all this in a shaker with a Metasploit wrapper, shake well and you have just one of the attack modules of sqlninja!

  >Sqlninja is a tool targeted to exploit SQL Injection vulnerabilities on a web application that uses Microsoft SQL Server as its back-end.

  >Its main goal is to provide a remote access on the vulnerable DB server, even in a very hostile environment. It should be used by penetration testers to help and automate the process of taking over a DB Server when a SQL Injection vulnerability has been discovered.
- sqlsus:sqlsus是使用Perl语言编写的MySQL注入和接管工具。它可以获取数据库结构，实施注入查询，下载服务器的文件，爬取可写目录并写入后门，以及复制数据库文件等功能。它提供Inband和盲注两种注入模式，获取数据库权限。使用时，用户首先使用该工具生成一个配置文件。在配置文件中，设置注入路径以及注入的各项参数，然后再加载该文件，实施渗透测试。
  >sqlsus is an open source MySQL injection and takeover tool, written in perl.

  >Via a command line interface, you can retrieve the database(s) structure, inject your own SQL queries (even complex ones), download files from the web server, crawl the website for writable directories, upload and control a backdoor, clone the database(s), and much more…
  >Whenever relevant, sqlsus will mimic a MySQL console output.

  >sqlsus focuses on speed and efficiency, optimizing the available injection space, making the best use (I can think of) of MySQL functions.
  >It uses stacked subqueries and an powerful blind injection algorithm to maximize the data gathered per web server hit.
  >Using multi-threading on top of that, sqlsus is an extremely fast database dumper, be it for inband or blind injection.

  >If the privileges are high enough, sqlsus will be a great help for uploading a backdoor through the injection point, and takeover the web server.

  >It uses SQLite as a backend, for an easier use of what has been dumped, and integrates a lot of usual features (see below) such as cookie support, socks/http proxying, https.
- ua-tester:根据不同的UA字符串分析服务器响应
  >This tool is designed to automatically check a given URL using a list of standard and non-standard User Agent strings provided by the user (1 per line). The results of these checks are then reported to the user for further manual analysis where required.
- Uniscan:网站漏洞扫描工具Uniscan,网站漏洞的种类有很多种，如何快速扫描寻找漏洞，是渗透测试人员面临的一个棘手问题。Uniscan是Kali Linux预先安装的一个网站漏洞扫描工具。该工具可以针对单一、批量、dork类型目标进行扫描。同时，它支持多种漏洞扫描，如敏感文件、敏感目录、XSS、盲注、本地包含、远程包含、压力测试等。该工具容易扩展，用户只需要修改配置文件、列表文件或者数据库文件，就可以增强扫描功能。
  >Uniscan is a simple Remote File Include, Local File Include and Remote Command Execution vulnerability scanner.
- Vega:Web应用扫描测试工具Vega。Vega是Kali Linux提供的图形化的Web应用扫描和测试平台工具。该工具提供代理和扫描两种模式。在代理模式中，安全人员可以分析Web应用的会话信息。通过工具自带的拦截功能，用户可以修改请求和响应信息，从而实施中间人攻击。在扫描模式中，安全人员对指定的目标进行目录爬取，注入攻击和响应处理。其中，支持的注入攻击包括SQL注入、XML注入、文件包含、Shell注入、HTTP Header注入等十八种。最后，该工具会给出详细的分析报告，列出每种漏洞的利用方式。

  >Vega is a free and open source scanner and testing platform to test the security of web applications. Vega can help you find and validate SQL Injection, Cross-Site Scripting (XSS), inadvertently disclosed sensitive information, and other vulnerabilities. It is written in Java, GUI based, and runs on Linux, OS X, and Windows.

  >Vega includes an automated scanner for quick tests and an intercepting proxy for tactical inspection. The Vega scanner finds XSS (cross-site scripting), SQL injection, and other vulnerabilities. Vega can be extended using a powerful API in the language of the web: Javascript.

    - Automated Crawler and Vulnerability Scanner
    - Consistent UI
    - Website Crawler
    - Intercepting Proxy
    - SSL MITM
    - Content Analysis
    - Extensibility through a Powerful Javascript Module API
    - Customizable alerts
    - Database and Shared Data Model
- w3af:W3af是一个Web应用程序攻击和检查框架。该项目已超过130个插件，其中检查SQL注入，跨站点脚本（XSS），本地和远程文件等。该项目的目标是要建立一个框架，以寻找和开发Web应用安全漏洞，很容易使用和扩展。
  >w3af is a Web Application Attack and Audit Framework which aims to identify and exploit all web application vulnerabilities. This package provides a graphical user interface (GUI) for the framework. If you want a command-line application only, install w3af-console. The framework has been called the “metasploit for the web”, but it’s actually much more than that, because it also discovers the web application vulnerabilities using black-box scanning techniques!. The w3af core and it’s plugins are fully written in Python. The project has more than 130 plugins, which identify and exploit SQL injection, cross site scripting (XSS), remote file inclusion and more.
- WebScarab:WebScarab是一个用来分析使用HTTP和HTTPS协议的应用程序框架。其原理很简单，WebScarab可以记录它检测到的会话内容（请求和应答），并允许使用者可以通过多种形式来查看记录。WebScarab的设计目的是让使用者可以掌握某种基于HTTP（S）程序的运作过程；可以用它来调试程序中较难处理的bug，也可以帮助安全专家发现潜在的程序漏洞。
  >WebScarab is designed to be a tool for anyone who needs to expose the workings of an HTTP(S) based application, whether to allow the developer to debug otherwise difficult problems, or to allow a security specialist to identify vulnerabilities in the way that the application has been designed or implemented.
- Webshag:webshag是一个用于对web服务器进行安全审计的跨平台多线程工具。Webshag会收集那些通常对Web服务器有用的功能，比如端口扫描、URL扫描和文件模糊测试。可以通过代理和HTTP身份认证（基于认证或摘要认证），用它来以HTTP或HTTPS的方式扫描WEB服务器。此外Webshag可以凭借IDS规避能力，使请求之间的相关性变的
  >Webshag is a multi-threaded, multi-platform web server audit tool. Written in Python, it gathers commonly useful functionalities for web server auditing like website crawling, URL scanning or file fuzzing.

  >Webshag can be used to scan a web server in HTTP or HTTPS, through a proxy and using HTTP authentication (Basic and Digest). In addition to that it proposes innovative IDS evasion functionalities aimed at making correlation between request more complicated (e.g. use a different random per request HTTP proxy server).
- WebSlayer:Sparta是一个nmap、nikto、hydra等工具的集合，利用各个优秀工具的结合，使渗透测试更加便捷。
  >Webslayer is a tool designed for brute forcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts,files, etc), brute force GET and POST parameters, bruteforce Forms parameters (User/Password), Fuzzing, etc. The tools has a payload generator and an easy and powerful results analyzer.

  >You can perform attacks like:

    - Predictable resource locator, recursion supported (Discovery)
    - Login forms brute force
    - Session brute force
    - Parameter brute force
    - Parameter fuzzing and injection (XSS, SQL)
    - Basic and Ntml authentication brute forcing

  >Some features:

    - Recursion
    - Encodings: 15 encodings supported
    - Authentication: supports Ntml and Basic
    - Multiple payloads: you can use 2 payloads in different parts
    - Proxy support (authentication supported)
    - For predictable resource location it has: Recursion, common extensions, non standard code detection
    - Multiple filters for improving the performance and for producing cleaner results
    - Live filters
    - Multithreads
    - Session saving
    - Integrated browser (webKit)
    - Time delay between requests
    - Attack balancing across multiple proxies
    - Predefined dictionaries for predictable resource location, based on known servers
- WebSploit:是一个开源项目,主要用于远程扫描和分析系统漏洞。使用它可以非常容易和快速发现系统中存在的问题，并用于深入分析。
  >WebSploit Is An Open Source Project For:

    - Social Engineering Works
    - Scan,Crawler & Analysis Web
    - Automatic Exploiter
    - Support Network Attacks
    - Autopwn – Used From Metasploit For Scan and Exploit Target Service
    - wmap – Scan,Crawler Target Used From Metasploit wmap plugin
    - format infector – inject reverse & bind payload into file format
    - phpmyadmin Scanner
    - CloudFlare resolver
    - LFI Bypasser
    - Apache Users Scanner
    - Dir Bruter
    - admin finder
    - MLITM Attack – Man Left In The Middle, XSS Phishing Attacks
    - MITM – Man In The Middle Attack
    - Java Applet Attack
    - MFOD Attack Vector
    - USB Infection Attack
    - ARP Dos Attack
    - Web Killer Attack
    - Fake Update Attack
    - Fake Access point Attack
    - Wifi Honeypot
    - Wifi Jammer
    - Wifi Dos
    - Bluetooth POD Attack
- Wfuzz:Wfuzz是一个基于Python的Web爆破程序，它支持多种方法来测试WEB应用的漏洞。你可以审计参数、登录认证、GET/POST方式爆破的表单，并且可以发掘未公开的资源，比如目录、文件和头部之类的。
  >Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc.

  >Some features:

    - Multiple Injection points capability with multiple dictionaries
    - Recursion (When doing directory bruteforce)
    - Post, headers and authentication data brute forcing
    - Output to HTML
    - Colored output
    - Hide results by return code, word numbers, line numbers, regex
    - Cookies fuzzing
    - Multi threading
    - Proxy support
    - SOCK support
    - Time delays between requests
    - Authentication support (NTLM, Basic)
    - All parameters bruteforcing (POST and GET)
    - Multiple encoders per payload
    - Payload combinations with iterators
    - Baseline request (to filter results against)
    - Brute force HTTP methods
    - Multiple proxy support (each request through a different proxy)
    - HEAD scan (faster for resource discovery)
    - Dictionaries tailored for known applications (Weblogic, Iplanet, Tomcat, Domino, Oracle 9i, Vignette, Coldfusion and many more
- WPScan:一款针对WordPress的黑盒漏洞扫描器
  >WPScan is a black box WordPress vulnerability scanner that can be used to scan remote WordPress installations to find security issues.

- XSSer:是一个可命令行也可图形化的工具，集成了大量绕过服务器过滤机制的方法。由python开发。
  >Cross Site “Scripter” (aka XSSer) is an automatic -framework- to detect, exploit and report XSS vulnerabilities in web-based applications. It contains several options to try to bypass certain filters, and various special techniques of code injection.
- zaproxy:是一款用于寻找Web应用程序漏洞的综合性渗透测试工具，同时它也易于使用。ZAP是为拥有丰富经验的安全研究人员设计的，同时，也是渗透测试新手用于开 发和功能测试的理想工具，它也提供一系列工具用于手动寻找安全漏洞。同时该工具也是开源工具，支持多种语言版本。
  >The OWASP Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing as well as being a useful addition to an experienced pen testers toolbox.

## Database Assessment 数据库评估

- BBQSQL:BBQSQL是一个用Python写的SQL盲注框架。对于棘手的SQL注入漏洞攻击非常有用。bbqsql也是一个半自动的工具，对于那些难以触发SQL注入有比较多的定制。该工具与数据库类型无关并且非常灵活。它也有一个直观的用户界面，使攻击设置更容易。Python Gevent也被实现，使bbqsql速度非常快。http://www.mottoin.com/90324.html
  >Blind SQL injection can be a pain to exploit. When the available tools work they work well, but when they don’t you have to write something custom. This is time-consuming and tedious. BBQSQL can help you address those issues.

  >BBQSQL is a blind SQL injection framework written in Python. It is extremely useful when attacking tricky SQL injection vulnerabilities. BBQSQL is also a semi-automatic tool, allowing quite a bit of customization for those hard to trigger SQL injection findings. The tool is built to be database agnostic and is extremely versatile. It also has an intuitive UI to make setting up attacks much easier. Python gevent is also implemented, making BBQSQL extremely fast.

  >Similar to other SQL injection tools you provide certain request information.

  >Must provide the usual information:

    - URL
    - HTTP Method
    - Headers
    - Cookies
    - Encoding methods
    - Redirect behavior
    - Files
    - HTTP Auth
    - Proxies
    - Then specify where the injection is going and what syntax we are injecting.
- HexorBase:数据库密码爆破HexorBase,数据库服务是服务器上最常见的一类服务。由于数据库保存大量的敏感信息，所以它的安全非常重要。测试数据库服务安全的重要方式，就是检查口令的强壮度。Kali Linux提供了HexorBase工具。该工具是少有的图形界面工具，它支持MySQL、Oracle、PostgreSQL、SQLite和SQL Server五大主流数据库。它允许安全人员指定用户字典和密码字典，然后实施字典攻击。同时，它还提供对应的图形界面客户端，允许安全人员使用破解出的用户名和密码，对数据库进行远程管理。
- jSQL:一款轻量级安全测试工具，可以检测SQL注入漏洞。
  >jSQL Injection is a lightweight application used to find database information from a distant server. jSQL is free, open source and cross-platform (Windows, Linux, Mac OS X, Solaris).
- mdb-sql:可用来连接access数据库文件（mdb）然后通过sql语句查询数据
- Oscanner:Oracle系统评估框架
  >Oscanner is an Oracle assessment framework developed in Java. It has a plugin-based architecture and comes with a couple of plugins that currently do:

    - Sid Enumeration
    - Passwords tests (common & dictionary)
    - Enumerate Oracle version
    - Enumerate account roles
    - Enumerate account privileges
    - Enumerate account hashes
    - Enumerate audit information
    - Enumerate password policies
    - Enumerate database links
    - The results are given in a graphical java tree.
- SidGuesser：用字典探测oracle数据库存在的sid
  >Guesses sids/instances against an Oracle database according to a predefined dictionary file. The speed is slow (80-100 guesses per second) but it does the job.
- SQLdict:SQL Server密码爆破工具SQLdict.SQL Server是Windows系统常用的数据库服务器。它广泛采用用户名和密码方式，进行身份认证。Kali Linux提供一款专用的数据库密码爆破工具SQLdict。该工具是一个WIndows程序，运行时会自动调用Kali Linux内置的Wine组件。渗透测试人员只要指定目标IP地址、账户名和密码字典，就可以实施密码爆破。
- sqlite DB Browser:SQLite DB刘浏览器
- sqlmap:SQLmap是一款用来检测与利用SQL注入漏洞的免费开源工具，有一个非常棒的特性，即对检测与利用的自动化处理（数据库指纹、访问底层文件系统、执行命令）。
  >sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

  >Features:

    - Full support for MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase and SAP MaxDB database management systems.
    - Full support for six SQL injection techniques: boolean-based blind, time-based blind, error-based, UNION query, stacked queries and out-of-band.
    - Support to directly connect to the database without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
    - Support to enumerate users, password hashes, privileges, roles, databases, tables and columns.
    - Automatic recognition of password hash formats and support for cracking them using a dictionary-based attack.
    - Support to dump database tables entirely, a range of entries or specific columns as per user’s choice. The user can also choose to dump only a range of characters from each column’s entry.
    - Support to search for specific database names, specific tables across all databases or specific columns across all databases’ tables. This is useful, for instance, to identify tables containing custom application credentials where relevant columns’ names contain string like name and pass.
    - Support to download and upload any file from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to execute arbitrary commands and retrieve their standard output on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to establish an out-of-band stateful TCP connection between the attacker machine and the database server underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user’s choice.
    - Support for database process’ user privilege escalation via Metasploit’s Meterpreter getsystem command.
- Sqlninja:一个专门针对Microsoft SQL Server的sql注入工具,可找到远程SQL服务器的标志和特征(版本、用户执行的查询、用户特权、xp_cmdshell的可用性、身份验证模式等),“sa”口令的强力攻击,如果找到口令后，就将特权提升到“sa”,如果原始的xp_cmdshell被禁用后，就创建一个定制的xp_cmdshell。使用纯粹的ASCII GET/POST请求来上载netcat.exe程序(以及其它任何可执行的程序)，因此并不需要FTP连接。为了找到目标网络的防火墙所允许的端口，可以实施针对目标SQL　服务器的TCP/UDP端口扫描。逃避技术，这是为了使注入式代码“模糊”不清，并且混淆/绕过基于签名的IPS和应用层防火墙。采用“盲目执行”攻击模式，在其它模式失效时，可以用于发布命令并执行诊断。在sqlninja生成的SQL代码上，执行的是自动化的URL编码，这使得用户可以更精细地控制漏洞利用的字符串。如果得到权限为sa，可以结合msf进一步对目标主机进行渗透。
  >Fancy going from a SQL Injection on Microsoft SQL Server to a full GUI access on the DB? Take a few new SQL Injection tricks, add a couple of remote shots in the registry to disable Data Execution Prevention, mix with a little Perl that automatically generates a debug script, put all this in a shaker with a Metasploit wrapper, shake well and you have just one of the attack modules of sqlninja!

  >Sqlninja is a tool targeted to exploit SQL Injection vulnerabilities on a web application that uses Microsoft SQL Server as its back-end.

  >Its main goal is to provide a remote access on the vulnerable DB server, even in a very hostile environment. It should be used by penetration testers to help and automate the process of taking over a DB Server when a SQL Injection vulnerability has been discovered.
- sqlsus:sqlsus是使用Perl语言编写的MySQL注入和接管工具。它可以获取数据库结构，实施注入查询，下载服务器的文件，爬取可写目录并写入后门，以及复制数据库文件等功能。它提供Inband和盲注两种注入模式，获取数据库权限。使用时，用户首先使用该工具生成一个配置文件。在配置文件中，设置注入路径以及注入的各项参数，然后再加载该文件，实施渗透测试。
  >sqlsus is an open source MySQL injection and takeover tool, written in perl.

  >Via a command line interface, you can retrieve the database(s) structure, inject your own SQL queries (even complex ones), download files from the web server, crawl the website for writable directories, upload and control a backdoor, clone the database(s), and much more…
  >Whenever relevant, sqlsus will mimic a MySQL console output.

  >sqlsus focuses on speed and efficiency, optimizing the available injection space, making the best use (I can think of) of MySQL functions.
  >It uses stacked subqueries and an powerful blind injection algorithm to maximize the data gathered per web server hit.
  >Using multi-threading on top of that, sqlsus is an extremely fast database dumper, be it for inband or blind injection.

  >If the privileges are high enough, sqlsus will be a great help for uploading a backdoor through the injection point, and takeover the web server.

  >It uses SQLite as a backend, for an easier use of what has been dumped, and integrates a lot of usual features (see below) such as cookie support, socks/http proxying, https.
- tnscmd10g:Oracle服务器通常都配置TNS，用来管理和配置客户端和数据库的连接。每个Oracle服务器都会运行一个TNS监听器进程tnslsnr用来处理客户端和服务器的数据传输。该接口默认工作在TCP 1521端口。由于该监听器在验证请求的身份之前，可以对部分命令进行响应，所以造成一定程度的漏洞。Kali Linux提供的tnscmd10g工具可以利用该漏洞。使用该工具，用户可以获取数据库的版本信息、服务信息、配置信息，甚至可以关闭TNS服务，导致客户端无法连接服务器。

## Password Attacks 密码攻击

- acccheck:该工具基于SMB协议用来暴力破解Windows，它是根据smbClient这个二进制文件来构造的一小段代码，所以只对运行有smbClient这个文件的计算机终端上才有用 
  >The tool is designed as a password dictionary attack tool that targets windows authentication via the SMB protocol. It is really a wrapper script around the ‘smbclient’ binary, and as a result is dependent on it for its execution.
- BruteSpray:BruteSpray是一个基于Nmap扫描结果的端口爆破工具,它可以载入Nmap的扫描结果,然后对我们指定的端口和ip进行枚举口令爆破.
  >BruteSpray takes nmap GNMAP/XML output and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
- Burp Suite:Burp Suite是Web应用程序测试的最佳工具之一，其多种功能可以帮我们执行各种任务.请求的拦截和修改,扫描web应用程序漏洞,以暴力破解登陆表单,执行会话令牌等多种的随机性检查。
  >Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, through to finding and exploiting security vulnerabilities.

  >Burp gives you full control, letting you combine advanced manual techniques with state-of-the-art automation, to make your work faster, more effective, and more fun.
- CeWL:cewl是通过爬取网站的时候，根据爬取内容的关键字生成一份字典，通过这种方式生成的字典可以作为cupp生成字典的补充。
  >CeWL is a ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.

  >CeWL also has an associated command line app, FAB (Files Already Bagged) which uses the same meta data extraction techniques to create author/creator lists from already downloaded.
- chntpw:重设Windows 密码 若是忘记了Windows 密码，可使用chntpw工具重设密码
  >This little program provides a way to view information and change user passwords in a Windows NT/2000 user database file. Old passwords need not be known since they are overwritten. In addition it also contains a simple registry editor (same size data writes) and an hex-editor which enables you to fiddle around with bits and bytes in the file as you wish.

  >If you want GNU/Linux bootdisks for offline password recovery you can add this utility to custom image disks or use those provided at the tools homepage.
- cisco-auditing-tool:一个很小的安全审计工具，扫描Cisco路由器的一般性漏洞，例如默认密码，SNMP community字串和一些老的IOS bug
  >Perl script which scans cisco routers for common vulnerabilities.
- CmosPwd:wd其作用是帮你找回遗忘的CMOS/BIOS密码
  >CmosPwd is a cross-platform tool to decrypt password stored in CMOS used to access a computer’s BIOS setup.

  >This application should work out of the box on most modern systems, but some more esoteric BIOSes may not be supported or may require additional steps.
- creddump:Creddump 是一个python开发的工具，可以从注册表hives文件中提取各种不同的windows密码信息，包括LM and NT hashes (SYSKEY protected)、Cached domain passwords、LSA secrets
  >creddump is a python tool to extract various credentials and secrets from Windows registry hives. It currently extracts:

    - LM and NT hashes (SYSKEY protected)
    - Cached domain passwords
    - LSA secrets
  >It essentially performs all the functions that bkhive/samdump2, cachedump, and lsadump2 do, but in a platform-independent way.

  >It is also the first tool that does all of these things in an offline way (actually, Cain & Abel does, but is not open source and is only available on Windows).
- crowbar:Crowbar是Kali Linux新增的一款服务认证暴力破解工具。该工具支持OpenVPN、RDP、SSH和VNC服务。该工具具备常见的暴力破解功能，如主机字典、用户名字典、密码字典，并且支持多线程、日志过滤等功能。同时，它还支持基于服务密钥破解。这样，渗透测试人员就可以通过其他工具收集服务私钥，然后在该工具中直接使用。
  >Crowbar (formally known as Levye) is a brute forcing tool that can be used during penetration tests. It was developed to brute horse some protocols in a different manner according to other popular brute forcing tools. As an example, while most brute forcing tools use username and password for SSH brute horse, Crowbar uses SSH key(s). This allows for any private keys that have been obtained during penetration tests, to be used to attack other SSH servers.
- crunch:密码词列表生成工具
  >Crunch is a wordlist generator where you can specify a standard character set or a character set you specify. crunch can generate all possible combinations and permutations.

  >Features:

    - crunch generates wordlists in both combination and permutation ways
    - it can breakup output by number of lines or file size
    - now has resume support
    - pattern now supports number and symbols
    - pattern now supports upper and lower case characters separately
    - adds a status report when generating multiple files
    - new -l option for literal support of @,%^
    - new -d option to limit duplicate characters see man file for details
    - now has unicode support
- Cupp是一款用Python语言写成的可交互性的字典生成脚本。尤其适合社会工程学，当你收集到目标的具体信息后，你就可以通过这个工具来智能化生成关于目标的字典。当对目标进行渗透测试的时候，常见密码爆破不成功，大批量的字典耗时太长时，就需要一份结合具体目标的带社工性质的字典，可以很大提升爆破效率，这时候就可以利用Cupp打造一份。本文基于kali2.0进行演示，我的kali系统是利用清华源更新过的最新系统，但没有Cupp。所以先安装。  

- DBPwAudit:DBPwAudit是一个Java数据库密码审计工具，是一个可以执行在线审计密码质量的数据库引擎。该应用程序可以通过复制新的JDBC驱动程序到JDBC目录来添加额外的数据库驱动程序。
  >DBPwAudit is a Java tool that allows you to perform online audits of password quality for several database engines. The application design allows for easy adding of additional database drivers by simply copying new JDBC drivers to the jdbc directory. Configuration is performed in two files, the aliases.conf file is used to map drivers to aliases and the rules.conf tells the application how to handle error messages from the scan.

  >The tool has been tested and known to work with:

    - Microsoft SQL Server 2000/2005
    - Oracle 8/9/10/11
    - IBM DB2 Universal Database
    - MySQL
  >The tool is pre-configured for these drivers but does not ship with them, due to licensing issues.
- findmyhash:在渗透测试的过程中，我们常常会dump出用户密码的哈希值。每一个渗透测试人员都会使用不同方法破解哈希值以便获得权限或用于进一步渗透。初步的渗透测试结束后，拥有一个有效的密码将会为我们在服务器或域环境中做进一步渗透争取更多的时间。出于这个原因，我编写了此脚本，整合了互联网中现有的破解各类Hash的服务。
  >Accepted algorithms are:

    - MD4 – RFC 1320
    - MD5 – RFC 1321
    - SHA1 – RFC 3174 (FIPS 180-3)
    - SHA224 – RFC 3874 (FIPS 180-3)
    - SHA256 – FIPS 180-3
    - SHA384 – FIPS 180-3
    - SHA512 – FIPS 180-3
    - RMD160 – RFC 2857
    - GOST – RFC 583
    - WHIRLPOOL – ISO/IEC 10118-3:2004
    - LM – Microsoft Windows hash NTLM – Microsoft Windows hash
    - MYSQL – MySQL 3, 4, 5 hash
    - CISCO7 – Cisco IOS type 7 encrypted passwords
    - JUNIPER – Juniper Networks $9$ encrypted passwords
    - LDAP_MD5 – MD5 Base64 encoded
    - LDAP_SHA1 – SHA1 Base64 encoded
- gpp-decrypt:GPP加密破解工具gpp-decrypt。GPP是Group Policy Preferences（组策略首选项）的缩写，这是一个组策略实施工具。通过该工具，网络管理员可以实现更多的网络管理，如驱动映射、添加计划任务、管理本地组和用户。其中最常用的功能就是远程创建本地账户。在创建过程中，会在目标主机传送一个Groups.xml文件。该文件中保存这创建的用户名和加密的密码。该加密的密码采用对称加密。该文件是通过网络传输到目标主机的。通过数据抓包，就可以截获该文件。然后使用Kali Linux提供工具gpp-decrypt来破解该密码。工具gpp-decrypt是一个Ruby脚本，可以直接破解GPP加密的密码。
  >A simple ruby script that will decrypt a given GPP encrypted string.
- hash-identifier：确定Hash的算法类型
  >Software to identify the different types of hashes used to encrypt data and especially passwords.
- Hashcat：当前最强大的开源密码恢复工具,用Hashcat每秒计算1.4亿个密码。
  >hashcat is the world’s fastest and most advanced password recovery utility, supporting five unique modes of attack for over 200 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and OSX, and has facilities to help enable distributed password cracking.
- HexorBase:数据库密码爆破HexorBase,数据库服务是服务器上最常见的一类服务。由于数据库保存大量的敏感信息，所以它的安全非常重要。测试数据库服务安全的重要方式，就是检查口令的强壮度。Kali Linux提供了HexorBase工具。该工具是少有的图形界面工具，它支持MySQL、Oracle、PostgreSQL、SQLite和SQL Server五大主流数据库。它允许安全人员指定用户字典和密码字典，然后实施字典攻击。同时，它还提供对应的图形界面客户端，允许安全人员使用破解出的用户名和密码，对数据库进行远程管理。
  >HexorBase is a database application designed for administering and auditing multiple database servers simultaneously from a centralized location, it is capable of performing SQL queries and bruteforce attacks against common database servers (MySQL, SQLite, Microsoft SQL Server, Oracle, PostgreSQL ). HexorBase allows packet routing through proxies or even metasploit pivoting antics to communicate with remotely inaccessible servers which are hidden within local subnets.
- THC-Hydra:是一个支持多种网络服务的非常快速的网络登陆破解工具。这个工具是一个验证性质的工具，它被设计的主要目的是为研究人员和安全从业人员展示远程获取一个系统的认证权限是比较容易的！
  >Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add. This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.

  >It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET, HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS, POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2), Telnet, VMware-Auth, VNC and XMPP.
- John the Ripper:是一个快速的密码破解工具，用于在已知密文的情况下尝试破解出明文的破解密码软件，支持目前大多数的加密算法。
  >John the Ripper is designed to be both feature-rich and fast. It combines several cracking modes in one program and is fully configurable for your particular needs (you can even define a custom cracking mode using the built-in compiler supporting a subset of C). Also, John is available for several different platforms which enables you to use the same cracker everywhere (you can even continue a cracking session which you started on another platform).

  >Out of the box, John supports (and autodetects) the following Unix crypt(3) hash types: traditional DES-based, “bigcrypt”, BSDI extended DES-based, FreeBSD MD5-based (also used on Linux and in Cisco IOS), and OpenBSD Blowfish-based (now also used on some Linux distributions and supported by recent versions of Solaris). Also supported out of the box are Kerberos/AFS and Windows LM (DES-based) hashes, as well as DES-based tripcodes.

  >When running on Linux distributions with glibc 2.7+, John 1.7.6+ additionally supports (and autodetects) SHA-crypt hashes (which are actually used by recent versions of Fedora and Ubuntu), with optional OpenMP parallelization (requires GCC 4.2+, needs to be explicitly enabled at compile-time by uncommenting the proper OMPFLAGS line near the beginning of the Makefile).

  >Similarly, when running on recent versions of Solaris, John 1.7.6+ supports and autodetects SHA-crypt and SunMD5 hashes, also with optional OpenMP parallelization (requires GCC 4.2+ or recent Sun Studio, needs to be explicitly enabled at compile-time by uncommenting the proper OMPFLAGS line near the beginning of the Makefile and at runtime by setting the OMP_NUM_THREADS environment variable to the desired number of threads).

  >John the Ripper Pro adds support for Windows NTLM (MD4-based) and Mac OS X 10.4+ salted SHA-1 hashes.

  >“Community enhanced” -jumbo versions add support for many more password hash types, including Windows NTLM (MD4-based), Mac OS X 10.4-10.6 salted SHA-1 hashes, Mac OS X 10.7 salted SHA-512 hashes, raw MD5 and SHA-1, arbitrary MD5-based “web application” password hash types, hashes used by SQL database servers (MySQL, MS SQL, Oracle) and by some LDAP servers, several hash types used on OpenVMS, password hashes of the Eggdrop IRC bot, and lots of other hash types, as well as many non-hashes such as OpenSSH private keys, S/Key skeykeys files, Kerberos TGTs, PDF files, ZIP (classic PKZIP and WinZip/AES) and RAR archives.

  >Unlike older crackers, John normally does not use a crypt(3)-style routine. Instead, it has its own highly optimized modules for different hash types and processor architectures. Some of the algorithms used, such as bitslice DES, couldn’t have been implemented within the crypt(3) API; they require a more powerful interface such as the one used in John. Additionally, there are assembly language routines for several processor architectures, most importantly for x86-64 and x86 with SSE2.
- Johnny:John the Ripper工具的GUI版本
  >Johnny provides a GUI for the John the Ripper password cracking tool.
- keimpx:内网杀手，通过Hash注入拿到域计算机权限
  >keimpx is an open source tool, released under a modified version of Apache License 1.1.

  >It can be used to quickly check for valid credentials across a network over SMB. Credentials can be:

    - Combination of user / plain-text password.
    - Combination of user / NTLM hash.
    - Combination of user / NTLM logon session token.
  >If any valid credentials has been discovered across the network after its attack phase, the user is asked to choose which host to connect to and which valid credentials to use, then he will be prompted with an interactive SMB shell where the user can:

    - Spawn an interactive command prompt.
    - Navigate through the remote SMB shares: list, upload, download files, create, remove files, etc.
    - Deploy and undeploy his own service, for instance, a backdoor listening on a TCP port for incoming connections.
    - List users details, domains and password policy.
- Maltego Teeth:Maltego是一个开源的漏洞评估工具，它主要用于论证一个网络内单点故障的复杂性和严重性。该工具能够聚集来自内部和外部资源的信息，并且提供一个清晰的漏洞分析界面。
  >Maltego is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. Maltego’s unique advantage is to demonstrate the complexity and severity of single points of failure as well as trust relationships that exist currently within the scope of your infrastructure.

  >The unique perspective that Maltego offers to both network and resource based entities is the aggregation of information posted all over the internet – whether it’s the current configuration of a router poised on the edge of your network or the current whereabouts of your Vice President on his international visits, Maltego can locate, aggregate and visualize this information.

  >Maltego offers the user with unprecedented information. Information is leverage. Information is power. Information is Maltego.

  >What does Maltego do?

  >Maltego is a program that can be used to determine the relationships and real world links between:

    - People
    - Groups of people (social networks)
    - Companies
    - Organizations
    - Web sites
    - Internet infrastructure such as:
    - Domains
    - DNS names
    - Netblocks
    - IP addresses
    - Phrases
    - Affiliations
    - Documents and files
    - These entities are linked using open source intelligence.
    - Maltego is easy and quick to install – it uses Java, so it runs on Windows, Mac and Linux.
    - Maltego provides you with a graphical interface that makes seeing these relationships instant and accurate – making it possible to see hidden connections.
    - Using the graphical user interface (GUI) you can see relationships easily – even if they are three or four degrees of separation away.
    - Maltego is unique because it uses a powerful, flexible framework that makes customizing possible. As such, Maltego can be adapted to your own, unique requirements.
  >What can Maltego do for me?

    - Maltego can be used for the information gathering phase of all security related work. It will save you time and will allow you to work more accurately and smarter.
    - Maltego aids you in your thinking process by visually demonstrating interconnected links between searched items.
    - Maltego provide you with a much more powerful search, giving you smarter results.
    - If access to “hidden” information determines your success, Maltego can help you discover it.
- Maskprocessor:Maskprocessor是每个位置configureable字符集打包到一个独立的二进制一个高性能的词生成器。 Maskprocessor是每个位置configureable字符集打包到一个独立的二进制一个高性能的词生成器。
  >Maskprocessor is a High-Performance word generator with a per-position configureable charset packed into a single stand-alone binary. 
- multiforcer:支持CUDA和OpenCL的加速从地上爬起来彩虹表的实施，以及CUDA哈希暴力破解工具，许多的哈希类型，包括MD5，SHA1，LM，NTLM和其它更多的支持。
  >A CUDA & OpenCL accelerated rainbow table implementation from the ground up, and a CUDA hash brute forcing tool with support for many hash types including MD5, SHA1, LM, NTLM, and lots more.
- Ncrack:Ncrack是一个高速的网络认证破解工具。它的建立是为了帮助公司通过积极主动地测试所有的主机和网络为贫困密码设备保护他们的网络。审核客户时，安全专家还要靠Ncrack。 Ncrack采用模块化方法，类似的Nmap命令行语法和动态引擎，可以根据网络的反馈调整自己的行为而设计的。它允许多个主机的快速而可靠的大规模审计。Ncrack的功能包括一个非常灵活的接口授予用户完全控制网络操作的，允许非常复杂的穷举攻击，定时模板的易用性，类似的Nmap的许多更多的运行时的交互。支持的协议包括RDP，SSH，HTTP（S），SMB，POP3（S），VNC，FTP和Telnet。
  >Ncrack is a high-speed network authentication cracking tool. It was built to help companies secure their networks by proactively testing all their hosts and networking devices for poor passwords. Security professionals also rely on Ncrack when auditing their clients. Ncrack was designed using a modular approach, a command-line syntax similar to Nmap and a dynamic engine that can adapt its behaviour based on network feedback. It allows for rapid, yet reliable large-scale auditing of multiple hosts.

  >Ncrack’s features include a very flexible interface granting the user full control of network operations, allowing for very sophisticated bruteforcing attacks, timing templates for ease of use, runtime interaction similar to Nmap’s and many more. Protocols supported include RDP, SSH, http(s), SMB, pop3(s), VNC, FTP, and telnet.
- oclgausscrack:该方案的目标是破解高斯病毒的加密的净荷的验证哈希。使用的OpenCL加速10K MD5循环使用的优化也用于oclHashcat加为最高性能能够处理多GPU设置VCL（同类型）（虚拟CL）V1.18兼容的开源支持集成到分布式计算环境支架恢复。
  >The goal of the program is to crack the verification hash of the encrypted payload of the Gauss Virus. Uses OpenCL to accelerate the 10k MD5 loop Uses optimizations also used in oclHashcat-plus for maximum performance Able to handle multi-GPU setups (of the same type) VCL (Virtual CL) v1.18 compatible Open Source Supports integration into distributed computing environments Supports resume.
- ophcrack:Ophcrack是一个使用Rainbow table（彩虹表）来破解视窗作业系统下的LAN Manager散列（比如hash文件）的程序，它是基于GPL下发布的开放原始码程式
  >Ophcrack is a free Windows password cracker based on rainbow tables. It is a very efficient implementation of rainbow tables done by the inventors of the method. It comes with a Graphical User Interface and runs on multiple platforms.
- PACK:通过对现有密码列表规则的分析来帮助密码破解
  >PACK was developed in order to aid in a password cracking competition “Crack Me If You Can” that occurred during Defcon 2010. The goal of this toolkit is to aid in preparation for the “better than bruteforce” password attacks by analyzing common ways that people create passwords. After the analysis stage, the statistical database can be used to generate attack masks for tools such as oclHashcat. NOTE: This tool itself can not crack passwords, but helps other tools crack more passwords faster.
- patator：是一个多用途的暴力破解，具有模块化设计和一个灵活的使用。
  >Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage. Currently it supports the following modules:

    - ftp_login : Brute-force FTP
    - ssh_login : Brute-force SSH
    - telnet_login : Brute-force Telnet
    - smtp_login : Brute-force SMTP
    - smtp_vrfy : Enumerate valid users using the SMTP ‘VRFY’ command
    - smtp_rcpt : Enumerate valid users using the SMTP ‘RCPT TO’ command
    - finger_lookup : Enumerate valid users using Finger
    - http_fuzz : Brute-force HTTP
    - pop_login : Brute-force POP3
    - pop_passd : Brute-force poppassd (http://netwinsite.com/poppassd/)
    - imap_login : Brute-force IMAP4 – ldap_login : Brute-force LDAP
    - smb_login : Brute-force SMB
    - smb_lookupsid : Brute-force SMB SID-lookup
    - vmauthd_login : Brute-force VMware Authentication Daemon
    - mssql_login : Brute-force MSSQL
    - oracle_login : Brute-force Oracle
    - mysql_login : Brute-force MySQL
    - pgsql_login : Brute-force PostgreSQL
    - vnc_login : Brute-force VNC
    - dns_forward : Brute-force DNS
    - dns_reverse : Brute-force DNS (reverse lookup subnets)
    - snmp_login : Brute-force SNMPv1/2 and SNMPv3
    - unzip_pass : Brute-force the password of encrypted ZIP files
    - keystore_pass : Brute-force the password of Java keystore files
- phrasendrescher:模块化多进程密码段破解工具
  >phrasen|drescher (p|d) is a modular and multi processing pass phrase cracking tool. It comes with a number of plugins but a simple plugin API allows an easy development of new plugins. The main features of p|d are:

    - Modular with the use of plugins
    - Multi processing
    - Dictionary attack with or without permutations (uppercase, lowercase, l33t, etc.)
    - Incremental brute force attack with custom character maps
    - Runs on FreeBSD, NetBSD, OpenBSD, MacOS and Linux
- polenum: uses the Impacket Library from CORE Security Technologies to extract the password policy information
  >polenum is a python script which uses the Impacket Library from CORE Security Technologies to extract the password policy information from a windows machine. This allows a non-windows (Linux, Mac OSX, BSD etc..) user to query the password policy of a remote windows box without the need to have access to a windows machine.
- RainbowCrack:RainbowCrack是一个使用内存时间交换技术（Time-Memory Trade-Off Technique）加速口令破解过程的口令破解器，这个工具可以在地址http://project-rainbowcrack.com/下载。RainbowCrack使用了彩虹表，也就是一张预先计算好的明文和散列值的对照表。通过预先花费时间创建这样的彩虹表，能够在以后破解口令时节约大量的时间。
  >RainbowCrack is a general propose implementation of Philippe Oechslin’s faster time-memory trade-off technique. It crack hashes with rainbow tables.

  >RainbowCrack uses time-memory tradeoff algorithm to crack hashes. It differs from brute force hash crackers.

  >A brute force hash cracker generate all possible plaintexts and compute the corresponding hashes on the fly, then compare the hashes with the hash to be cracked. Once a match is found, the plaintext is found. If all possible plaintexts are tested and no match is found, the plaintext is not found. With this type of hash cracking, all intermediate computation results are discarded.

  >A time-memory tradeoff hash cracker need a pre-computation stage, at the time all plaintext/hash pairs within the selected hash algorithm, charset, plaintext length are computed and results are stored in files called rainbow table. It is time consuming to do this kind of computation. But once the one time pre-computation is finished, hashes stored in the table can be cracked with much better performance than a brute force cracker.
- rcracki-mt:又一款彩虹表哈希破解工具，不同的是次攻击支持最新格式的彩虹表进行哈希破解，当然，彩虹表仍然是不可缺少的关键存在。
  >rcracki_mt is a modified version of rcrack which supports hybrid and indexed tables. In addition to that, it also adds multi-core support.
- RSMangler:通过一定的规则模式来生成暴力破解的密码集
  >RSMangler will take a wordlist and perform various manipulations on it similar to those done by John the Ripper the main difference being that it will first take the input words and generate all permutations and the acronym of the words (in order they appear in the file) before it applies the rest of the mangles.
- SQLdict:SQL Server密码爆破工具SQLdict.SQL Server是Windows系统常用的数据库服务器。它广泛采用用户名和密码方式，进行身份认证。Kali Linux提供一款专用的数据库密码爆破工具SQLdict。该工具是一个WIndows程序，运行时会自动调用Kali Linux内置的Wine组件。渗透测试人员只要指定目标IP地址、账户名和密码字典，就可以实施密码爆破。

  >SQLdict is a dictionary attack tool for SQL Server.
- Statsprocessor:基于马尔科夫模型的词列表生成器
  >Statsprocessor is a high-performance word-generator based on per-position markov-attack packed into a single stand-alone binary.
- THC-pptp-bruter: 一款对PPTP VPN端点设备进行暴力破解的工具 
  >Brute force program against pptp vpn endpoints (tcp port 1723). Fully standalone. Supports latest MSChapV2 authentication. Tested against Windows and Cisco gateways. Exploits a weakness in Microsoft’s anti-brute force implementation which makes it possible to try 300 passwords the second.
- TrueCrack:TrueCrack是一款TrueCrypt(Copyrigth) volume文件破解工具，它工作在Linux平台下并且基于Nvidia的Cuda技术做了优化。Cuda是什么呢？英伟达™ CUDA™ 是英伟达™ (NVIDIA®) 公司的并行计算架构。 该架构通过利用GPU的处理能力，可大幅提升计算性能。TrueCrack支持两种破解模式，一个是利用已知字典，另一种方式根据用户设置动态生成指定字 符集合的字典。
  >TrueCrack is a brute-force password cracker for TrueCrypt volumes. It works on Linux and it is optimized for Nvidia Cuda technology. It supports:

    - PBKDF2 (defined in PKCS5 v2.0) based on key derivation functions: Ripemd160, Sha512 and Whirlpool.
    - XTS block cipher mode for hard disk encryption based on encryption algorithms: AES, SERPENT, TWOFISH.
    - File-hosted (container) and Partition/device-hosted.
    - Hidden volumes and Backup headers.
  >TrueCrack is able to perform a brute-force attack based on:

    - Dictionary: read the passwords from a file of words.
    - Alphabet: generate all passwords of given length from given alphabet.
  >TrueCrack works on gpu and cpu
- WebScarab:WebScarab是一个用来分析使用HTTP和HTTPS协议的应用程序框架。其原理很简单，WebScarab可以记录它检测到的会话内容（请求和应答），并允许使用者可以通过多种形式来查看记录。WebScarab的设计目的是让使用者可以掌握某种基于HTTP（S）程序的运作过程；可以用它来调试程序中较难处理的bug，也可以帮助安全专家发现潜在的程序漏洞。
  >WebScarab is designed to be a tool for anyone who needs to expose the workings of an HTTP(S) based application, whether to allow the developer to debug otherwise difficult problems, or to allow a security specialist to identify vulnerabilities in the way that the application has been designed or implemented.
- wordlists:词列表数据库
  >This package contains the rockyou wordlist and contains symlinks to a number of other password files present in the Kali Linux distribution. This package has an installation size of 134 MB. 
- zaproxy:是一款用于寻找Web应用程序漏洞的综合性渗透测试工具，同时它也易于使用。ZAP是为拥有丰富经验的安全研究人员设计的，同时，也是渗透测试新手用于开 发和功能测试的理想工具，它也提供一系列工具用于手动寻找安全漏洞。同时该工具也是开源工具，支持多种语言版本。
  >The OWASP Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing as well as being a useful addition to an experienced pen testers toolbox.

## Wireless Attacks 无线攻击

- Airbase-ng:包含在aircrack-ng包中,
  >Airbase-ng is included in the aircrack-ng package. It is a multi-purpose tool aimed at attacking clients as opposed to the Access Point itself. Some of its many features are:

    - Implements the Caffe Latte WEP client attack
    - Implements the Hirte WEP client attack
    - Ability to cause the WPA/WPA2 handshake to be captured
    - Ability to act as an ad-hoc Access Point
    - Ability to act as a full Access Point
    - Ability to filter by SSID or client MAC addresses
    - Ability to manipulate and resend packets
    - Ability to encrypt sent packets and decrypt received packets
- Aircrack-ng:Aircrack-ng是一款用于破解无线802.11WEP及WPA-PSK加密的工具，该工具在2005年11月之前名字是Aircrack，在其2.41版本之后才改名为Aircrack-ng。Aircrack-ng主要使用了两种攻击方式进行WEP破解：一种是FMS攻击，该攻击方式是以发现该WEP漏洞的研究人员名字（Scott Fluhrer、Itsik Mantin及Adi Shamir）所命名；另一种是KoreK攻击，经统计，该攻击方式的攻击效率要远高于FMS攻击。当然，最新的版本又集成了更多种类型的攻击方式。对于无线黑客而言，Aircrack-ng是一款必不可缺的无线攻击工具，可以说很大一部分无线攻击都依赖于它来完成；而对于无线安全人员而言，Aircrack-ng也是一款必备的无线安全检测工具，它可以帮助管理员进行无线网络密码的脆弱性检查及了解无线网络信号的分布情况，非常适合对企业进行无线安全审计时使用。Aircrack-ng（注意大小写）是一个包含了多款工具的无线攻击审计套装，这里面很多工具在后面的内容中都会用到，具体见下表1为Aircrack-ng包含的组件具体列表。

组件名称     | 描    述
-------     | -------------
aircrack-ng | 主要用于WEP及WPA-PSK密码的恢复，只要airodump-ng收集到足够数量的数据包，aircrack-ng就可以自动检测数据包并判断是否可以破解
airmon-ng | 用于改变无线网卡工作模式，以便其他工具的顺利使用
airodump-ng | 用于捕获802.11数据报文，以便于aircrack-ng破解
aireplay-ng | 在进行WEP及WPA-PSK密码恢复时，可以根据需要创建特殊的无线网络数据报文及流量
airserv-ng | 可以将无线网卡连接至某一特定端口，为攻击时灵活调用做准备
airolib-ng | 进行WPA Rainbow Table攻击时使用，用于建立特定数据库文件
airdecap-ng | 用于解开处于加密状态的数据包
tools | 其他用于辅助的工具，如airdriver-ng、packetforge-ng等

  >Aircrack-ng is an 802.11 WEP and WPA-PSK keys cracking program that can recover keys once enough data packets have been captured. It implements the standard FMS attack along with some optimizations like KoreK attacks, as well as the all-new PTW attack, thus making the attack much faster compared to other WEP cracking tools.

- Airdecap-ng:用于解密WEP/WPA/WPA2协议的数据包
  >Airdecap-ng can decrypt WEP/WPA/WPA2 capture files and it can also be used to strip the wireless headers from an unencrypted wireless capture.
  >It outputs a new file ending with -dec.cap, which is the decrypted/stripped version of the input file.

- Airdecloak-ng:用于分析无线数据报文时过滤出指定无线网络数据。

  >Airdecloak-ng removes WEP cloaking from a pcap file. It works by reading the input file and selecting packets from a specific network. Each selected packet is put into a list and classified (default status is “unknown”). Filters are then applied (in the order specified by the user) on this list. They will change the status of the packets (unknown, uncloaked, potentially cloaked or cloaked). The order of the filters is important as each filter will base its analysis amongst other things on the status of the packets and different orders will give different results.
- Aireplay-ng:WPA攻击工具
  >Aireplay-ng is included in the aircrack-ng package and is used to inject wireless frames. Its main role is to generate traffic for later use in aircrack-ng for cracking WEP and WPA-PSK keys. Aireplay-ng has many attacks that can deauthenticate wireless clients for the purpose of capturing WPA handshake data, fake authentications, interactive packet replay, hand-crafted ARP request injection, and ARP-request reinjection.

- Airmon-ng:
  >Airmon-ng is included in the aircrack-ng package and is used to enable and disable monitor mode on wireless interfaces. It may also be used to go back from monitor mode to managed mode.

- Airodump-ng
  >Airodump-ng is included in the aircrack-ng package and is used for packet capturing of raw 802.11 frames. It is ideal for collecting WEP IVs for use with aircrack-ng. If you have a GPS receiver connected to the computer, airodump-ng can log the coordinates of the discovered access points.
- airodump-ng-oui-update
  >airodump-ng-oui-update is a small utility included in the aircrack-ng package and is used to download the OUI list from the IEEE.
- Airolib-ng:
  >Airolib-ng is an aircrack-ng suite tool designed to store and manage essid and password lists, compute their Pairwise Master Keys (PMKs) and use them in WPA/WPA2 cracking. The program uses the lightweight SQLite3 database as the storage mechanism which is available on most platforms.
- Airserv-ng
  >Airserv-ng is a wireless card server that allows multiple wireless application programs to independently use a wireless card via a client-server TCP network connection. All operating system and wireless card driver specific code is incorporated into the server. This eliminates the need for each wireless application to contain the complex wireless card and driver logic. It is also supports multiple operating systems.
- Airtun-ng
  >Airtun-ng is a virtual tunnel interface creator and is included in the aircrack-ng package. Airtun-ng two basic functions:

    - Allow all encrypted traffic to be monitored for wireless Intrusion Detection System (wIDS) purposes
    - Inject arbitrary traffic into a network
  >In order to perform wIDS data gathering, you must have the encryption key and the bssid for the network you wish to monitor.
- Asleap
  >Demonstrates a serious deficiency in proprietary Cisco LEAP networks. Since LEAP uses a variant of MS-CHAPv2 for the authentication exchange, it is susceptible to accelerated offline dictionary attacks. Asleap can also attack the Point-to-Point Tunneling Protocol (PPTP), and any MS-CHAPv2 exchange where you can specify the challenge and response values on the command line.
- Besside-ng:你用WPA握手破解WPA网络
  >Besside-ng is a tool like Besside-ng but it support also WPA encryption. It will crack automatically all the WEP networks in range and log the WPA handshakes.

- Bluelog:Linux蓝牙扫描器
  >Bluelog is a Linux Bluetooth scanner with optional daemon mode and web front-end, designed for site surveys and traffic monitoring. It’s intended to be run for long periods of time in a static location to determine how many discoverable Bluetooth devices there are in the area.
- BlueMaho:蓝牙设备安全测试GUI工具
  >BlueMaho is GUI-shell (interface) for suite of tools for testing security of bluetooth devices. It is freeware, opensource, written on python, uses wxPyhon. It can be used for testing BT-devices for known vulnerabilities and major thing to do – testing to find unknown vulns. Also it can form nice statistics.

  Features:

    - scan for devices, show advanced info, SDP records, vendor etc
    - track devices – show where and how much times device was seen, its name changes
    - loop scan – it can scan all time, showing you online devices
    - alerts with sound if new device found
    - on_new_device – you can spacify what command should it run when it founds new device
    - it can use separate dongles – one for scaning (loop scan) and one for running tools or exploits
    - send files
    - change name, class, mode, BD_ADDR of local HCI devices
    - save results in database
    - form nice statistics (uniq devices by day/hour, vendors, services etc)
    - test remote device for known vulnerabilities (see exploits for more details)
    - test remote device for unknown vulnerabilities (see tools for more details)
    - themes! you can customize it
- Bluepot:蓝牙蜜罐
  >Bluepot is a Bluetooth Honeypot written in Java, it runs on Linux.

  >Bluepot was a third year university project attempting to implement a fully functional Bluetooth Honeypot. A piece of software designed to accept and store any malware sent to it and interact with common Bluetooth attacks such as “BlueBugging?” and “BlueSnarfing?”. Bluetooth connectivity is provided via hardware Bluetooth dongles.

  >The system also allows monitoring of attacks via a graphical user interface that provides graphs, lists, a dashboard and further detailed analysis from log files.

- BlueRanger:定位蓝牙设备频率的工具
  >BlueRanger is a simple Bash script which uses Link Quality to locate Bluetooth device radios. It sends l2cap (Bluetooth) pings to create a connection between Bluetooth interfaces, since most devices allow pings without any authentication or authorization. The higher the link quality, the closer the device (in theory).

  >Use a Bluetooth Class 1 adapter for long range location detection. Switch to a Class 3 adapter for more precise short range locating. The recision and accuracy depend on the build quality of the Bluetooth adapter, interference, and response from the remote device. Fluctuations may occur even when neither device is in motion.
- Bluesnarfer:蓝牙漏洞攻击
  >A Bluetooth bluesnarfing Utility.
- Bully：WPS暴力破解
  >Bully is a new implementation of the WPS brute force attack, written in C. It is conceptually identical to other programs, in that it exploits the (now well known) design flaw in the WPS specification. It has several advantages over the original reaver code. These include fewer dependencies, improved memory and cpu performance, correct handling of endianness, and a more robust set of options. It runs on Linux, and was specifically developed to run on embedded Linux systems (OpenWrt, etc) regardless of architecture.

  >Bully provides several improvements in the detection and handling of anomalous scenarios. It has been tested against access points from numerous vendors, and with differing configurations, with much success.

- coWPAtty:针对WPA/WPA2网络的词典工具
  >Implementation of an offline dictionary attack against WPA/WPA2 networks using PSK-based authentication (e.g. WPA-Personal). Many enterprise networks deploy PSK-based authentication mechanisms for WPA/WPA2 since it is much easier than establishing the necessary RADIUS, supplicant and certificate authority architecture needed for WPA-Enterprise authentication. Cowpatty can implement an accelerated attack if a precomputed PMK file is available for the SSID that is being assessed.

- crackle:利用在BLE配对过程，允许攻击者猜测或很快蛮力TK（临时密钥）的一个漏洞。随着传统知识和配对过程中收集的其他数据中，STK（短期密钥）和后来的LTK（长期密钥）可以被收集。
  >crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected.

  >With the STK and LTK, all communications between the master and the slave can be decrypted.

- eapmd5pass:EAP-MD5认证暴力破解工具
  >EAP-MD5 is a legacy authentication mechanism that does not provide sufficient protection for user authentication credentials. Users who authenticate using EAP-MD5 subject themselves to an offline dictionary attack vulnerability. This tool reads from a live network interface in monitor-mode, or from a stored libpcap capture file, and extracts the portions of the EAP-MD5 authentication exchange. Once the challenge and response portions have been collected from this exchange, eapmd5pass will mount an offline dictionary attack against the user’s password.

- Easside-ng:无需key使用WEP AP的工具
  >Easside-ng is an auto-magic tool which allows you to communicate via an WEP-encrypted access point (AP) without knowing the WEP key. It first identifies a network, then proceeds to associate with it, obtain PRGA (pseudo random generation algorithm) xor data, determine the network IP scheme and then setup a TAP interface so that you can communicate with the AP without requiring the WEP key. All this is done without your intervention.
- Fern Wifi Cracker:Fern Wifi Cracker是一种无线安全审计和攻击软件编写的程序，使用Python编程语言和Python的Qt图形界面库，该程序是能够破解和恢复WEP、WPA、WPS键和无线或以太网上运行其他基于网络的攻击基于网络的。
  >Fern Wifi Cracker is a Wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks.

  >Fern Wifi Cracker currently supports the following features:

    - WEP Cracking with Fragmentation,Chop-Chop, Caffe-Latte, Hirte, ARP Request Replay or WPS attack
    - WPA/WPA2 Cracking with Dictionary or WPS based attacks
    - Automatic saving of key in database on successful crack
    - Automatic Access Point Attack System
    - Session Hijacking (Passive and Ethernet Modes)
    - Access Point MAC Address Geo Location Tracking
    - Internal MITM Engine
    - Bruteforce Attacks (HTTP,HTTPS,TELNET,FTP)
    - Update Support

- FreeRADIUS-WPE:尽管企业使用WPA/WPA2对802.1x授权的安全性会比PSK高，但它仍有不少漏洞。FreeRadius-WPE就可以帮助人们更好理解这些漏洞带来的攻击以及测试网络安全性。FreeRadius-WPE是一款针对开源FreeRADIUS服务器的补丁程序，旨在避免使用80.1x无线网络授权带来的中间人攻击。
  >A patch for the popular open-source FreeRADIUS implementation to demonstrate RADIUS impersonation vulnerabilities by Joshua Wright and Brad Antoniewicz. This patch adds the following functionality:

    - Simplifies the setup of FreeRADIUS by adding all RFC1918 addresses as acceptable NAS devices;
    - Simplifies the setup of EAP authentication by including support for all FreeRADIUS supported EAP types;
    - Adds WPE logging in $prefix/var/log/radius/freeradius-server-wpe.log, can be controlled in radius.conf by changing the “wpelogfile” directive;
    - Simplified the setup of user authentication with a default “users” file that accepts authentication for any username;
    - Adds credential logging for multiple EAP types including PEAP, TTLS, LEAP, EAP-MD5, EAP-MSCHAPv2, PAP, CHAP and others
- Ghost Phisher:无线网或者以太网安全评估和攻击软件-伪造服务钓鱼工具Ghost Phisher是一款支持有线网络和无线网络的安全审计工具。它通过伪造服务的方式，来收集网络中的有用信息。它不仅可以伪造AP，还可以伪造DNS服务、DHCP服务、HTTP服务。同时，它还可以构建陷阱，进行会话劫持、ARP攻击，最后还可以收集各种授权信息。该工具使用Python编写，并提供界面操作，所以使用非常方便。
  >Ghost Phisher is a Wireless and Ethernet security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to emulate access points and deploy.

  >Ghost Phisher currently supports the following features:

    - HTTP Server
    - Inbuilt RFC 1035 DNS Server
    - Inbuilt RFC 2131 DHCP Server
    - Webpage Hosting and Credential Logger (Phishing)
    - Wifi Access point Emulator
    - Session Hijacking (Passive and Ethernet Modes)
    - ARP Cache Poisoning (MITM and DOS Attacks)
    - Penetration using Metasploit Bindings
    - Automatic credential logging using SQlite Database
    - Update Support
- GISKismet:把Kismet的收集数据可视化
  >GISKismet is a wireless recon visualization tool to represent data gathered using Kismet in a flexible manner. GISKismet stores the information in a database so that the user can generate graphs using SQL. GISKismet currently uses SQLite for the database and GoogleEarth / KML files for graphing.
- Gqrx:软件定义的无线电接收器
  >Gqrx is a software defined radio receiver powered by the GNU Radio SDR framework and the Qt graphical toolkit. Gqrx supports many of the SDR hardware available, including Funcube Dongles, rtl-sdr, HackRF and USRP devices. See supported devices for a complete list. Gqrx is free and hacker friendly software. It comes with source code licensed under the GNU General Public license allowing anyone to fix and modify it for whatever use. Currently it works on Linux and Mac and supports the following devices:. Funcube Dongle Pro and Pro+ RTL2832U-based DVB-T dongles (rtlsdr via USB and TCP) OsmoSDR USRP HackRF Jawbreaker Nuand bladeRF any other device supported by the gr-osmosdr library

  >The latest stable version of Gqrx is 2.2, it is available for Linux, FreeBSD and Mac and it offers the following features:

    - Discover devices attached to the computer.
    - Process I/Q data from the supported devices.
    - Change frequency, gain and apply various corrections (frequency, I/Q balance).
    - AM, SSB, FM-N and FM-W (mono and stereo) demodulators.
    - Special FM mode for NOAA APT.
    - Variable band pass filter.
    - AGC, squelch and noise blankers.
    - FFT plot and waterfall.
    - Record and playback audio to / from WAV file.
    - Spectrum analyzer mode where all signal processing is disabled.

- gr-scan
  >gr-scan is a program written in C++, and built upon GNU Radio, rtl-sdr, and the OsmoSDR Source Block. It is intended to scan a range of frequencies and print a list of discovered signals. It should work with any device that works with that block, including Realtek RTL2832U devices. This software was developed using a Compro U620F, which uses an E4000 tuner. That product doesn’t seem to be available on the US site, but the Newsky DVB-T Receiver (RTL2832U/E4000 Device) has good reviews.
- hostapd-wpe:权限Server伪造
  >hostapd-wpe is the replacement for FreeRADIUS-WPE.

  >It implements IEEE 802.1x Authenticator and Authentication Server impersonation attacks to obtain client credentials, establish connectivity to the client, and launch other attacks where applicable.

  >hostapd-wpe supports the following EAP types for impersonation:
    1. EAP-FAST/MSCHAPv2 (Phase 0)
    2. PEAP/MSCHAPv2
    3. EAP-TTLS/MSCHAPv2 
    4. EAP-TTLS/MSCHAP
    5. EAP-TTLS/CHAP
    6. EAP-TTLS/PAP

  >Once impersonation is underway, hostapd-wpe will return an EAP-Success message so that the client believes they are connected to their legitimate authenticator.

  >For 802.11 clients, hostapd-wpe also implements Karma-style gratuitous probe responses. Inspiration for this was provided by JoMo-Kun’s patch for older versions of hostapd.
- ivstools
  >ivstools is included in the aircrack-ng package and is used to merge and covert .ivs files.

- kalibrate-rtl:GSM基站扫描
  >Kalibrate, or kal, can scan for GSM base stations in a given frequency band and can use those GSM base stations to calculate the local oscillator frequency offset.
- KillerBee:Attify ZigBee Framework是对备受赞誉的工具KillerBee的GUI封装，KillerBee由RiverLoop Security开发。AZF(Attify ZigBee Framework)适合任何刚开始接触物联网/无线电的人，它让使用KillerBee的整个过程变得更加容易。随着时间的推移，我们计划添加更多功能并拓展框架，使其更有效地识别Zigbee通信中的漏洞。
  >KillerBee is a Python based framework and tool set for exploring and exploiting the security of ZigBee and IEEE 802.15.4 networks. Using KillerBee tools and a compatible IEEE 802.15.4 radio interface, you can eavesdrop on ZigBee networks, replay traffic, attack cryptosystems and much more. Using the KillerBee framework, you can build your own tools, implement ZigBee fuzzing, emulate and attack end-devices, routers and coordinators and much more.
- Kismet:Kismet 是一款工作在 802.11 协议第二层的无线网络检测、嗅探、干扰工具。可以工作在支持raw监控模式的所有无线网卡上。可以嗅探包括 802.11b, 802.11a, 和 802.11g 在内的协议包。Kismet是一个基于Linux的无线网络扫描程序，这是一个相当方便的工具，通过测量周围的无线信号来找到目标WLAN。虽说Kismet也可以捕获网络上的数据通信，但在还有其他更好的工具使用(如Airodump)，在这里我们只使用它来确认无线网卡是否正常工作和用来扫描无线网络，在下面的部分中将会换用不同的工具软件来真正地侦听和捕获网络上的数据通信。
  >Kismet is an 802.11 layer-2 wireless network detector, sniffer, and intrusion detection system. It will work with any wireless card that supports raw monitoring (rfmon) mode, and can sniff 802.11a/b/g/n traffic. It can use other programs to play audio alarms for network events, read out network summaries, or provide GPS coordinates. This is the main package containing the core, client, and server.
- makeivs-ng
  >makeivs-ng is part of the aircrack-ng package and is used to generate an IVS dump file with a given WEP key. The aim of the tool is to provide a way to create dumps with a known encryption key for testing.
- mdk3:利用IEEE 802.11的协议漏洞
  >MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses. IMPORTANT: It is your responsibility to make sure you have permission from the network owner before running MDK against it.
- mfcuk:NFC芯片卡攻击
  >Toolkit containing samples and various tools based on and around libnfc and crapto1, with emphasis on Mifare Classic NXP/Philips RFID cards. Special emphasis of the toolkit is on the following:

    - mifare classic weakness demonstration/exploitation
    - demonstrate use of libnfc (and ACR122 readers)
    - demonstrate use of Crapto1 implementation to confirm internal workings and to verify theoretical/practical weaknesses/attacks
- mfoc:智能卡授权信息获取
  >MFOC is an open source implementation of “offline nested” attack by Nethemba.
  >This program allow to recover authentication keys from MIFARE Classic card.

  >Please note MFOC is able to recover keys from target only if it have a known key: default one (hardcoded in MFOC) or custom one (user provided using command line).
- mfterm:智能卡Mifare芯片的操作终端
  >mfterm is a terminal interface for working with Mifare Classic tags.

  >Tab completion on commands is available. Also, commands that have file name arguments provide tab completion on files. There is also a command history, like in most normal shells.
- Multimon-NG:数据传输的解码
  >MultimonNG a fork of multimon. It decodes the following digital transmission modes:

    - POCSAG512 POCSAG1200 POCSAG2400
    - EAS
    - UFSK1200 CLIPFSK AFSK1200 AFSK2400 AFSK2400_2 AFSK2400_3
    - HAPN4800
    - FSK9600
    - DTMF
    - ZVEI1 ZVEI2 ZVEI3 DZVEI PZVEI
    - EEA EIA CCIR
    - MORSE CW
- Packetforge-ng
  >The purpose of packetforge-ng is to create encrypted packets that can subsequently be used for injection. You may create various types of packets such as arp requests, UDP, ICMP and custom packets. The most common use is to create ARP requests for subsequent injection.

- PixieWPS:Pixiewps大大缩短了暴力破解WPS的时间，从10多个小时到几秒钟！
  >Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only. All credits for the research go to Dominique Bongard.

  >Features:

    - Checksum optimization: it’ll try first for valid PINs (11’000);
    - Reduced entropy of the seed from 32 to 25 bits for the C LCG pseudo-random function;
    - Small Diffie-Hellman keys: don’t need to specify the Public Registrar Key if the same option is used with Reaver.
    - The program will also try first with E-S0 = E-S1 = 0, then it’ll tries to bruteforce the seed of the PRNG if the –e-nonce option is specificed.
- Pyrit:使用GPU加速工具PYRIT极速破解无线密码 
  >Pyrit allows you to create massive databases of pre-computed WPA/WPA2-PSK authentication phase in a space-time-tradeoff. By using the computational power of Multi-Core CPUs and other platforms through ATI-Stream,Nvidia CUDA and OpenCL, it is currently by far the most powerful attack against one of the world’s most used security-protocols.
- Reaver:Wifi WPA/WPA2协议下密码破解工具
  >Reaver implements a brute force attack against Wifi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases, as described in http://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf.

  >Reaver has been designed to be a robust and practical attack against WPS, and has been tested against a wide variety of access points and WPS implementations.

  >On average Reaver will recover the target AP’s plain text WPA/WPA2 passphrase in 4-10 hours, depending on the AP. In practice, it will generally take half this time to guess the correct WPS pin and recover the passphrase
- redfang:发现蓝牙设备
  >RedFang is a small proof-of-concept application to find non discoverable Bluetooth devices. This is done by brute forcing the last six (6) bytes of the Bluetooth address of the device and doing a read_remote_name().

- RTLSDR Scanner：是一款免费的网络扫描工具，使您能够快速找到网络计算机上的开放端口（TCP 和 UDP），并对检测到的端口上运行的程序版本进行检索。
  >A cross platform Python frequency scanning GUI for USB TV dongles, using the OsmoSDR rtl-sdr library.
  >In other words a cheap, simple Spectrum Analyser.

  >The scanner attempts to overcome the tuner’s frequency response by averaging scans from both the positive and negative frequency offets of the baseband data.

- Spooftooph:自动化欺骗和复制蓝牙设备信息的工具
  >Spooftooph is designed to automate spoofing or cloning Bluetooth device information. Make a Bluetooth device hide in plain site.

  >Features:

    - Clone and log Bluetooth device information
    - Generate a random new Bluetooth profile
    - Change Bluetooth profile every X seconds
    - Specify device information for Bluetooth interface
    - Select device to clone from scan log
- Tkiptun-ng:Tkiptun-ng设计思路主要是通过获得一个包含明文与MIC(消息完整性检查)的数据包作为开始，然后使用MICHAEL算法替换了原本用于保护从AP发往客户端的数据包的MIC秘钥，使其能够计算出来。稍等片刻后，Tkiptun-ng便能够恢复关键的MIC秘钥，并且得到AP与客户端通信的keysteam，这样，之后就可以使用异或文件来创建新的数据包并注入其中。归根结底，Tkiptun-ng只是可以解开使用tkip加密了的数据包，并不是说能够快速算出WPA PMK或WPA PS
  >Tkiptun-ng is the proof-of-concept implementation the WPA/TKIP attack. This attack is described in the paper, Practical attacks against WEP and WPA written by Martin Beck and Erik Tews. The paper describes advanced attacks on WEP and the first practical attack on WPA.

- Wesside-ng:　wesside-ng是一款自动化的WEP破解工具，该工具采用了多种WEP加密破解技术。它首先会自动明确目标无线网络，然后尝试与之相关联，在获得PRGA（伪随机生成算法)异或数据后，会确定该无线网络中的IP，并重新注入ARP请求，直到最终获得足够的IVS后便顺利破解出WEP秘钥。
  >Wesside-ng is an auto-magic tool which incorporates a number of techniques to seamlessly obtain a WEP key in minutes. It first identifies a network, then proceeds to associate with it, obtain PRGA (pseudo random generation algorithm) xor data, determine the network IP scheme, reinject ARP requests and finally determine the WEP key. All this is done without your intervention.
- Wifi Honey:这是一个wifi蜜罐脚本，它会建立5个监控模式的接口，其中四个是aps，另一个则是为airdump-ng使用
  >This script creates five monitor mode interfaces, four are used as APs and the fifth is used for airodump-ng. To make things easier, rather than having five windows all this is done in a screen session which allows you to switch between screens to see what is going on. All sessions are labelled so you know which is which.

- wifiphisher:针对Wi-Fi网络的自动网络钓鱼攻击。
  >Wifiphisher is a security tool that mounts automated phishing attacks against Wi-Fi networks in order to obtain credentials or infect the victims with ‘malware’. It is a social engineering attack that can be used to obtain WPA/WPA2 secret passphrases and unlike other methods, it does not require any brute forcing.
  >After achieving a man-in-the-middle position using the Evil Twin attack, Wifiphisher redirects all HTTP requests to an attacker-controlled phishing page.

  >From the victim’s perspective, the attack takes place in three phases:

    - Victim is deauthenticated from their access point.
    - Victim joins a rogue access point. Wifiphisher sniffs the area and copies the target access point settings.
    - Victim is served a realistic specially-customized phishing page.
- Wifitap:通过使用流量注入的WiFi网络进行通信的概念验证。
  >Wifitap is a proof of concept for communication over WiFi networks using traffic injection.

  >Wifitap allows any application do send and receive IP packets using 802.11 traffic capture and injection over a WiFi network simply configuring wj0, which means :

    - setting an IP address consistent with target network address range
    - routing desired traffic through it
  >In particular, it’s a cheap method for arbitrary packets injection in 802.11 frames without specific library.

  >In addition, it will allow one to get rid of any limitation set at access point level, such as bypassing inter-client communications prevention systems (e.g. Cisco PSPF) or reaching multiple SSID handled by the same access point.
- Wifite:wifite是一款自动化wep、wpa破解工具，不支持windows和osx。wifite的特点是可以同时攻击多个采用wep和wpa加密的网络。wifite只需简单的配置即可自动化运行，期间无需人工干预。
  >To attack multiple WEP, WPA, and WPS encrypted networks in a row. This tool is customizable to be automated with only a few arguments. Wifite aims to be the “set it and forget it” wireless auditing tool.

  >Features:

    - sorts targets by signal strength (in dB); cracks closest access points first
    - automatically de-authenticates clients of hidden networks to reveal SSIDs
    - numerous filters to specify exactly what to attack (wep/wpa/both, above certain signal strengths, channels, etc)
    - customizable settings (timeouts, packets/sec, etc)
    - “anonymous” feature; changes MAC to a random address before attacking, then changes back when attacks are complete
    - all captured WPA handshakes are backed up to wifite.py’s current directory
    - smart WPA de-authentication; cycles between all clients and broadcast deauths
    - stop any attack with Ctrl+C, with options to continue, move onto next target, skip to cracking, or exit
    - displays session summary at exit; shows any cracked keys
    - all passwords saved to cracked.txt
- wpaclean
  >wpaclean is a small utility included in the aircrack-ng package that is used to clean capture files to get only the 4-way handshake and a beacon.

## Reverse Engineering 逆向工程

- apktool:APK逆向
  >It is a tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications; it makes possible to debug smali code step by step. Also it makes working with app easier because of project-like files structure and automation of some repetitive tasks like building apk, etc.

  >It is NOT intended for piracy and other non-legal uses. It could be used for localizing, adding some features or support for custom platforms and other GOOD purposes. Just try to be fair with authors of an app, that you use and probably like.

  >Features:

    - decoding resources to nearly original form (including resources.arsc, XMLs and 9.png files) and rebuilding them
    - smali debugging: SmaliDebugging
    - helping with some repetitive tasks
- dex2jar:Dex转Jar
  >dex2jar contains following compments:

    - dex-reader is designed to read the Dalvik Executable (.dex/.odex) format. It has a light weight API similar with ASM.
    - dex-translator is designed to do the convert job. It reads the dex instruction to dex-ir format, after some optimize, convert to ASM format.
    - dex-ir used by dex-translator, is designed to represent the dex instruction
    - dex-tools tools to work with .class files. here are examples: Modify a apk, DeObfuscate a jar
    - d2j-smali [To be published] disassemble dex to smali files and assemble dex from smali files. different implementation to smali/baksmali, same syntax, but we support escape in type desc “Lcom/dex2jar\t\u1234;”
    - dex-writer [To be published] write dex same way as dex-reader.
- diStorm3:diStorm3是Kali Linux自带的一款轻量级、容易使用的反汇编引擎。它可以反汇编生成16位、32位和64位指令。它支持的指令集包括FPU、MMX、SSE、SSE2、SSE3、SSSE3、SSE4、3DNow@、x86-64、VMX、AMDs、SVM等。虽然diStorm3采用C语言编写，但可以被Python、Ruby、Java快速封装。这样，用户可以使用Python、Ruby等脚本语言编写脚本，并引入diStorm3，从而定制自己的反汇编工具。

  >diStorm is a lightweight, easy-to-use and fast decomposer library. diStorm disassembles instructions in 16, 32 and 64 bit modes. Supported instruction sets: FPU, MMX, SSE, SSE2, SSE3, SSSE3, SSE4, 3DNow! (w/ extensions), new x86-64 instruction sets, VMX, AMD’s SVM and AVX!. The output of new interface of diStorm is a special structure that can describe any x86 instruction, this structure can be later formatted into text for display too. diStorm is written in C, but for rapidly use, diStorm also has wrappers in Python/Ruby/Java and can easily be used in C as well. It is also the fastest disassembler library!. The source code is very clean, readable, portable and platform independent (supports both little and big endianity). diStorm solely depends on the C library, therefore it can be used in embedded or kernel modules. Note that diStorm3 is backward compatible with the interface of diStorm64 (however, make sure you use the newest header files).
- edb-debugger:扩平台调试器
  >A Linux equivalent of the famous Olly debugger on the Windows platform. Some of its features are:.

    - Intuitive GUI interface
    - The usual debugging operations (step-into/step-over/run/break)
    - Conditional breakpoints
    - Debugging core is implemented as a plugin so people can have drop in replacements. Of course if a given platform has several debugging APIs available, then you may have a plugin that implements any of them.
    - Basic instruction analysis
    - View/Dump memory regions
    - Effective address inspection
    - The data dump view is tabbed, allowing you to have several views of memory open at the same time and quickly switch between them.
    - Importing and generation of symbol maps
    - Plugins
- jad: Java反编译
- javasnoop
  >Normally, without access to the original source code, testing the security of a Java client is unpredictable at best and unrealistic at worst. With access the original source, you can run a simple Java program and attach a debugger to it remotely, stepping through code and changing variables where needed. Doing the same with an applet is a little bit more difficult.

  >Unfortunately, real-life scenarios don’t offer you this option, anyway. Compilation and decompilation of Java are not really as deterministic as you might imagine. Therefore, you can’t just decompile a Java application, run it locally and attach a debugger to it.

  >Next, you may try to just alter the communication channel between the client and the server, which is where most of the interesting things happen anyway. This works if the client uses HTTP with a configurable proxy. Otherwise, you’re stuck with generic network traffic altering mechanisms. These are not so great for almost all cases, because the data is usually not plaintext. It’s usually a custom protocol, serialized objects, encrypted, or some combination of those.

  >JavaSnoop attempts to solve this problem by allowing you attach to an existing process (like a debugger) and instantly begin tampering with method calls, run custom code, or just watch what’s happening on the system.
- JD-GUI:JAD GUI
  >JD-GUI is a standalone graphical utility that displays Java source codes of “.class” files. You can browse the reconstructed source code with the JD-GUI for instant access to methods and fields.
- OllyDbg:汇编调试器
  >OllyDbg is a 32-bit assembler level analysing debugger for Microsoft Windows. Emphasis on binary code analysis makes it particularly useful in cases where source is unavailable.

  >Features:

    - Intuitive user interface, no cryptical commands
    - Code analysis – traces registers, recognizes procedures, loops, API calls, switches, tables, constants and strings
    - Directly loads and debugs DLLs
    - Object file scanning – locates routines from object files and libraries
    - Allows for user-defined labels, comments and function descriptions
    - Understands debugging information in Borland® format
    - Saves patches between sessions, writes them back to executable file and updates fixups
    - Open architecture – many third-party plugins are available
    - No installation – no trash in registry or system directories
    - Debugs multithread applications
    - Attaches to running programs
    - Configurable disassembler, supports both MASM and IDEAL formats
    - MMX, 3DNow! and SSE data types and instructions, including Athlon extensions
    - Full UNICODE support
    - Dynamically recognizes ASCII and UNICODE strings – also in Delphi format!
    - Recognizes complex code constructs, like call to jump to procedure
    - Decodes calls to more than 1900 standard API and 400 C functions
    - Gives context-sensitive help on API functions from external help file
    - Sets conditional, logging, memory and hardware breakpoints
    - Traces program execution, logs arguments of known functions
    - Shows fixups
    - Dynamically traces stack frames
    - Searches for imprecise commands and masked binary sequences
    - Searches whole allocated memory
    - Finds references to constant or address range
    - Examines and modifies memory, sets breakpoints and pauses program on-the-fly
    - Assembles commands into the shortest binary form
    - Starts from the floppy disk
- smali：DEX汇编和反汇编
  >smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android’s Java VM implementation. The syntax is loosely based on Jasmin’s/dedexer’s syntax, and supports the full functionality of the dex format (annotations, debug info, line info, etc.)

- Valgrind:是一款用于内存调试、内存泄漏检测以及性能分析的软件开发工具。
  >Valgrind is a system for debugging and profiling Linux programs. With its tool suite you can automatically detect many memory management and threading bugs, avoiding hours of frustrating bug-hunting and making your programs more stable. You can also perform detailed profiling to help speed up your programs and use Valgrind to build new tools. The Valgrind distribution currently includes six production-quality tools:

    - a memory error detector (Memcheck)
    - two thread error detectors (Helgrind and DRD)
    - a cache and branch-prediction profiler (Cachegrind)
    - a call-graph generating cache and branch-prediction profiler (Callgrind)
    - a heap profiler (Massif)
  >It also includes three experimental tools:

    - a stack/global array overrun detector (SGCheck)
    - a second heap profiler that examines how heap blocks are used (DHAT)
    - a SimPoint basic block vector generator (BBV)
- YARA:YARA是一款旨在帮助恶意软件研究人员识别和分类恶意软件样本的开源工具（由virustotal的软件工程师Victor M. Alvarezk开发），使用YARA可以基于文本或二进制模式创建恶意软件家族描述信息，当然也可以是其他匹配信息。YARA的每一条描述或规则都由一系列字符串和一个布尔型表达式构成，并阐述其逻辑。YARA规则可以提交给文件或在运行进程，以帮助研究人员识别其是否属于某个已进行规则描述的恶意软件家族。
  >With YARA you can create descriptions of malware families based on textual or binary patterns contained on samples of those families. Each description consists of a set of strings and a boolean expression which determines its logic. This package contains the command-line interface.


## Exploitation Tools - 漏洞利用工具集

- Armitage:一个图形化的metasploit网络攻击管理工具，它可视化你的攻击目标，推荐exploit和公开了metasploit框架的高级功能。
  >Armitage is a scriptable red team collaboration tool for Metasploit that visualizes targets, recommends exploits, and exposes the advanced post-exploitation features in the framework.

  >Through one Metasploit instance, your team will:

    - Use the same sessions
    - Share hosts, captured data, and downloaded files
    - Communicate through a shared event log.
    - Run bots to automate red team tasks.
    - Armitage is a force multiplier for red team operations.
- Backdoor Factory:The Backdoor Factory是一款安全测试工具，可以轻松的生成win32PE后门测试程序。值得注意的是，本工具仅用于安全实验和信息安全实验教学使用，禁止任何非法用途！
  >The goal of BDF is patch executable binaries with user desidered shellcode and continue normal execution of the prepatched state.

  >Supporting: Windows PE x32/x64 and Linux ELF x32/x64 (System V)

  >Some executables have built in protections, as such this will not work on all binaries. It is advisable that you test target binaries before deploying them to clients or using them in exercises.
- BeEF:BeEF是目前欧美最流行的web框架攻击平台，它的全称是 the Browser exploitation framework project.最近两年国外各种黑客的会议都有它的介绍，很多pentester对这个工具都有很高的赞美。通过XSS这个简单的漏洞，BeEF可以通过一段编制好的javascript控制目标主机的浏览器，通过浏览器拿到各种信息并且扫描内网信息，同时能够配合metasploit进一步渗透主机，强大的有些吓人。
  >BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.

  >Amid growing concerns about web-borne attacks against clients, including mobile clients, BeEF allows the professional penetration tester to assess the actual security posture of a target environment by using client-side attack vectors. Unlike other security frameworks, BeEF looks past the hardened network perimeter and client system, and examines exploitability within the context of the one open door: the web browser. BeEF will hook one or more web browsers and use them as beachheads for launching directed command modules and further attacks against the system from within the browser context.
- cisco-auditing-tool:一个很小的安全审计工具，扫描Cisco路由器的一般性漏洞，例如默认密码，SNMP community字串和一些老的IOS bug
  >Perl script which scans cisco routers for common vulnerabilities.
- cisco-global-exploiter
  >Cisco Global Exploiter (CGE), is an advanced, simple and fast security testing tool.
- cisco-ocs:Cisco路由器安全扫描器
  >A mass Cisco scanning tool.
- cisco-torch:Cisco Torch 是一款集成扫描、电子指纹识别、漏洞利用的针对Cisco设备的强大工具。它可以多线程在后台进行扫描，效率非常高，另外，它的扫描是在多个协议层的，可以发现在网络中运行有Telnet、SSH、Web、NEP和SNMP服务的Cisco设备，并可以根据其开启的服务进行攻击。
  >Cisco Torch mass scanning, fingerprinting, and exploitation tool was written while working on the next edition of the “Hacking Exposed Cisco Networks”, since the tools available on the market could not meet our needs.

  >The main feature that makes Cisco-torch different from similar tools is the extensive use of forking to launch multiple scanning processes on the background for maximum scanning efficiency. Also, it uses several methods of application layer fingerprinting simultaneously, if needed. We wanted something fast to discover remote Cisco hosts running Telnet, SSH, Web, NTP and SNMP services and launch dictionary attacks against the services discovered.
- Commix:是一个适用于web开发者、渗透测试人员及安全研究者的自动化测试工具，可以帮助他们更高效的发现web应用中的命令注入攻击相关漏洞。Commix由Python编写。
  >Commix (short for [comm]and [i]njection e[x]ploiter) has a simple environment and it can be used, from web developers, penetration testers or even security researchers to test web applications with the view to find bugs, errors or vulnerabilities related to command injection attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or string. Commix is written in Python programming language.
- crackle:利用在BLE配对过程，允许攻击者猜测或很快蛮力TK（临时密钥）的一个漏洞。随着传统知识和配对过程中收集的其他数据中，STK（短期密钥）和后来的LTK（长期密钥）可以被收集。
  >crackle exploits a flaw in the BLE pairing process that allows an attacker to guess or very quickly brute force the TK (Temporary Key). With the TK and other data collected from the pairing process, the STK (Short Term Key) and later the LTK (Long Term Key) can be collected.

  >With the STK and LTK, all communications between the master and the slave can be decrypted.
- exploitdb:大型漏洞数据库
  >Searchable archive from The Exploit Database.
- jboss-autopwn:这个JBOSS脚本会在目标JBOSS服务器上部署一个JSP Shell，部署成功后，渗透测试人员可以获得一个交互式会话，可以进行命令执行等工作。
  >This JBoss script deploys a JSP shell on the target JBoss AS server. Once deployed, the script uses its upload and command execution capability to provide an interactive session.
- Linux Exploit Suggester: Linux漏洞建议工具Linux Exploit Suggester.在Linux系统渗透测试中，通常使用Nessus、OpenVAS对目标主机进行扫描，获取目标主机可能存在的漏洞。如果无法进行漏洞扫描操作，或者无法判断获取的漏洞中哪些可以获取root权限，这时可以使用Kali Linux自带工具Linux Exploit Suggester。该工具可以对指定版本内核给出建议，提示该版本存在哪些root权限相关的漏洞信息，同时给出漏洞利用工具的下载地址。

  >As the name suggests, this is a Linux Exploit Suggester, with no frills and no fancy features; just a simple script to keep track of vulnerabilities and suggest possible exploits to use to gain ‘root‘ on a legitimate penetration test, or governing examining body
- Maltego Teeth:Maltego是一个开源的漏洞评估工具，它主要用于论证一个网络内单点故障的复杂性和严重性。该工具能够聚集来自内部和外部资源的信息，并且提供一个清晰的漏洞分析界面。
  >Maltego is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. Maltego’s unique advantage is to demonstrate the complexity and severity of single points of failure as well as trust relationships that exist currently within the scope of your infrastructure.

  >The unique perspective that Maltego offers to both network and resource based entities is the aggregation of information posted all over the internet – whether it’s the current configuration of a router poised on the edge of your network or the current whereabouts of your Vice President on his international visits, Maltego can locate, aggregate and visualize this information.

  >Maltego offers the user with unprecedented information. Information is leverage. Information is power. Information is Maltego.

  >What does Maltego do?

  >Maltego is a program that can be used to determine the relationships and real world links between:

    - People
    - Groups of people (social networks)
    - Companies
    - Organizations
    - Web sites
    - Internet infrastructure such as:
    - Domains
    - DNS names
    - Netblocks
    - IP addresses
    - Phrases
    - Affiliations
    - Documents and files
    - These entities are linked using open source intelligence.
    - Maltego is easy and quick to install – it uses Java, so it runs on Windows, Mac and Linux.
    - Maltego provides you with a graphical interface that makes seeing these relationships instant and accurate – making it possible to see hidden connections.
    - Using the graphical user interface (GUI) you can see relationships easily – even if they are three or four degrees of separation away.
    - Maltego is unique because it uses a powerful, flexible framework that makes customizing possible. As such, Maltego can be adapted to your own, unique requirements.
  >What can Maltego do for me?

    - Maltego can be used for the information gathering phase of all security related work. It will save you time and will allow you to work more accurately and smarter.
    - Maltego aids you in your thinking process by visually demonstrating interconnected links between searched items.
    - Maltego provide you with a much more powerful search, giving you smarter results.
    - If access to “hidden” information determines your success, Maltego can help you discover it.
- Metasploit Framework:Metasploit就是一个漏洞框架。它的全称叫做The Metasploit Framework，简称叫做MSF。Metasploit作为全球最受欢迎的工具，不仅仅是因为它的方便性和强大性，更重要的是它的框架。它允许使用者开发自己的漏洞脚本，从而进行测试。
  >Metasploit is a penetration testing platform that enables you to find, exploit, and validate vulnerabilities. It provides the infrastructure, content, and tools to perform penetration tests and extensive security auditing and thanks to the open source community and Rapid7’s own hard working content team, new modules are added on a regular basis, which means that the latest exploit is available to you as soon as it’s published.
- MSFPC:根据用户选择生成多类型的攻击载荷。这个想法就是让攻击载荷生成尽可能简单
  >MSFvenom Payload Creator (MSFPC) is a wrapper that generates multiple types of payloads, based on user-selected options. The idea is to be as simple as possible (using as few as one option) to produce a payload.

  >Fully automating msfvenom & Metasploit is the end goal (well as to be be able to automate MSFPC itself). The rest is to make the user’s life as easy as possible (e.g. IP selection menu, msfconsole resource file/commands, batch payload production and able to enter any argument in any order (in various formats/patterns)).
- RouterSploit:RouteSploit框架是一款开源的漏洞检测及利用框架，其针对的对象主要为路由器等嵌入式设备。
  >The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices. It consists of various modules that aids penetration testing operations:

    - exploits – modules that take advantage of identified vulnerabilities
    - creds – modules designed to test credentials against network services
    - scanners – modules that check if a target is vulnerable to any exploit
- SET: https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf
  >The Social-Engineer Toolkit is an open-source penetration testing framework designed for Social-Engineering. SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of the time.
    - SPEAR-PHISHING:交叉式鱼叉
    - Applet
    - 浏览器全屏
    - Metasploit
    - 凭证收集
    - Tab点击
    - URL作伪点击
    - 复合多维度Web攻击向量
    - U盘\DVD病毒
    - USB做成键盘
    - SMS欺骗
    - 无线攻击
    - 二维码攻击

    - 1BEGINNING WITH THE SOCIAL ENGINEER TOOLKIT.............2
    - 2SET MENU’S..............8
    - 3SPEAR-PHISHING ATTACK VECTOR............14
    - 4JAVA APPLET ATTACK VECTOR....20
    - 5FULL SCREEN ATTACK VECTOR...27
    - 6METASPLOIT BROWSER EXPLOIT METHOD.........................29
    - 7CREDENTIAL HARVESTERATTACK METHOD......................34
    - 8TABNABBING ATTACK METHOD...38
    - 9WEB JACKING ATTACK METHOD.................41
    - 10MULTI-ATTACK WEB VECTOR.....44
    - 11INFECTIOUS MEDIA GENERATOR..............54
    - 12TEENSY USB HID ATTACK VECTOR...........59
    - 13SMS SPOOFING ATTACK VECTOR.............66
    - 14WIRELESS ATTACK VECTOR........68
    - 15QRCODE ATTACK VECTOR..........70
    - 16FAST-TRACK EXPLOITATION.......71
    - 17SET INTERACTIVE SHELL AND RATTE.......72
    - 18SET AUTOMATION.........................76
    - 19FREQUENTLY ASKED QUESTIONS.............81
    - 20CODE SIGNING CERTIFICATES....81
    - 21DEVELOPING YOUR OWN SET MODULES...........................82
- ShellNoob:Shellcode开发辅助工具shellnoob。Shellcode开发的过程中会遇到很多繁杂的工作，如编译、反编译、调试等。为了减少这部分工作，Kali Linux提供了开发辅助工具shellnoob。该工具提供各类辅助开发功能：（1）它提供了交互模式，让开发者更直观的看到运行效果。（2）它提供强大的格式转化功能，可以把Shellcode在十几种格式之间转化。（3）提供简洁的跟踪调试功能，方便用户分析代码。（4）提供打包、反编译和安装功能。
  >Writing shellcodes has always been super fun, but some parts are extremely boring and error prone. Focus only on the fun part, and use ShellNoob!

  >Features:

    - convert shellcode between different formats and sources. Formats currently supported: asm, bin, hex, obj, exe, C, python, ruby, pretty, safeasm, completec, shellstorm. (All details in the “Formats description” section.)
    - interactive asm-to-opcode conversion (and viceversa) mode. This is useful when you cannot use specific bytes in the shellcode and you want to figure out if a specific assembly instruction will cause problems.
    - support for both ATT & Intel syntax. Check the –intel switch.
    - support for 32 and 64 bits (when playing on x86_64 machine). Check the –64 switch.
    - resolve syscall numbers, constants, and error numbers (now implemented for real! :-)).
    - portable and easily deployable (it only relies on gcc/as/objdump and python). It is just one self-contained python script, and it supports both Python2.7+ and Python3+.
    - in-place development: you run ShellNoob directly on the target architecture!
    - built-in support for Linux/x86, Linux/x86_64, Linux/ARM, FreeBSD/x86, FreeBSD/x86_64.
    - “prepend breakpoint” option. Check the -c switch.
    - read from stdin / write to stdout support (use “-” as filename)
    - uber cheap debugging: check the –to-strace and –to-gdb option!
    - Use ShellNoob as a Python module in your scripts! Check the “ShellNoob as a library” section.
    - Verbose mode shows the low-level steps of the conversion: useful to debug / understand / learn!
    - Extra plugins: binary patching made easy with the –file-patch, –vm-patch, –fork-nopper options! (all details below)
- sqlmap:SQLmap是一款用来检测与利用SQL注入漏洞的免费开源工具，有一个非常棒的特性，即对检测与利用的自动化处理（数据库指纹、访问底层文件系统、执行命令）。
  >sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

  >Features:

    - Full support for MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase and SAP MaxDB database management systems.
    - Full support for six SQL injection techniques: boolean-based blind, time-based blind, error-based, UNION query, stacked queries and out-of-band.
    - Support to directly connect to the database without passing via a SQL injection, by providing DBMS credentials, IP address, port and database name.
    - Support to enumerate users, password hashes, privileges, roles, databases, tables and columns.
    - Automatic recognition of password hash formats and support for cracking them using a dictionary-based attack.
    - Support to dump database tables entirely, a range of entries or specific columns as per user’s choice. The user can also choose to dump only a range of characters from each column’s entry.
    - Support to search for specific database names, specific tables across all databases or specific columns across all databases’ tables. This is useful, for instance, to identify tables containing custom application credentials where relevant columns’ names contain string like name and pass.
    - Support to download and upload any file from the database server underlying file system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to execute arbitrary commands and retrieve their standard output on the database server underlying operating system when the database software is MySQL, PostgreSQL or Microsoft SQL Server.
    - Support to establish an out-of-band stateful TCP connection between the attacker machine and the database server underlying operating system. This channel can be an interactive command prompt, a Meterpreter session or a graphical user interface (VNC) session as per user’s choice.
    - Support for database process’ user privilege escalation via Metasploit’s Meterpreter getsystem command.
- THC-IPV6:THC-IPV6是一套完整的工具包，可用来攻击IPV6和ICMP6协议的固有弱点，THC-IPV6包含了易用的库文件，可二次开发。THC-IPV6由先进的主机存活扫描工具，中间人攻击工具，拒绝服务攻击工具构成。
  >A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
- Yersinia:Yersinia 是国外的一款专门针对交换机的攻击工具。它现在的最新版本是0.7.1。Yersinia主要是针对交换机上运行的一些网络协议进行的攻击，截至到现在，可以完成的攻击协议见下面的列表，针对这些网络协议，Yersinia攻击的实现方式也是这个软件最大的特点是，他可以根据攻击者的需要和网络协议自身存在的漏洞，通过伪造一些特定的协议信息或协议包来实现对这些网络协议的破坏以达到攻击目的。
  >Yersinia is a framework for performing layer 2 attacks. It is designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. Attacks for the following network protocols are implemented in this particular release:

    - Spanning Tree Protocol (STP)
    - Cisco Discovery Protocol (CDP)
    - Dynamic Trunking Protocol (DTP)
    - Dynamic Host Configuration Protocol (DHCP)
    - Hot Standby Router Protocol (HSRP)
    - 802.1q
    - 802.1x
    - Inter-Switch Link Protocol (ISL)
    - VLAN Trunking Protocol (VTP)

## Sniffing & Spoofing - 嗅探和欺骗

- Burp Suite:Burp Suite是Web应用程序测试的最佳工具之一，其多种功能可以帮我们执行各种任务.请求的拦截和修改,扫描web应用程序漏洞,以暴力破解登陆表单,执行会话令牌等多种的随机性检查。
  >Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application’s attack surface, through to finding and exploiting security vulnerabilities.

  >Burp gives you full control, letting you combine advanced manual techniques with state-of-the-art automation, to make your work faster, more effective, and more fun.
- DNSChef:DNSChef是一个高度可配置的DNS代理，用于渗透测试和恶意软件分析。DNS代理（又名“假DNS”），可用于分析用户间传输的网络流量。例如，我们可以使用一个DNS代理伪造所有到“badguy.com”的请求至本地计算机，进而对流量进行分析。在最新的版本0.2中，引入了对IPv6的支持、大量新的DNS记录类型，自定义端口和其他常用的功能。
  >DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka “Fake DNS”) is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for “badguy.com” to point to a local machine for termination or interception instead of a real host somewhere on the Internet.

  >There are several DNS Proxies out there. Most will simply point all DNS queries a single IP address or implement only rudimentary filtering. DNSChef was developed as part of a penetration test where there was a need for a more configurable system. As a result, DNSChef is cross-platform application capable of forging responses based on inclusive and exclusive domain lists, supporting multiple DNS record types, matching domains with wildcards, proxying true responses for nonmatching domains, defining external configuration files, IPv6 and many other features. You can find detailed explanation of each of the features and suggested uses below.

  >The use of DNS Proxy is recommended in situations where it is not possible to force an application to use some other proxy server directly. For example, some mobile applications completely ignore OS HTTP Proxy settings. In these cases, the use of a DNS proxy server such as DNSChef will allow you to trick that application into forwarding connections to the desired destination.
- fiked:VPN凭证嗅探工具fiked。虚拟专用网络（VPN）是在公用网络中建立的专用网络。基于VPN方式，可以将两个局域网通过公共网络连接在一起。两个局域网之间传输的数据都是加密的，所以可以保证通信的安全性。在整个VPN连接中，每个局域网都有一个VPN网关。该网关连接局域网，并连接公网。当局域网的一台电脑要通过VPN访问另外一个局域网的电脑，都要通过VPN网关连接。连接过程中，通过分别验证预设密钥和凭证（用户名和密码），建立连接。其中，预设密钥安全度较低，而凭证的安全度较高。Kali Linux提供了fiked工具。通过中间人攻击方式获取流量后，该工具会伪装为VPN网关，使用预先设置的预设密钥，而骗取客户端的VPN凭证。PS：该工具只针对IKE中的XAUTH授权方式，因为该方式不对网关端点进行验证。
 
  >FakeIKEd, or fiked for short, is a fake IKE daemon supporting just enough of the standards and Cisco extensions to attack commonly found insecure Cisco VPN PSK+XAUTH based IPsec authentication setups in what could be described as a semi MitM attack. Fiked can impersonate a VPN gateway’s IKE responder in order to capture XAUTH login credentials; it doesn’t currently do the client part of full MitM.
- hamster-sidejack:Session side jacking工具hamster-sidejack。Session side jacking是会话劫持（session hijacking）方式的一种。实现方式为，渗透测试人员通过嗅探客户端和服务器之间的数据，获取会话的cookie。然后，然后利用该cookie，以该cookie的所有者身份访问服务器，以获得相应的数据。Kali Linux提供对应的工具hamster-sidejack。该工具把提取cookie和利用cookie整合在一起，简化渗透测试人员的操作。渗透测试人员只需要通过中间人攻击截取流量，然后设置HTTP代理，就可以在本机浏览器中获取cookie，并直接利用。
  >Hamster is a tool or “sidejacking”. It acts as a proxy server that replaces your cookies with session cookies stolen from somebody else, allowing you to hijack their sessions. Cookies are sniffed using the Ferret program. You need a copy of that as well.

- HexInject:网络数据嗅探工具HexInject.网络数据嗅探是渗透测试工作的重要组成部分。通过嗅探，渗透人员可以了解足够多的内容。极端情况下，只要通过嗅探，就可以完成整个任务，如嗅探到支持网络登录的管理员帐号和密码。为了实现这个功能，Kali Linux中的很多软件都提供这种功能，最知名的就是Wireshark，唯一缺点就是只能运行在图形界面中。如果在终端中，用户可以使用HexInject工具。该工具不仅可以嗅探，还可以支持数据注入。最强大的地方就是，它可以结合Shell脚本，实现各种复杂的任务。在嗅探方面，它支持有线的混杂模式，还支持无线的监听模式。在显示方面，它支持十六进制数值显示，还支持原始数据模式。配合Shell脚本，可以对结果进行各种处理。
  >HexInject is a very versatile packet injector and sniffer, that provide a command-line framework for raw network access. It’s designed to work together with others command-line utilities, and for this reason it facilitates the creation of powerful shell scripts capable of reading, intercepting and modifying network traffic in a transparent manner.

- iaxflood:内部电话机协议Inter-Asterisk_eXchange的泛洪攻击工具
  >A UDP Inter-Asterisk_eXchange (i.e. IAX) packet was captured from an IAX channel between two Asterisk IP PBX’s. The content of that packet is the source of the payload for the attack embodied by this tool. While the IAX protocol header might not match the Asterisk PBX you’ll attack with this tool, it may require more processing on the part of the PBX than a simple udpflood without any payload that even resembles an IAX payload.
- inviteflood:SIP/SDP协议邀请消息泛洪攻击工具
  >A tool to perform SIP/SDP INVITE message flooding over UDP/IP. It was tested on a Linux Red Hat Fedora Core 4 platform (Pentium IV, 2.5 GHz), but it is expected this tool will successfully build and execute on a variety of Linux distributions.
- iSMTP:SMTP用户枚举、内部欺骗和转发
  >Test for SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.
- isr-evilgrade:构建伪Update服务器工具isr-evilgrade。现在大部分软件都提供更新功能。软件一旦运行，就自动检查对应的Update服务器。如果发现新版本，就会提示用户，并进行下载和安装。而用户往往相信任提示，会选择进行升级。如果更新策略制定不严密，就存在严重漏洞。基于这个社工思路，渗透测试人员可以轻松控制目标主机。Kali Linux提供了一款工具isr-evilgrade利用这个功能。该工具提供DNS和Web服务模块，并提供几十种伪更新服务模块。当实施DNS欺骗后，需要更新的软件就会访问渗透测试人员的电脑，下载预先准备好的攻击载荷作为更新包，并进行运行。从而，渗透测试人员就可以控制目标主机。安全人员还可以使用自带的模版，编写特定的伪更新模块。
  >Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. It comes with pre-made binaries (agents), a working default configuration for fast pentests, and has it’s own WebServer and DNSServer modules. Easy to set up new settings, and has an autoconfiguration when new binary agents are set.
- mitmproxy:mitmproxy是一款支持HTTP(S)的中间人代理工具。不同于Fiddler2，burpsuite等类似功能工具，mitmproxy可在终端下运行。mitmproxy使用Python开发，是辅助web开发&测试，移动端调试，渗透测试的工具。
  >mitmproxy is an SSL-capable man-in-the-middle HTTP proxy. It provides a console interface that allows traffic flows to be inspected and edited on the fly. Also shipped is mitmdump, the command-line version of mitmproxy, with the same functionality but without the frills. Think tcpdump for HTTP.

  >Features:

    - intercept and modify HTTP traffic on the fly
    - save HTTP conversations for later replay and analysis
    - replay both HTTP clients and servers
    - make scripted changes to HTTP traffic using Python
    - SSL interception certs generated on the fly
- ohrwurm:是一个小而简单的RTP模糊器已在少数SIP电话的试验成功
  >ohrwurm is a small and simple RTP fuzzer that has been successfully tested on a small number of SIP phones. Features:

    - reads SIP messages to get information of the RTP port numbers
    - reading SIP can be omitted by providing the RTP port numbers, sothat any RTP traffic can be fuzzed
    - RTCP traffic can be suppressed to avoid that codecs
    - learn about the “noisy line”
    - special care is taken to break RTP handling itself
    - the RTP payload is fuzzed with a constant BER
    - the BER is configurable
    - requires arpspoof from dsniff to do the MITM attack
    - requires both phones to be in a switched LAN (GW operation only works partially)
- protos-sip:对SIP协议实现的安全和鲁棒性做评估测试的套件
  >The purpose of this test-suite is to evaluate implementation level security and robustness of Session Initiation Protocol (SIP) implementations.

- rebind:重新绑定是实现多个A记录DNS重新绑定攻击的工具。虽然这种工具在最初写入到目标家用路由器，它可以用于靶向任何公开的（非RFC1918）的IP地址。重新绑定提供一个外部攻击者访问目标路由器的内部Web界面。该工具适用于实现终端系统模型薄弱的IP协议栈的路由器，有专门配置的防火墙规则，谁是自己的Web服务绑定到路由器的WAN接口。注意，远程管理不需要启用此攻击工作。所有需要的是，所述目标网络冲浪到被控制，或已被破坏，由攻击者网站内的用户
  >Rebind is a tool that implements the multiple A record DNS rebinding attack. Although this tool was originally written to target home routers, it can be used to target any public (non RFC1918) IP address. Rebind provides an external attacker access to a target router’s internal Web interface. This tool works on routers that implement the weak end system model in their IP stack, have specifically configured firewall rules, and who bind their Web service to the router’s WAN interface. Note that remote administration does not need to be enabled for this attack to work. All that is required is that a user inside the target network surf to a Web site that is controlled, or has been compromised, by the attacker.
- responder:LLMNR欺骗工具Responder。LLMNR（Link-Local Multicast Name Resolution，链路本地多播名称解析）协议是一种基于DNS包格式的协议。它可以将主机名解析为IPv4和IPv6的IP地址。这样用户就可以直接使用主机名访问特定的主机和服务，而不用记忆对应的IP地址。该协议被广泛使用在Windows Vista/7/8/10操作系统中。协议的工作机制很简单。例如，计算机A和计算机B同处一个局域网中。当计算机A请求主机B时，先以广播形式发送一个包含请求的主机名的UDP包。主机B收到该UDP包后，以单播形式发送UDP的响应包给主机A。由于整个过程中，都是以UDP方式进行，主机A根本不能确认响应主机B是否为该主机名对应的主机。这就造成欺骗的可能。针对这个漏洞，Kali Linux提供了Responder工具。该工具不仅可以嗅探网络内所有的LLMNR包，获取各个主机的信息，还可以发起欺骗，诱骗发起请求的主机访问错误的主机。为了渗透方便，该工具还可以伪造HTTP/s、SMB、SQL Server、FTP、IMAP、POP3等多项服务，从而采用钓鱼的方式获取服务认证信息，如用户名和密码等。
  >This tool is first an LLMNR and NBT-NS responder, it will answer to *specific* NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answers to File Server Service request, which is for SMB. The concept behind this, is to target our answers, and be stealthier on the network. This also helps to ensure that we don’t break legitimate NBT-NS behavior. You can set the -r option to 1 via command line if you want this tool to answer to the Workstation Service request name suffix.

- rtpbreak:随着rtpbreak可以检测，重建和分析任何RTP会话。它不需要的RTCP分组的存在，并且独立地工程形成用于信令协议（SIP，H.323，SCCP，...）。输入是数据包的顺序，输出是一组可以作为其他工具的输入使用的文件（Wireshark的/ tshark的，袜中，grep / awk的/剪切/ CAT / sed的，...）。它也支持无线（AP_DLT_IEEE802_11）网络。
  >With rtpbreak you can detect, reconstruct and analyze any RTP session. It doesn’t require the presence of RTCP packets and works independently form the used signaling protocol (SIP, H.323, SCCP, …). The input is a sequence of packets, the output is a set of files you can use as input for other tools (wireshark/tshark, sox, grep/awk/cut/ cat/sed, …). It supports also wireless (AP_DLT_IEEE802_11) networks.

    - reconstruct any RTP stream with an unknown or unsupported signaling protocol
    - reconstruct any RTP stream in wireless networks, while doing channel hopping (VoIP activity detector)
    - reconstruct and decode any RTP stream in batch mode (with sox, asterisk, …)
    - reconstruct any already existing RTP stream
    - reorder the packets of any RTP stream for later analysis (with tshark, wireshark, …)
    - build a tiny wireless VoIP tapping system in a single chip Linux unit
    - build a complete VoIP tapping system (rtpbreak would be just the RTP dissector module!)
- rtpinsertsound:一个工具插入音频到一个指定的音频（如RTP）流是在8月创建的。该工具被命名为rtpinsertsound。经测试在Linux红帽的Fedora Core 4平台（奔腾IV，2.5千兆赫），但预计该工具将成功建立和各种Linux发行版执行。
  >A tool to insert audio into a specified audio (i.e. RTP) stream was created in the August – September 2006 timeframe. The tool is named rtpinsertsound. It was tested on a Linux Red Hat Fedora Core 4 platform (Pentium IV, 2.5 GHz), but it is expected this tool will successfully build and execute on a variety of Linux distributions.
- rtpmixsound:一个工具来在实时与在指定的目标音频流中的音频（即，RTP）混合预先记录的音频。
  >A tool to mix pre-recorded audio in real-time with the audio (i.e. RTP) in the specified target audio stream.
- sctpscan:SCTPscan是一个工具来扫描SCTP功能的机器。通常，这些电信面向机器携带SS7和SIGTRAN通过IP。使用SCTPscan，你可以找到切入点电信网络。这对做电信核心网络基础设施pentests时特别有用。 SCTP也用于高性能网络（Internet2的）。
  >SCTPscan is a tool to scan SCTP enabled machines. Typically, these are Telecom oriented machines carrying SS7 and SIGTRAN over IP. Using SCTPscan, you can find entry points to Telecom networks. This is especially useful when doing pentests on Telecom Core Network infrastructures. SCTP is also used in high-performance networks (internet2).
- SIPArmyKnife:SIP瑞士军刀是一个模糊器的搜索跨站脚本，SQL注入，登录注入，格式化字符串，缓冲区溢出等。
  >SIP Army Knife is a fuzzer that searches for cross site scripting, SQL injection, log injection, format strings, buffer overflows, and more.

- SIPp:SIPp是一个测试SIP协议性能的工具软件。这是一个GPL的开放源码软件。它包含了一些基本的SipStone用户代理工作流程（UAC和UAS），并可使用INVITE和B YE建立和释放多个呼叫。它也可以读XML的场景文件，即描述任何性能测试的配置文件。它能动态显示测试运行的统计数据（呼叫速率、信号来回的延迟，以及消息统计）。周期性地把CSV统计数据转储，在多个套接字上的TCP和UDP，利用重新传输管理的多路复用。在场景定义文件中可以使用正规表达式，动态调整呼叫速率。SIPp可以用来测试许多真实的SIP设备，如SIP代理，B2BUAs,SIP媒体服务器，SIP/x网关，SIP PBX，等等，它也可以模仿上千个SIP代理呼叫你的SIP系统。
  >SIPp is a free Open Source test tool / traffic generator for the SIP protocol. It includes a few basic SipStone user agent scenarios (UAC and UAS) and establishes and releases multiple calls with the INVITE and BYE methods. It can also reads custom XML scenario files describing from very simple to complex call flows. It features the dynamic display of statistics about running tests (call rate, round trip delay, and message statistics), periodic CSV statistics dumps, TCP and UDP over multiple sockets or multiplexed with retransmission management and dynamically adjustable call rates.

  >Other advanced features include support of IPv6, TLS, SCTP, SIP authentication, conditional scenarios, UDP retransmissions, error robustness (call timeout, protocol defense), call specific variable, Posix regular expression to extract and re-inject any protocol fields, custom actions (log, system command exec, call stop) on message receive, field injection from external CSV file to emulate live users.

  >SIPp can also send media (RTP) traffic through RTP echo and RTP / pcap replay. Media can be audio or video.

  >While optimized for traffic, stress and performance testing, SIPp can be used to run one single call and exit, providing a passed/failed verdict.

  >Last, but not least, SIPp has a comprehensive documentation available both in HTML and PDF format.

  >SIPp can be used to test various real SIP equipment like SIP proxies, B2BUAs, SIP media servers, SIP/x gateways, SIP PBX, … It is also very useful to emulate thousands of user agents calling your SIP system.
- SIPVicious：SIPVicious本来被设计用来审计SIP系统，但是攻击者用它对VoIP系统进行爆破密码攻击——“大量的错误密码登陆尝试影响了系统的性能。这种行为可能会导致拒绝服务攻击，导致服务对于正常用户也不可用。”
  >SIPVicious suite is a set of tools that can be used to audit SIP based VoIP systems. It currently consists of four tools:. svmap – this is a sip scanner. Lists SIP devices found on an IP range svwar – identifies active extensions on a PBX svcrack – an online password cracker for SIP PBX svreport – manages sessions and exports reports to various formats svcrash – attempts to stop unauthorized svwar and svcrack scans.

- SniffJoke:网络防嗅探工具SniffJoke。在渗透测试中，通过网络嗅探，可以获取网络通信主机的各种信息。为了防止嗅探，Kali Linux提供了专用工具SniffJoke。该工具能够自动对用户的网络数据进行附加处理，如发包延时、修改部分包、注入无效包，使得嗅探工具无法正确读取数据包。但所有这些处理不会影响数据接收方的处理。在使用的时候，用户首先需要使用sniffjoke-autotest检测网络和插件情况，生成有效的配置文件。然后，再使用SniffJoke加载该配置文件，进行数据的防护处理。同时，用户还可以使用sniffjokectl对防护操作进行控制。
  >SniffJoke is an application for Linux that handle transparently your TCP connection, delaying, modifyng and inject fake packets inside your transmission, make them almost impossible to be correctly read by a passive wiretapping technology (IDS or sniffer).

- SSLsplit：SSL中间人攻击工具
  >SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.

  >SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6. For SSL and HTTPS connections, SSLsplit generates and signs forged X509v3 certificates on-the-fly, based on the original server certificate subject DN and subjectAltName extension. SSLsplit fully supports Server Name Indication (SNI) and is able to work with RSA, DSA and ECDSA keys and DHE and ECDHE cipher suites. SSLsplit can also use existing certificates of which the private key is available, instead of generating forged ones. SSLsplit supports NULL-prefix CN certificates and can deny OCSP requests in a generic way. SSLsplit removes HPKP response headers in order to prevent public key pinning.
- sslstrip:SSL剥离工具sslstrip.在日常上网过程中，用户只是在地址栏中输入网站域名，而不添加协议类型，如HTTP和HTTPS。这时，浏览器会默认在域名之前添加http://，然后请求网站。如果网站采用HTTPS协议，就会发送一个302重定向状态码和一个HTTPS的跳转网址，让浏览器重新请求。浏览器收到后，会按照新的网址，进行访问，从而实现数据安全加密。由于存在一次不安全的HTTP的请求，所以整个过程存在安全漏洞。sslstrip工具就是利用这个漏洞，实施攻击。渗透测试人员通过中间人攻击方式，将目标的数据转发到攻击机。sslstrip将跳转网址的HTTPS替换为HTTP，发给目标。目标以HTTP方式重新请求，而sslstrip将HTTP替换为HTTPS，请求对应的网站。这样就形成了，目标和ssltrip之间以HTTP明文方式传输，而sslstrip和服务器以HTTPS加密方式传输。这样，渗透人员就可以轻松获取明文数据了。
  >sslstrip is a tool that transparently hijacks HTTP traffic on a network, watch for HTTPS links and redirects, and then map those links into look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
- THC-IPV6:THC-IPV6是一套完整的工具包，可用来攻击IPV6和ICMP6协议的固有弱点，THC-IPV6包含了易用的库文件，可二次开发。THC-IPV6由先进的主机存活扫描工具，中间人攻击工具，拒绝服务攻击工具构成。
  >A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
- VoIPHopper:VoIP Hopper是一个GPLv3的许可的安全工具，用C写的，也迅速运行VLAN合到语音VLAN上的特定以太网交换机。 VoIP的料斗通过模拟IP电话的行为，在思科，AVAYA，北电网络和阿尔卡特朗讯的环境中做到这一点。这需要为了遍历VLAN内进行未经授权的访问工具的两个重要步骤。首先，发现使用的IP电话正确的12位语音VLAN ID（VVID）是必需的。 VoIP的料斗支持多种协议的发现方法（CDP，DHCP，LLDP-MED，802.1Q ARP）这一重要的第一步。其次，该工具创建的操作系统上的虚拟VoIP的以太网接口。然后，它把包含12位VVID成伪造DHCP请求伪造4个字节的802.1Q VLAN头。一旦收到在VoIP VLAN子网的IP地址，所有后续的以太网帧“标记”与欺骗802.1Q头。的VoIP Hopper是一个VLAN合测试工具，也是一个工具来测试VoIP基础设施的安全性。
  >VoIP Hopper is a GPLv3 licensed security tool, written in C, that rapidly runs a VLAN Hop into the Voice VLAN on specific ethernet switches. VoIP Hopper does this by mimicking the behavior of an IP Phone, in Cisco, Avaya, Nortel, and Alcatel-Lucent environments. This requires two important steps in order for the tool to traverse VLANs for unauthorized access. First, discovery of the correct 12 bit Voice VLAN ID (VVID) used by the IP Phones is required. VoIP Hopper supports multiple protocol discovery methods (CDP, DHCP, LLDP-MED, 802.1q ARP) for this important first step. Second, the tool creates a virtual VoIP ethernet interface on the OS. It then inserts a spoofed 4-byte 802.1q vlan header containing the 12 bit VVID into a spoofed DHCP request. Once it receives an IP address in the VoIP VLAN subnet, all subsequent ethernet frames are “tagged” with the spoofed 802.1q header. VoIP Hopper is a VLAN Hop test tool but also a tool to test VoIP infrastructure security.

- WebScarab:WebScarab是一个用来分析使用HTTP和HTTPS协议的应用程序框架。其原理很简单，WebScarab可以记录它检测到的会话内容（请求和应答），并允许使用者可以通过多种形式来查看记录。WebScarab的设计目的是让使用者可以掌握某种基于HTTP（S）程序的运作过程；可以用它来调试程序中较难处理的bug，也可以帮助安全专家发现潜在的程序漏洞。
  >WebScarab is designed to be a tool for anyone who needs to expose the workings of an HTTP(S) based application, whether to allow the developer to debug otherwise difficult problems, or to allow a security specialist to identify vulnerabilities in the way that the application has been designed or implemented.
- Wifi Honey:这是一个wifi蜜罐脚本，它会建立5个监控模式的接口，其中四个是aps，另一个则是为airdump-ng使用。
  >This script creates five monitor mode interfaces, four are used as APs and the fifth is used for airodump-ng. To make things easier, rather than having five windows all this is done in a screen session which allows you to switch between screens to see what is going on. All sessions are labelled so you know which is which.
- Wireshark:是一个免费开源的网路封包分析软体。网路封包分析软体的功能是截取网路封包，并尽可能显示出最为详细的网路封包资料。在过去，网路封包分析软体是非常昂贵，或是专门属于营利用的软体，Wireshark的出现改变了这一切。在GNU通用公共许可证的保障范围底下，使用者可以以免费的代价取得软体与其程式码，并拥有针对其原始码修改及客制化的权利。Wireshark是目前全世界最广泛的网路封包分析软体之一。
  >Wireshark is the world’s foremost network protocol analyzer. It lets you see what’s happening on your network at a microscopic level. It is the de facto (and often de jure) standard across many industries and educational institutions. Wireshark development thrives thanks to the contributions of networking experts across the globe. It is the continuation of a project that started in 1998.

  >Wireshark has a rich feature set which includes the following:

    - Deep inspection of hundreds of protocols, with more being added all the time
    - Live capture and offline analysis
    - Standard three-pane packet browser
    - Multi-platform: Runs on Windows, Linux, OS X, Solaris, FreeBSD, NetBSD, and many others
    - Captured network data can be browsed via a GUI, or via the TTY-mode TShark utility
    - The most powerful display filters in the industry
    - Rich VoIP analysis
    - Capture files compressed with gzip can be decompressed on the fly
    - Live data can be read from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI, and others (depending on your platform)
    - Coloring rules can be applied to the packet list for quick, intuitive analysis
    - Output can be exported to XML, PostScript®, CSV, or plain text
    - Decryption support for many protocols, including IPsec, ISAKMP, Kerberos, SNMPv3, SSL/TLS, WEP, and WPA/WPA2
    - Read/write many different capture file formats: tcpdump (libpcap), Pcap NG, Catapult DCT2000, Cisco Secure IDS iplog, Microsoft Network Monitor, Network * General Sniffer® (compressed and uncompressed), Sniffer® Pro, and NetXray®, Network Instruments Observer, NetScreen snoop, Novell LANalyzer, RADCOM WAN/LAN Analyzer, Shomiti/Finisar Surveyor, Tektronix K12xx, Visual Networks Visual UpTime, WildPackets EtherPeek/TokenPeek/AiroPeek, and many others
- xspy：X-Windows完整名字是X Windows图形用户接口。它是一种计算机软件系统和网络协议。它为联网计算机提供了一个基础的图形用户界面（GUI）和丰富的输入设备功能。现在所有的操作系统都支持和使用X-Windows。例如，Gnome和KED就是基于X-Windows服务构建的。Kali Linux提供了一个针对X-Windows服务嗅探按键的工具xspy。使用该工具，不仅可以嗅探本地X-Windows服务的用户按键，还可以通过劫持流量的方式，嗅探远程X-Windows服务的用户按键。通过获取的按键信息，渗透测试人员可以了解到目标主机上正在进行的操作，尤其是输入的用户名和密码等关键信息。

  >Sniffs keystrokes on remote or local X-Windows servers.
- Yersinia:Yersinia 是国外的一款专门针对交换机的攻击工具。它现在的最新版本是0.7.1。Yersinia主要是针对交换机上运行的一些网络协议进行的攻击，截至到现在，可以完成的攻击协议见下面的列表，针对这些网络协议，Yersinia攻击的实现方式也是这个软件最大的特点是，他可以根据攻击者的需要和网络协议自身存在的漏洞，通过伪造一些特定的协议信息或协议包来实现对这些网络协议的破坏以达到攻击目的。
  >Yersinia is a framework for performing layer 2 attacks. It is designed to take advantage of some weakeness in different network protocols. It pretends to be a solid framework for analyzing and testing the deployed networks and systems. Attacks for the following network protocols are implemented in this particular release:

    - Spanning Tree Protocol (STP)
    - Cisco Discovery Protocol (CDP)
    - Dynamic Trunking Protocol (DTP)
    - Dynamic Host Configuration Protocol (DHCP)
    - Hot Standby Router Protocol (HSRP)
    - 802.1q
    - 802.1x
    - Inter-Switch Link Protocol (ISL)
    - VLAN Trunking Protocol (VTP)
- zaproxy:是一款用于寻找Web应用程序漏洞的综合性渗透测试工具，同时它也易于使用。ZAP是为拥有丰富经验的安全研究人员设计的，同时，也是渗透测试新手用于开 发和功能测试的理想工具，它也提供一系列工具用于手动寻找安全漏洞。同时该工具也是开源工具，支持多种语言版本。
  >The OWASP Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing as well as being a useful addition to an experienced pen testers toolbox.

## Maintaining Access - 权限维持

- CryptCat:Cryptcat是网络工具Netcat的加密版本。Cryptcat支持TCP、UDP两种网络协议。它可以在两个计算机之间建立指定的连接，并使用特定的密钥对传输数据进行加密。为了提高加密，该工具允许用户在每次连接使用自定义的密钥，从而保证数据的安全性。

  >CryptCat is a simple Unix utility which reads and writes data across network connections, using TCP or UDP protocol while encrypting the data being transmitted. It is designed to be a reliable “back-end” tool that can be used directly or easily driven by other programs and scripts. At the same time, it is a feature-rich network debugging and exploration tool, since it can create almost any kind of connection you would need and has several interesting built-in capabilities.

- Cymothoa:进程注入后门工具Cymothoa。Cymothoa是一款隐秘的后门工具。它通过向目标主机活跃的进程注入恶意代码，从而获取和原进程相同的权限。该工具最大的优点就是不创建新的进程，不容易被发现。由于该工具基于ptrace库，所以适合各种类Unix系统。该工具提供14种攻击载荷，可以实现各种攻击和后门。由于该后门是基于进程注入，所以当原有进程结束，后门也会被关闭。所以，渗透测试必须结合自启动脚本，注入到自启动服务中（如Web服务），才能使Cymothoa的脚本持久有效。
  >Cymothoa is a stealth backdooring tool, that inject backdoor’s shellcode into an existing process. The tool uses the ptrace library (available on nearly all * nix), to manipulate processes and infect them.

- dbd：后门工具dbd。dbd功能类似于Netcat，但提供强大的加密功能，支持AES-CBC-128和HMAC-SHA1加密。该工具可以运行在类Unix和Windows系统中。渗透测试人员首先使用该工具在目标主机建立监听，构建后门。然后，再在攻击机使用该工具连接目标主机，执行Shell命令，从而达到控制目标主机的功能。为了安全，用户可以指定数据传输所使用的密钥，避免数据被窃听。除了作为后门工具，该工具还可以用于点对点的通信功能，如聊天等。
  >dbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. dbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. dbd supports TCP/IP communication only. Source code and binaries are distributed under the GNU General Public License.
- dns2tcp:DNS隧道工具dns2tcp。在很多网络环境中，防火墙会限制出站流量，主机往往只能访问外网主机有限的几个端口，如DNS的53端口。这时，就可以通过DNS请求和响应机制，建立通信隧道。Kali Linux提供dns2tcp就是一款DNS隧道工具。该工具自带DNS解析功能，同时实现服务器端和客户端两部分。用户只要具备一个域名控制权，就可以在公网运行dns2tcp搭建服务器，然后在被限制的主机运行dns2tcp搭建客户端。这样，用户就可以建立的隧道，在客户端中通过SSH、SMTP、POP3、SSH2等工具连接dns2tcp的服务器了。

  >Dns2tcp is a network tool designed to relay TCP connections through DNS traffic. Encapsulation is done on the TCP level, thus no specific driver is needed (i.e: TUN/TAP). Dns2tcp client doesn’t need to be run with specific privileges.

  >Dns2tcp is composed of two parts : a server-side tool and a client-side tool. The server has a list of resources specified in a configuration file. Each resource is a local or remote service listening for TCP connections. The client listen on a predefined TCP port and relays each incoming connection through DNS to the final service.

- http-tunnel:HTTP-Tunnel使你很方便的通过任何防火墙。你可以利用它使用大多数的即时通讯软件（ATM,ICQ,Yahoo等,同时，它支持TCP,SOCKS5，Napster等。

  >Creates a bidirectional virtual data stream tunnelled in HTTP requests. The requests can be sent via a HTTP proxy if so desired. This can be useful for users behind restrictive firewalls. If WWW access is allowed through a HTTP proxy, it’s possible to use httptunnel and, say, telnet or PPP to connect to a computer outside the firewall.

- HTTPTunnel:HTTP隧道工具HTTPTunnel。在很多服务器上，防火墙会限制主机的出站流量，只允许80之类的端口。如果要使用其他端口，只能通过HTTP隧道方式实现。Kali Linux提供一款HTTP隧道工具HTTPTunnel。该工具可以将其他端口的数据以HTTP协议的方式进行发送和接受。该工具包括服务器端和客户端两部分。渗透测试人员在公共网络运行服务端，监听80端口，接受和转发数据。然后，在被限制的主机上运行客户端，监听本地特定的应用端口（如12355），并以HTTP协议方式转发到服务器端的80端口。在被限制的主机上，直接执行其他程序，连接本地的12355端口，就可以规避防火墙的拦截了。
  >HTTPTunnel is a tunneling software that can tunnel network connections through restrictive HTTP proxies over pure HTTP “GET” and “POST” requests. HTTPTunnel consists of two components:

    - The client that resides behind the firewall and accepts network connections on ports that will either be mapped to a specific remote target server/port (portmapping) or will act as a SOCKS (v4 and v5) proxy. The SOCKS authentication source can be a fixed user list, an LDAP or MySQL directory. The client is available as platform-independent Perl script or as Win32 binary.
    - The server that resides on the internet and accepts HTTP requests from the client which will be translated and forwarded to network connections to the remote servers.
  >Two different servers are available:

    - The hosted server, which is basically a PHP script that must be put on a PHP enabled web server. Putting the PHP script on a webserver enables the webserver to act as your HTTP tunnel server.
    - The standalone server, which is available as platform-independent Perl script or as Win32 binary. This server can be used if you have a box on the internet where you can run your own programs (e.g. your box at home). Using the standalone server (as opposed to the hosted server) is recommended as it does not suffer from many restrictions that the webserver may impose on the PHP script, e.g. maximum script runtime (which will limit the duration of your connections), load-balanced server environments, provider policies etc.
  >Configuration of all components is done over a web-based GUI. SOCKS proxy cascading is supported.
- Intersect:Post Exploitation Framework
  >Intersect 2.5 is the second major release in the project line. This release is much different from the previous,in that it gives the user complete control over which features the Intersect script includes and lets them easily import their own features, among other new functionality.

  >This release focuses mainly on the individual modules(features) and the capability to generate your own customized Intersect scripts. By using the Create.py application, the user is guided through a menu-driven process which allows them to select which modules they would like to include, import their own custom modules and ultimately create an Intersect script that is built around the specific modules they choose.
- Nishang:Nishang是基于PowerShell的渗透测试专用工具。集成了框架、脚本和各种payload。这些脚本是由Nishang的作者在真实渗透测试过程中有感而发编写的，具有实战价值。包括了下载和执行、键盘记录、dns、延时命令等脚本。
  >Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and post exploitation during Penetraion Tests. The scripts are written on the basis of requirement by the author during real Penetration Tests.

  >It contains many interesting scripts like Keylogger, DNS TXT Code Execution, HTTP Backdoor, Powerpreter, LSA Secrets and much more.
- polenum: uses the Impacket Library from CORE Security Technologies to extract the password policy information
  >polenum is a python script which uses the Impacket Library from CORE Security Technologies to extract the password policy information from a windows machine. This allows a non-windows (Linux, Mac OSX, BSD etc..) user to query the password policy of a remote windows box without the need to have access to a windows machine.
- PowerSploit:PowerSploit是又一款Post Exploitation相关工具，Post Exploitation是老外渗透测试标准里面的东西，就是获取shell之后干的一些事情。PowerSploit其实就是一些powershell 脚本，包括Inject-Dll(注入dll到指定进程)、Inject-Shellcode（注入shellcode到执行进程）、Encrypt- Script（文本或脚本加密）、Get-GPPPassword（通过groups.xml获取明文密码）、Invoke- ReverseDnsLookup（扫描 DNS PTR记录）

  >PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.
- pwnat:NAT穿透工具pwnat,由于网络环境的限制，大部分计算机都不在公网中，而是位于NAT或者防火墙之后。这时，不同NAT之后的计算机通信就受到限制。为了解决这个问题，Kali Linux提供了一个NAT穿透工具pwnat。该工具首先在公网计算机上建立一个服务端。然后，处于NAT后的其他计算机以客户端模式运行，通过连接服务端，就可以互相访问了。使用该工具，渗透测试人员不需要在NAT路由器上进行设置，就实现了NAT穿透，连接其他NAT后的计算机，形成P2P打洞。
  >pwnat, pronounced “poe-nat”, is a tool that allows any number of clients behind NATs to communicate with a server behind a separate NAT with *no* port forwarding and *no* DMZ setup on any routers in order to directly communicate with each other. The server does not need to know anything about the clients trying to connect.
  >Simply put, this is a proxy server that works behind a NAT, even when the client is behind a NAT, without any 3rd party.
- QuasiBot是一款php编写的webshell管理工具，可以对webshell进行远程批量管理。这个工具超越于普通的webshell管理是因为其还拥有安全扫描、漏洞利用测试等功能，可以帮助渗透测试人员进行高效的测试工作。
- RidEnum:RID枚举工具RidEnum。RID（Relative ID）是域RID主机为域内用户、组或者计算机对象分配的标识。RID和域的SID就构成该对象的SID。RidEnum是一个RID循环攻击工具。它通过空会话，利用枚举RID而获取用户账户。如果指定密码字典文件，该工具还会基于该文件暴力破解获取出来账户的密码。如果同时指定用户名和密码字典，该工具还会尝试用户名和密码的所有组合，找出所有可用的组合。
  >Rid Enum is a RID cycling attack that attempts to enumerate user accounts through null sessions and the SID to RID enum. If you specify a password file, it will automatically attempt to brute force the user accounts when its finished enumerating.
- sbd:sbd是一款小型后门，且具有较强大的加密功能，是居家旅行杀人越货谋财害命之必备佳品（安全测试工具请勿非法使用）
  >sbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32. sbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. sbd supports TCP/IP communication only.
- shellter:这是一款真正意义上的动态Shellcode注入工具。“动态”二字就能够说明注入代码不可能存在于规则严格的地方，例如可执行文件的入口点等。Shellter目前仅支持32位可执行文件，为这个项目已经花费了我近两年多时间。

  >Shellter is a dynamic shellcode injection tool, and the first truly dynamic PE infector ever created. It can be used in order to inject shellcode into native Windows applications (currently 32-bit applications only). The shellcode can be something yours or something generated through a framework, such as Metasploit.
- U3-Pwn:闪迪U3利用工具U3-Pwn,闪迪U3是闪迪公司为Sandisk Cruzer系列U盘提供的一个功能。该模块支持数据加密和CD启动功能。U3-Pwn就是针对U3的一个利用工具。渗透测试人员可以通过该工具篡改CD启动锁使用的ISO，对目标进行渗透。测试人员可以在启动镜像中注入各种反向链接的后门。这样，一旦U盘的CD启动功能被使用，用户就可以通过反向连接控制目标电脑。为了适应不同的场景，U3-Pwn提供了九种反向连接，并且允许修改自启动文件。
  >U3-Pwn is a tool designed to automate injecting executables to Sandisk smart usb devices with default U3 software install. This is performed by removing the original iso file from the device and creating a new iso with autorun features.
- Webshells:针对 ASP, ASPX, CFM, JSP, Perl, and PHP的 Web shell工具集合
  >A collection of webshells for ASP, ASPX, CFM, JSP, Perl, and PHP servers.
- Weevely:Weevely是一款使用python编写的webshell工具，集webshell生成和连接于一身，可以算作是linux下的一款菜刀替代工具（限于php）。Weevely类似于菜刀，一个厚客户端，与一个轻服务端，由客户端生成要执行的代码，传递到服务端执行。与菜刀不同的是Weevely只提供命令行终端，同时自己生成服务端文件。文件的混淆与执行代码的传递更复杂于菜刀。下面将对这两方面进行分析。
  >Weevely is a stealth PHP web shell that simulate telnet-like connection. It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.
- Winexe:从Linux机器上向远程windows执行命令
  >Winexe remotely executes commands on Windows NT/2000/XP/2003 systems from GNU/Linux (and possibly also from other Unices capable of building the Samba 4 software package).

## Forensics Tools - 数字取证

- Binwalk:是一个固件的分析工具，旨在协助研究人员对固件非分析，提取及逆向工程用处。简单易用，完全自动化脚本，并通过自定义签名，提取规则和插件模块，还重要一点的是可以轻松地扩展。
  >Binwalk is a tool for searching a given binary image for embedded files and executable code. Specifically, it is designed for identifying files and code embedded inside of firmware images. Binwalk uses the libmagic library, so it is compatible with magic signatures created for the Unix file utility. Binwalk also includes a custom magic signature file which contains improved signatures for files that are commonly found in firmware images such as compressed/archived files, firmware headers, Linux kernels, bootloaders, filesystems, etc.
- bulk-extractor:是一个计算机取证工具，可以扫描磁盘映像、文件、文件目录，并在不解析文件系统或文件系统结构的情况下提取有用的信息，由于其忽略了文件系统结构，程序在速度和深入程度上都有了很大的提高
  >bulk_extractor is a program that extracts features such as email addresses, credit card numbers, URLs, and other types of information from digital evidence files. It is a useful forensic investigation tool for many tasks such as malware and intrusion investigations, identity investigations and cyber investigations, as well as analyzing imagery and pass-word cracking. The program provides several unusual capabilities including:

    - It finds email addresses, URLs and credit card numbers that other tools miss because it can process compressed data (like ZIP, PDF and GZIP ﬁles) and incomplete or partially corrupted data. It can carve JPEGs, office documents and other kinds of files out of fragments of compressed data. It will detect and carve encrypted RAR files.
    - It builds word lists based on all of the words found within the data, even those in compressed files that are in unallocated space. Those word lists can be useful for password cracking.
    - It is multi-threaded; running bulk_extractor on a computer with twice the number of cores typically makes it complete a run in half the time.
    - It creates histograms showing the most common email addresses, URLs, domains, search terms and other kinds of information on the drive.
  >bulk_extractor operates on disk images, files or a directory of files and extracts useful information without parsing the ﬁle system or ﬁle system structures. The input is split into pages and processed by one or more scanners. The results are stored in feature files that can be easily inspected, parsed, or processed with other automated tools.
  >bulk_extractor also creates histograms of features that it finds. This is useful because features such as email addresses and internet search terms that are more common tend to be important.
  >In addition to the capabilities described above, bulk_extractor also includes:

    - A graphical user interface, Bulk Extractor Viewer, for browsing features stored in feature ﬁles and for launching bulk_extractor scans
    - A small number of python programs for performing additional analysis on feature ﬁles
- Capstone:Capstone是一个轻量级的多平台多架构支持的反汇编框架。支持包括ARM，ARM64，MIPS和x86/x64平台。
  >Capstone is a disassembly framework with the target of becoming the ultimate disasm engine for binary analysis and reversing in the security community. Created by Nguyen Anh Quynh, then developed and maintained by a small community, Capstone offers some unparalleled features:

    - Support multiple hardware architectures: ARM, ARM64 (aka ARMv8), Mips & X86
    - Having clean/simple/lightweight/intuitive architecture-neutral API
    - Provide details on disassembled instruction (called “decomposer” by others)
    - Provide semantics of the disassembled instruction, such as list of implicit registers read & written
    - Implemented in pure C language, with lightweight wrappers for C++, Python, Ruby, OCaml, C#, Java and Go available
    - Native support for Windows & *nix platforms (MacOSX, Linux & *BSD confirmed)
    - Thread-safe by design.
- chntpw:重设Windows 密码 若是忘记了Windows 密码，可使用chntpw工具重设密码
  >This little program provides a way to view information and change user passwords in a Windows NT/2000 user database file. Old passwords need not be known since they are overwritten. In addition it also contains a simple registry editor (same size data writes) and an hex-editor which enables you to fiddle around with bits and bytes in the file as you wish.

  >If you want GNU/Linux bootdisks for offline password recovery you can add this utility to custom image disks or use those provided at the tools homepage.
- Cuckoo:病毒软件分析系统
  >Cuckoo Sandbox is a malware analysis system. You can throw any suspicious file at it and in a matter of seconds Cuckoo will provide you back some detailed results outlining what such file did when executed inside an isolated environment.

  >Cuckoo generates a handful of different raw data which include:

    - Native functions and Windows API calls traces
    - Copies of files created and deleted from the filesystem
    - Dump of the memory of the selected process
    - Full memory dump of the analysis machine
    - Screenshots of the desktop during the execution of the malware analysis
    - Network dump generated by the machine used for the analysis.
- dc3dd:
  >dc3dd is a patched version of GNU dd with added features for computer forensics:. * on the fly hashing (md5, sha-1, sha-256, and sha-512) * possibility to write errors to a file * group errors in the error log * pattern wiping * progress report * possiblity to split output


- ddrescue
  >Like dd, dd_rescue does copy data from one file or block device to another. You can specify file positions (called seek and Skip in dd). There are several differences:

    - dd_rescue does not provide character conversions.
    - The command syntax is different. Call dd_rescue -h.
    - dd_rescue does not abort on errors on the input file, unless you specify a maximum error number. Then dd_rescue will abort when this number is reached.
    - dd_rescue does not truncate the output file, unless asked to.
    - You can tell dd_rescue to start from the end of a file and move backwards.
    - It uses two block sizes, a large (soft) block size and a small (hard) block size. In case of errors, the size falls back to the small one and is promoted again after a while without errors.
- DFF:数字取证框架
  >DFF (Digital Forensics Framework) is a free and Open Source computer forensics software built on top of a dedicated Application Programming Interface (API).

  >It can be used both by professional and non-expert people in order to quickly and easily collect, preserve and reveal digital evidences without compromising systems and data.

    - Preserve digital chain of custody: Software write blocker, cryptographic hash calculation
    - Access to local and remote devices: Disk drives, removable devices, remote file systems
    - Read standard digital forensics file formats: Raw, Encase EWF, AFF 3 file formats
    - Virtual machine disk reconstruction: VmWare (VMDK) compatible
    - Windows and Linux OS forensics: Registry, Mailboxes, NTFS, EXTFS 2/3/4, FAT 12/16/32 file systems
    - Quickly triage and search for (meta-)data: Regular expressions, dictionaries, content search, tags, time-line
    - Recover hidden and deleted artifacts: Deleted files / folders, unallocated spaces, carving
    - Volatile memory forensics: Processes, local files, binary extraction, network connections
- diStorm3:diStorm3是Kali Linux自带的一款轻量级、容易使用的反汇编引擎。它可以反汇编生成16位、32位和64位指令。它支持的指令集包括FPU、MMX、SSE、SSE2、SSE3、SSSE3、SSE4、3DNow@、x86-64、VMX、AMDs、SVM等。虽然diStorm3采用C语言编写，但可以被Python、Ruby、Java快速封装。这样，用户可以使用Python、Ruby等脚本语言编写脚本，并引入diStorm3，从而定制自己的反汇编工具。
  >diStorm is a lightweight, easy-to-use and fast decomposer library. diStorm disassembles instructions in 16, 32 and 64 bit modes. Supported instruction sets: FPU, MMX, SSE, SSE2, SSE3, SSSE3, SSE4, 3DNow! (w/ extensions), new x86-64 instruction sets, VMX, AMD’s SVM and AVX!. The output of new interface of diStorm is a special structure that can describe any x86 instruction, this structure can be later formatted into text for display too. diStorm is written in C, but for rapidly use, diStorm also has wrappers in Python/Ruby/Java and can easily be used in C as well. It is also the fastest disassembler library!. The source code is very clean, readable, portable and platform independent (supports both little and big endianity). diStorm solely depends on the C library, therefore it can be used in embedded or kernel modules. Note that diStorm3 is backward compatible with the interface of diStorm64 (however, make sure you use the newest header files).
- Dumpzilla:Dumpzilla应用程序是用Python开发的3.x和有作为的目的提取物的Firefox，Iceweasel和Seamonkey的浏览器进行分析，所有的法医有趣的信息。由于它的Python 3.x的研究与开发，可能无法在旧版本的Python正常工作，这主要与某些字符。在Unix和Windows 32/64位系统的工作原理。工程在命令行界面，这样的信息转储可能是由于管道用例如grep工具重定向，AWK，剪切，sed的...... Dumpzilla允许可视化下面的章节，搜索定制和提取某些内容。Dumpzilla将显示每个文件的SHA256哈希提取信息，并最后汇总与汇总。这节日期过滤器是不可能的：DOM存储，权限/首选项，插件，扩展，密码/异常，缩略图和会议


  >Dumpzilla application is developed in Python 3.x and has as purpose extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers to be analyzed. Due to its Python 3.x developement, might not work properly in old Python versions, mainly with certain characters. Works under Unix and Windows 32/64 bits systems. Works in command line interface, so information dumps could be redirected by pipes with tools such as grep, awk, cut, sed… Dumpzilla allows to visualize following sections, search customization and extract certain content.

    - Cookies + DOM Storage (HTML 5).
    - User preferences (Domain permissions, Proxy settings…).
    - Downloads.
    - Web forms (Searches, emails, comments..).
    - Historial.
    - Bookmarks.
    - Cache HTML5 Visualization / Extraction (Offline cache).
    - visited sites “thumbnails” Visualization / Extraction .
    - Addons / Extensions and used paths or urls.
    - Browser saved passwords.
    - SSL Certificates added as a exception.
    - Session data (Webs, reference URLs and text used in forms).
    - Visualize live user surfing, Url used in each tab / window and use of forms.
    - Dumpzilla will show SHA256 hash of each file to extract the information and finally a summary with totals.
    - Sections which date filter is not possible: DOM Storage, Permissions / Preferences, Addons, Extensions, Passwords/Exceptions, Thumbnails and Session
- extundelete:ext3和ext4删除文件恢复
  >extundelete is a utility that can recover deleted files from an ext3 or ext4 partition. The ext3 and ext4 file systems are the most common default file systems in Linux distributions like Mint, Mageia, or Ubuntu. extundelete uses information stored in the partition’s journal to attempt to recover a file that has been deleted from the partition. There is no guarantee that any particular file will be able to be undeleted, so always try to have a good backup system in place, or at least put one in place after recovering your files.
- Foremost:文件恢复工具
  >Foremost is a forensic program to recover lost files based on their headers, footers, and internal data structures. Foremost can work on image files, such as those generated by dd, Safeback, Encase, etc, or directly on a drive. The headers and footers can be specified by a configuration file or you can use command line switches to specify built-in file types. These built-in types look at the data structures of a given file format allowing for a more reliable and faster recovery.
- Galleta:检查IE Cookie
  >Galleta is a forensic tool that examines the content of cookie files produced by Microsofts Internet Explorer. It parses the file and outputs a field separated that can be loaded in a spreadsheet.
- Guymager:媒体获取
  >Guymager is a free forensic imager for media acquisition. Its main features are:

    - Easy user interface in different languages
    - Runs under Linux
    - Really fast, due to multi-threaded, pipelined design and multi-threaded data compression
    - Makes full usage of multi-processor machines
    - Generates flat (dd), EWF (E01) and AFF images, supports disk cloning
    - Free of charges, completely open source
- iPhone Backup Analyzer:iPhone备份分析
  >iPhone Backup Analyzer is an utility designed to easily browse through the backup folder of an iPhone (or any other iOS device). Read configuration files, browse archives, lurk into databases, and so on.
- p0f:p0f是一款被动探测工具，能够通过捕获并分析目标主机发出的数据包来对主机上的操作系统进行鉴别，即使是在系统上装有性能良好的防火墙的情况下也没有问题。。目前最新版本为3.09b。同时p0f在网络分析方面功能强大，可以用它来分析NAT、负载均衡、应用代理等。p0f是万能的被动操作系统指纹工具。p0f对于网络攻击非常有用，它利用SYN数据包实现操作系统被动检测技术，能够正确地识别目标系统类型。和其他扫描软件不同，它不向目标系统发送任何的数据，只是被动地接受来自目标系统的数据进行分析。因此，一个很大的优点是：几乎无法被检测到，而且p0f是专门系统识别工具，其指纹数据库非常详尽，更新也比较快，特别适合于安装在网关中。工作原理：当被动地拦截原始的TCP数据包中的数据，如可以访问数据包流经的网段，或数据包发往，或数据包来自你控制的系统；就能收集到很多有用的信息：TCP SYN 和SYN/ACK数据包就能反映TCP的链接参数，并且不同的TCP协议栈在协商这些参数的表现不同。P0f不增加任何直接或间接的网络负载，没有名称搜索、没有秘密探测、没有ARIN查询，什么都没有。某些高手还可以用P0f检测出主机上是否有防火墙存在、是否有NAT、是否存在负载平衡器等等！P0f是继Nmap和Xprobe2之后又一款远程操作系统被动判别工具。
  
  >P0f is a tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications (often as little as a single normal SYN) without interfering in any way. Version 3 is a complete rewrite of the original codebase, incorporating a significant number of improvements to network-level fingerprinting, and introducing the ability to reason about application-level payloads (e.g., HTTP).
  
  >Some of p0f’s capabilities include:
    
    - Highly scalable and extremely fast identification of the operating system and software on both endpoints of a vanilla TCP connection – especially in settings where NMap probes are blocked, too slow, unreliable, or would simply set off alarms.
    - Measurement of system uptime and network hookup, distance (including topology behind NAT or packet filters), user language preferences, and so on.
    - Automated detection of connection sharing / NAT, load balancing, and application-level proxying setups.
    - Detection of clients and servers that forge declarative statements such as X-Mailer or User-Agent.
  >The tool can be operated in the foreground or as a daemon, and offers a simple real-time API for third-party components that wish to obtain additional information about the actors they are talking to.
  
  >Common uses for p0f include reconnaissance during penetration tests; routine network monitoring; detection of unauthorized network interconnects in corporate environments; providing signals for abuse-prevention tools; and miscellanous forensics.
- pdf-parser:PDF扫描
  >This tool will parse a PDF document to identify the fundamental elements used in the analyzed file. It will not render a PDF document.
- pdfid:查找PDF中的关键字
  >This tool is not a PDF parser, but it will scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.

  >The idea is to use this tool first to triage PDF documents, and then analyze the suspicious ones with my pdf-parser.

  >An important design criterium for this program is simplicity. Parsing a PDF document completely requires a very complex program, and hence it is bound to contain many (security) bugs. To avoid the risk of getting exploited, I decided to keep this program very simple (it is even simpler than pdf-parser.py).
- pdgmail:从内存Dump里面恢复gmail信息
  >Python script to gather gmail artifacts from a pd process memory dump. It’ll find what it can out of the memory image including contacts, emails, last acccess times, IP addresses etc.
- peepdf:PDF病毒扫描
  >peepdf is a Python tool to explore PDF files in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that a security researcher could need in a PDF analysis without using 3 or 4 tools to make all the tasks. With peepdf it’s possible to see all the objects in the document showing the suspicious elements, supports the most used filters and encodings, it can parse different versions of a file, object streams and encrypted files. With the installation of PyV8 and Pylibemu it provides Javascript and shellcode analysis wrappers too. Apart of this it is able to create new PDF files, modify existent ones and obfuscate them.
- RegRipper:从注册表抽取信息
  >RegRipper is an open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.

  >RegRipper consists of two basic tools, both of which provide similar capability. The RegRipper GUI allows the analyst to select a hive to parse, an output file for the results, and a profile (list of plugins) to run against the hive. When the analyst launches the tool against the hive, the results go to the file that the analyst designated. If the analyst chooses to parse the System hive, they might also choose to send the results to system.txt. The GUI tool will also create a log of it’s activity in the same directory as the output file, using the same file name but using the .log extension (i.e., if the output is written to system.txt, the log will be written to system.log).

  >RegRipper also includes a command line (CLI) tool called rip. Rip can be pointed against to a hive and can run either a profile (a list of plugins) or an individual plugin against that hive, with the results being sent to STDOUT. Rip can be included in batch files, using the redirection operators to send the output to a file. Rip does not write a log of it’s activity.

  >RegRipper is similar to tools such as Nessus, in that the application itself is simply an engine that runs plugins. The plugins are individual Perl scripts that each perform a specific function. Plugins can locate specific keys, and list all subkeys, as well as values and data, or they can locate specific values. Plugins are extremely valuable in the sense that they can be written to parse data in a manner that is useful to individual analysts.

  >Note: Plugins also serve as a means of retaining corporate knowledge, in that an analyst finds something, creates a plugin, and adds that plugin to a repository that other analysts can access. When the plugin is shared, this has the effect of being a force multiplier, in that all analysts know have access to the knowledge and experience of one analyst. In addition, plugins remain long after analysts leave an organization, allowing for retention of knowledge.
- Volatility:从RAM抽象里面抽取数字信息
  >The Volatility Framework is a completely open collection of tools, implemented in Python under the GNU General Public License, for the extraction of digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer unprecedented visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research.

  >Volatility supports memory dumps from all major 32- and 64-bit Windows versions and service packs including XP, 2003 Server, Vista, Server 2008, Server 2008 R2, and Seven. Whether your memory dump is in raw format, a Microsoft crash dump, hibernation file, or virtual machine snapshot, Volatility is able to work with it. We also now support Linux memory dumps in raw or LiME format and include 35+ plugins for analyzing 32- and 64-bit Linux kernels from 2.6.11 – 3.5.x and distributions such as Debian, Ubuntu, OpenSuSE, Fedora, CentOS, and Mandrake. We support 38 versions of Mac OSX memory dumps from 10.5 to 10.8.3 Mountain Lion, both 32- and 64-bit. Android phones with ARM processors are also supported. Support for Windows 8, 8.1, Server 2012, 2012 R2, and OSX 10.9 (Mavericks) is either already in svn or just around the corner
- Xplico: Xplico的目标是提取互联网流量并捕获应用数据中包含的信息。 举个例子，Xplico可以在pcap文件中提取邮件内容(通过POP，IMAP，SMTP协议)，所有的HTTP内容，每个VoIP的访问(SIP)，FTP，TFTP等等，但是Xplico不是一个网络协议分析工具。Xplico的目标是提取互联网流量并捕获应用数据中包含的信息。举个例子，Xplico可以在pcap文件中提取邮件内容(通过POP，IMAP，SMTP协议)，所有的HTTP内容，每个VoIP的访问(SIP)，FTP，TFTP等等，但是Xplico不是一个网络协议分析工具。Xplico是一个开源的网络取证分析工具(NFAT)。功能包括：

  - 协议支持：HTTP, SIP, IMAP, POP, SMTP, TCP, UDP, IPv6, … ;
  - 针对每个应用协议都有端口独立协议识别(PIPI);
  - 多线程;
  - 支持使用SQLite数据库或者Mysql数据库甚至文件进行数据和信息的输出;
  - 每个数据都由Xplico重新组装，并被关联到能够唯一识别流量的XML文件。Pcap包含重组数据;
  - 支持实时查询细节(能否真的实现取决于流量大小、协议类型和计算机性能-TAM, CPU, HD访问时间等...);
  - 为任何数据包和soft ACK认证使用ACK确认进行TCP重组;
  - 反向DNS查找是查找包含在输入文件(pcap)中的DNS数据包，而不是查找来自外部的DNS服务器;
  - 对输入数据的大小或者输入文件的数量没有限制(仅仅限制了HD的大小);
  - 支持IPv4和IPv6;
  - 模块化。每个Xplico部件都是一个模块。输入接口、协议解码器、输出接口都实现了模块化;
  - 轻松创建任何调度，使用最合适、最有效的方法实现数据分离。

## Reporting Tools - 报告工具集

- CaseFile:收集及报告信息关系可视化关系分析工具,CaseFile是Maltego的姊妹工具，功能非常类似于Maltego。CaseFile主要针对数据进行离线分析，缺少Maltego的数据采集功能。它可以导入各类数据，包括Maltego导出的数据。用户可以为信息添加连接线、标签和注释，标记数据的关系。CaseFile以图形化的方式展现数据，方便分析人员找出隐含的数据关系。
  >CaseFile is the little brother to Maltego. It targets a unique market of ‘offline’ analysts whose primary sources of information are not gained from the open-source intelligence side or can be programmatically queried. We see these people as investigators and analysts who are working ‘on the ground’, getting intelligence from other people in the team and building up an information map of their investigation.

  >CaseFile gives you the ability to quickly add, link and analyze data having the same graphing flexibility and performance as Maltego without the use of transforms. CaseFile is roughly a third of the price of Maltego.

  >What does CaseFile do?

  >CaseFile is a visual intelligence application that can be used to determine the relationships and real world links between hundreds of different types of information.
  >It gives you the ability to quickly view second, third and n-th order relationships and find links otherwise undiscoverable with other types of intelligence tools.
  >CaseFile comes bundled with many different types of entities that are commonly used in investigations allowing you to act quickly and efficiently. CaseFile also has the ability to add custom entity types allowing you to extend the product to your own data sets.

  >What can CaseFile do for me?

  >CaseFile can be used for the information gathering, analytics and intelligence phases of almost all types of investigates, from IT Security, Law enforcement and any data driven work. It will save you time and will allow you to work more accurately and smarter.
  >CaseFile has the ability to visualise datasets stored in CSV, XLS and XLSX spreadsheet formats.
  >We are not marketing people. Sorry.
  >CaseFile aids you in your thinking process by visually demonstrating interconnected links between searched items.
  >If access to “hidden” information determines your success, CaseFile can help you discover it.
- cherrytree:个支持无限层级分类的笔记软件，Python编写，支持富文本编辑和代码高亮，支持Linux和Windows平台。
  >A hierarchical note taking application, featuring rich text and syntax highlighting, storing data in a single xml or sqlite file.
- CutyCapt:CutyCapt实现网页截图
  >CutyCapt is a small cross-platform command-line utility to capture WebKit’s rendering of a web page into a variety of vector and bitmap formats, including SVG, PDF, PS, PNG, JPEG, TIFF, GIF, and BMP.
- dos2unix:dos2unix命令用来将DOS格式的文本文件转换成UNIX格式的（DOS/MAC to UNIX text file format converter）。DOS下的文本文件是以\r\n作为断行标志的，表示成十六进制就是0D 0A。而Unix下的文本文件是以\n作为断行标志的，表示成十六进制就是 0A。DOS格式的文本文件在Linux底下，用较低版本的vi打开时行尾会显示^M，而且很多命令都无法很好的处理这种格式的文件，如果是个shell脚本，。而Unix格式的文本文件在Windows下用Notepad打开时会拼在一起显示。因此产生了两种格式文件相互转换的需求，对应的将UNIX格式文本文件转成成DOS格式的是unix2dos命令。
  >This package contains utilities dos2unix, unix2dos, mac2unix, unix2mac to convert the line endings of text files between UNIX (LF), DOS (CRLF) and Mac (CR) formats. Text files under Windows and DOS typically have two ASCII characters at the end of each line: CR (carriage return) followed by LF (line feed). Older Macs used just CR, while UNIX uses just LF. While most modern editors can read all these formats, there may still be a need to convert files between them. This is the classic utility developed in 1989.
- Dradis:渗透测试报告是任何安全评估活动中的关键可交付成果。渗透测试中，最终可交付成果是一份报告，展示了所提供的服务，使用的方法，发现的结果和建议。许多渗透测试人员发现报告的制作是一个无聊的过程，因为它需要大量的时间和精力。在本文中，我们将讨论使用Kali Linux工具来简化制作报告的任务。这些工具可用于存储结果，做报告时的快速参考，与你的团队分享你的数据等。我们将学习如何使用这些工具上传BurpSuite、nmap、Nikto、OWASP Zap等的扫描结果。
  >Dradis is an open source framework to enable effective information sharing, specially during security assessments.
  >Dradis is a self-contained web application that provides a centralized repository of information to keep track of what has been done so far, and what is still ahead.
- KeepNote:跨平台好用的笔记管理软件
  >KeepNote is a note taking application that works on Windows, Linux, and MacOS X. With KeepNote, you can store your class notes, TODO lists, research notes, journal entries, paper outlines, etc in a simple notebook hierarchy with rich-text formatting, images, and more. Using full-text search, you can retrieve any note for later reference.

  >KeepNote is designed to be cross-platform (implemented in Python and PyGTK) and stores your notes in simple and easy to manipulate file formats (HTML and XML). Archiving and transferring your notes is as easy as zipping or copying a folder.
- MagicTree: MagicTree是Gremwell开发的一个JAVA程序，支持主动收集数据和生成报告的工具。他通过树形结构节点来管理数据，这种分层存储的方法对管理主机和网络数据特别有效。其分析数据的能力特别强大。 MagicTree可以基于选择的优先级创建可操作的报告，而这个报告是完全可定制的，甚至可以将数据导入到openoffice中。 
  >MagicTree is a penetration tester productivity tool. It is designed to allow easy and straightforward data consolidation, querying, external command execution and (yeah!) report generation. In case you wonder, “Tree” is because all the data is stored in a tree structure, and “Magic” is because it is designed to magically do the most cumbersome and boring part of penetration testing – data management and reporting.
- Metagoofil: “MetaGooFil”也是信息收集过程中可以利用的优秀软件，由开发The Harvester的团队编写而成，可用来提取元数据（metadata）。元数据经常被定义为是关于数据的数据。在我们创建文档时，例如Word或PowerPoint演示文稿，额外的数据也会被同时创建，并储存在文档里。这些数据通常是对该文档的描述信息，包括文件名、文件大小、作者或创建者的用户名，以及文件保存的位置或路径。这个过程全自动进行，无需用户输入或干预。攻击者若能读取到这些信息，就能对目标公司的用户名、系统名、文件共享以及其他诸多好东西有独特的见解。MetaGooFil就是这么一个工具，能在互联网上搜索属于目标的文档。一旦有所发现，MetaGooFil就会把这些文档下载下来，并尝试提取有用的元数据。
  >Metagoofil is an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) belonging to a target company.

  >Metagoofil will perform a search in Google to identify and download the documents to local disk and then will extract the metadata with different libraries like Hachoir, PdfMiner? and others. With the results it will generate a report with usernames, software versions and servers or machine names that will help Penetration testers in the information gathering phase.
- Nipper-ng:尼珀-NG是下一代nippper的，并且将永远是自由和开放源码。该软件将被用来制造许多关于不同设备类型的安全配置，例如路由器，防火墙，以及网络基础设施的开关观测。这是钳0.11.10版本的GNUv3 GPL代码叉子。
  >Nipper-ng is the next generation of nippper, and will always remain free and open source. This software will be used to make observations about the security configurations of many different device types such as routers, firewalls, and switches of a network infrastructure. This is a fork from nipper 0.11.10 release of the GNUv3 GPL code.
- pipal:Pipal是一款密码分析工具，功能主要是进行密码合集文件分析。说白了，就是对拿到的裤子中的密码进行特征分析，找出其中的“各种最”，你没看错，这个东西功能就是这么简单。。不过，工具的分析的速度还是很快的，同时也会从各个方面给出相应的分析结果。工具是作者为了满足自己和朋友的需要写的，现在被挂在了Git上面，这里我搬运过来，希望能为大家带来帮助。
  >All this tool does is to give you the stats and the information to help you analyse the passwords. The real work is done by you in interpreting the results.
- RDPY:微软远程桌面协议的Python实现。
  >RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).

## Hardware Hacking - 硬件破解

- android-sdk:Android SDK包
  >The Android SDK provides you the API libraries and developer tools necessary to build, test, and debug apps for Android.
- apktool:APK反编译
  >It is a tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications; it makes possible to debug smali code step by step. Also it makes working with app easier because of project-like files structure and automation of some repetitive tasks like building apk, etc.

  >It is NOT intended for piracy and other non-legal uses. It could be used for localizing, adding some features or support for custom platforms and other GOOD purposes. Just try to be fair with authors of an app, that you use and probably like.

  >Features:

    - decoding resources to nearly original form (including resources.arsc, XMLs and 9.png files) and rebuilding them
    - smali debugging: SmaliDebugging
    - helping with some repetitive tasks
- Arduino
  >Arduino is an open-source electronics prototyping platform based on flexible, easy-to-use hardware and software. It’s intended for artists, designers, hobbyists, and anyone interested in creating interactive objects or environments.

- dex2jar:Dex转jar
  >dex2jar contains following compments:

    - dex-reader is designed to read the Dalvik Executable (.dex/.odex) format. It has a light weight API similar with ASM.
    - dex-translator is designed to do the convert job. It reads the dex instruction to dex-ir format, after some optimize, convert to ASM format.
    - dex-ir used by dex-translator, is designed to represent the dex instruction
    - dex-tools tools to work with .class files. here are examples: Modify a apk, DeObfuscate a jar
    - d2j-smali [To be published] disassemble dex to smali files and assemble dex from smali files. different implementation to smali/baksmali, same syntax, but we support escape in type desc “Lcom/dex2jar\t\u1234;”
    - dex-writer [To be published] write dex same way as dex-reader.
- Sakis3G：Sakis3G是一个可微调的shell脚本应该是工作外的开箱即用的建立与调制解调器或运营商的任意组合的3G连接。它自动地设置USB或蓝牙™调制解调器，甚至可以检测操作者的设置。当别的失败，您应该尝试一下。
  >Sakis3G is a tweaked shell script which is supposed to work out-of-the-box for establishing a 3G connection with any combination of modem or operator. It automagically setups your USB or Bluetooth™ modem, and may even detect operator settings. You should try it when anything else fails.

- smali:Android应用再打包工具
  >smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android’s Java VM implementation. The syntax is loosely based on Jasmin’s/dedexer’s syntax, and supports the full functionality of the dex format (annotations, debug info, line info, etc.)

## Social-Engineer - 社工工具集

- Backdoor Factory:后门
- BeEF:浏览器漏洞利用
- Ghost Phisher:服务伪造
- Maltego Teeth:漏洞分析界面
- MSFPC:MSF攻击载荷生成器
- SET:
  >攻击向量:
    - SPEAR-PHISHING:交叉式鱼叉
    - Applet
    - 浏览器全屏
    - Metasploit
    - 凭证收集
    - Tab点击
    - URL作伪点击
    - 复合多维度Web攻击向量
    - U盘\DVD病毒
    - USB做成键盘
    - SMS欺骗
    - 无线攻击
    - 二维码攻击

- U3-Pwn:U盘

## Stress Testing - 压力测试

- DHCPig:DHCP拒绝服务攻击工具DHCPig。DHCP服务负责网络的IP分配服务。通过攻击该服务，可以导致网络内主机获取不到IP，而无法正常使用网络。Kali Linux提供一款专用工具DHCPig。该工具借助Scapy大量伪造Mac地址，而从DHCP服务器那里骗取IP，消耗掉所有的IP资源。这样，新加入网络的计算机将无法获取IP地址，导致联网失败。同时，该工具还可以借助ARP协议攻击局域网现有主机，造成这些主机离线，使其无法获取新的IP地址。
  >DHCPig initiates an advanced DHCP exhaustion attack. It will consume all IPs on the LAN, stop new users from obtaining IPs, release any IPs in use, then for good measure send gratuitous ARP and knock all windows hosts offline. It requires scapy >=2.1 library and admin privileges to execute. No configuration necessary, just pass the interface as a parameter. It has been tested on multiple Linux distributions and multiple DHCP servers (ISC,Windows 2k3/2k8).
- FunkLoad:FunkLoad是一个功能和负载的Web测试仪，主要的用于Web项目（进行回归测试），性能测试，负载测试（如音量的测试或寿命测试），压力测试的 功能。它也可以用来编写Web代理脚本的任何Web重复性的任务。 FunkLoad 是一个网站项目的功能、性能测试工具。
  >FunkLoad is a functional and load web tester, written in Python, whose main use cases are:

    - Functional testing of web projects, and thus regression testing as well.
    - Performance testing: by loading the web application and monitoring your servers it helps you to pinpoint bottlenecks, giving a detailed report of performance measurement.
    - Load testing tool to expose bugs that do not surface in cursory testing, like volume testing or longevity testing.
    - Stress testing tool to overwhelm the web application resources and test the application recoverability.
    - Writing web agents by scripting any web repetitive task.
- iaxflood:内部电话机协议Inter-Asterisk_eXchange的泛洪攻击工具
    - A UDP Inter-Asterisk_eXchange (i.e. IAX) packet was captured from an IAX channel between two Asterisk IP PBX’s. The content of that packet is the source of the payload for the attack embodied by this tool. While the IAX protocol header might not match the Asterisk PBX you’ll attack with this tool, it may require more processing on the part of the PBX than a simple udpflood without any payload that even resembles an IAX payload.
- Inundator:IDS/IPS测试工具
  >Inundator is a multi-threaded, queue-driven, anonymous intrusion detection false positives generator with support for multiple targets.
- inviteflood:SIP/SDP协议邀请消息泛洪攻击工具
  >A tool to perform SIP/SDP INVITE message flooding over UDP/IP. It was tested on a Linux Red Hat Fedora Core 4 platform (Pentium IV, 2.5 GHz), but it is expected this tool will successfully build and execute on a variety of Linux distributions.
- ipv6-toolkit:IPv6安全评估和故障排除工具
  >The SI6 Networks’ IPv6 toolkit is a set of IPv6 security assessment and trouble-shooting tools. It can be leveraged to perform security assessments of IPv6 networks, assess the resiliency of IPv6 devices by performing real-world attacks against them, and to trouble-shoot IPv6 networking problems. The tools comprising the toolkit range from packet-crafting tools to send arbitrary Neighbor Discovery packets to the most comprehensive IPv6 network scanning tool out there (our scan6 tool).

  >Included tools:

    - addr6: An IPv6 address analysis and manipulation tool
    - flow6: A tool to perform a security asseessment of the IPv6 Flow Label
    - frag6: A tool to perform IPv6 fragmentation-based attacks and to perform a security assessment of a number of fragmentation-related aspects
    - icmp6: A tool to perform attacks based on ICMPv6 error messages
    - jumbo6: A tool to assess potential flaws in the handling of IPv6 Jumbograms
    - na6: A tool to send arbitrary Neighbor Advertisement messages
    - ni6: A tool to send arbitrary ICMPv6 Node Information messages, and assess possible flaws in the processing of such packets
    - ns6: A tool to send arbitrary Neighbor Solicitation message
    - ra6: A tool to send arbitrary Router Advertisement messages
    - rd6: A tool to send arbitrary ICMPv6 Redirect messages
    - rs6: A tool to send arbitrary Router Solicitation messages
    - scan6: An IPv6 address scanning tool
    - tcp6: A tool to send arbitrary TCP segments and perform a variety of TCP- based attacks.
- mdk3:MDK3 是一款集成在 BackTrack上的无线DOS攻击测试工具，能够发起Beacon Flood 、Authentication DoS、Deauthentication/Disassociation Amok等模式的攻击，另外它还具有针对隐藏 ESSID的暴力探测模式、802.1X 渗透测试、WIDS 干扰等功能，对于后面几种功能模式，希望大家能一起探讨和参与测试，把测试的过程和经验分享出来。
  >MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses. IMPORTANT: It is your responsibility to make sure you have permission from the network owner before running MDK against it.
- Reaver:Wifi WPA/WPA2协议下密码破解工具
  >Reaver implements a brute force attack against Wifi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases, as described in http://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf.

  >Reaver has been designed to be a robust and practical attack against WPS, and has been tested against a wide variety of access points and WPS implementations.

  >On average Reaver will recover the target AP’s plain text WPA/WPA2 passphrase in 4-10 hours, depending on the AP. In practice, it will generally take half this time to guess the correct WPS pin and recover the passphrase
- rtpflood:对SIP SERVER进行rtp flood攻击的小程序
  >A command line tool used to flood any device that is processing RTP.
- SlowHTTPTest:Slowhttptest是一个依赖于实际HTTP协议的Slow HTTP DoS 攻击压力测试工具，它实现了最常见的应用层DOS攻击，如慢速HTTP POST，发起大量的TCP链接，以及Apache的Range头的拒绝服务攻击等。
  >SlowHTTPTest is a highly configurable tool that simulates some Application Layer Denial of Service attacks. It works on majority of Linux platforms, OSX and Cygwin – a Unix-like environment and command-line interface for Microsoft Windows.

  >It implements most common low-bandwidth Application Layer DoS attacks, such as slowloris, Slow HTTP POST, Slow Read attack (based on TCP persist timer exploit) by draining concurrent connections pool, as well as Apache Range Header attack by causing very significant memory and CPU usage on the server.

  >Slowloris and Slow HTTP POST DoS attacks rely on the fact that the HTTP protocol, by design, requires requests to be completely received by the server before they are processed. If an HTTP request is not complete, or if the transfer rate is very low, the server keeps its resources busy waiting for the rest of the data. If the server keeps too many resources busy, this creates a denial of service. This tool is sending partial HTTP requests, trying to get denial of service from target HTTP server.
- t50:一款优秀的网站压力测试工具
 >Multi-protocol packet injector tool for *nix systems, actually supporting 15 protocols. Features: – Flooding – CIDR support – TCP, UDP, ICMP, IGMPv2, IGMPv3, EGP, DCCP, RSVP, RIPv1, RIPv2, GRE, ESP, AH, EIGRP and OSPF support. – TCP Options. – High performance. – Can hit about 1.000.000 packets per second.
- Termineter:日前老外Spencer McIntyre发布了一款针对智能电表（smart meters）hack的工具，旨在评估智能电表的安全性。关于智能电表（smart meters）在国内貌似用的不多，不过在国外就比较流行了。自2009年起，美国就积极推行智能电网，并且电力企业强迫客户使用智能电表。这些新设备通过无线电波传送电力使用的数据，它可以记录住家电力使用的详细记录，包括冰箱、空调、电视机等等。
  >Termineter is a framework written in python to provide a platform for the security testing of smart meters. It implements the C12.18 and C12.19 protocols for communication. Currently supported are Meters using C12.19 with 7-bit character sets. Termineter communicates with Smart Meters via a connection using an ANSI type-2 optical probe with a serial interface.
- THC-IPV6:THC-IPV6是一套完整的工具包，可用来攻击IPV6和ICMP6协议的固有弱点，THC-IPV6包含了易用的库文件，可二次开发。THC-IPV6由先进的主机存活扫描工具，中间人攻击工具，拒绝服务攻击工具构成。
  >A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
- THC-SSL-DOS: 德国黑客组织“The Hacker’s Choice”发布了工具THC SSL DOS，与传统DDoS工具不同的是，只需要一台执行单一攻击的电脑就能迅速消耗服务器资源，造成服务器拒绝服务。 这个攻击方式的本质是消耗服务器的CPU资源，在协商加密算法的时候服务器CPU的开销是客户端的 15 倍左右。而Renegotiating机制让攻击者可以在一个TCP连接中不停的快速重新协商，如果建立多个连接则服务端的压力更为可怕，而且这种攻击建立的连接数很少导致难以被察觉。从漏洞形成原因中，我们看到 Renegotiating机制可以让攻击者在一个TCP连接中不停的快速重新协商，由此可知，我们可以通过禁用Renegotiating机制来实现延缓此类拒绝攻击。但是其只能相对延缓，仍然不能彻底解决问题。如果通过客户端模拟多次请求连接，则依然会出现服务器端消耗资源过大的情况。由于德国黑客组织提供的工具THC SSL DOS目前只针对Renegotiations  Enabled的情况.
  >THC-SSL-DOS is a tool to verify the performance of SSL. Establishing a secure SSL connection requires 15x more processing power on the server than on the client. THC-SSL-DOS exploits this asymmetric property by overloading the server and knocking it off the Internet. This problem affects all SSL implementations today. The vendors are aware of this problem since 2003 and the topic has been widely discussed. This attack further exploits the SSL secure Renegotiation feature to trigger thousands of renegotiations via single TCP connection.

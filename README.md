
# ToolBox
安全研究渗透工具箱

## 目录
- [Android](#android)
- [Binary](#binary)
- [CTF](#ctf)
- [CVE](#cve)
- [IOT](#IOT)
- [Pentest](#pentest)
- [Web](#web)
- [工作机工具](#Work-Computer)

## Android
安卓相关工具箱
* ACF
* AndBug - Android Debugging Library
* android_run_root_shell - android root 脚本
* android-backup-extractor - manifest backup属性问题测试工具
* android-forensics - Open source Android Forensics app and framework
* android-simg2img - Tool to convert Android sparse images to raw images
* AndroidEmbedIT - apk之间合并工具
* androwarn - Yet another static code analyzer for malicious Android applications
* ApkDetecter - Android Apk查壳工具
* APKiD - Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
* ApkScan-APKID - apk查壳
* baksmali - back smali
* busybox - busybox
* dex2jar - dex to jar
* drozer - android渗透测试工具
* Dwarf - Full featured multi arch/os debugger built on top of PyQt5 and frida
* ESFileExplorerOpenVuln - es cve
* Jadx - jadx
* jd-gui - jd gui
* LabServer - Server component of the mobile labs
* manifestbin2xml - mainfest binary to xml
* MobSF - mobsf
* odexMutildexRev - multi dex reverse
* pyAndriller - Forensic data extraction and decoding tool for Android devices取证工具
* qark - 类似mobsf，渗透工具
* root-poc - root
* smail - to smali
* su-Binary - su二进制编译文件
* tcpdump-Binary - tcpdump二进制编译文件
* TraceReader - android 调用栈
* unpacker - 安卓脱壳脚本集

## Binary
### 1. AFL (American Fuzzy Lop)
**核心功能**：AFL是一款**覆盖引导的模糊测试工具**，通过遗传算法自动发现程序中的潜在漏洞。

- **工作原理**：
  - 通过**编译时插桩**在目标程序中插入监控代码，实时跟踪执行路径
  - 使用**forkserver**机制提升测试吞吐量，避免重复初始化
  - 采用**边覆盖率**评估测试用例有效性，优先保留能触发新路径的输入
  - **变异策略**包括字节翻转、位翻转、算术扰动、字节块插删等

- **使用流程**：
  1. 编译AFL工具链：`make && sudo make install`
  2. 使用afl-gcc编译目标程序：`afl-gcc -g -o target target.c`
  3. 准备初始测试用例：创建包含有效输入的`seeds`目录
  4. 执行模糊测试：`afl-fuzz -i seeds -o findings -- ./target @@`
  5. 分析结果：检查`findings/crashes`和`hangs`目录

- **优势**：
  - **无需复杂配置**，可直接处理复杂程序
  - **性能消耗低**，支持多核并行测试（通过-M和-S参数）
  - **智能变异策略**，能快速探索复杂状态机

- **典型应用场景**：
  - 文件格式解析器漏洞挖掘（如PNG、JPEG处理）
  - 配置文件解析器安全测试
  - 网络协议实现的安全验证

### 2. angr
**核心功能**：angr是一款**开源二进制分析平台**，结合静态和动态符号分析技术，提供多种工具解决复杂分析任务。

- **技术架构**：
  - **CLE**：可执行文件和库加载器
  - **archinfo**：描述各种架构的库
  - **PyVEX**：二进制代码提升器VEX的Python包装器
  - **Claripy**：数据后端，抽象静态和符号域之间的差异
  - **angr**：程序分析套件本身

- **核心能力**：
  - **符号执行**：使用符号变量代替具体值，探索程序所有可能路径
  - **约束求解**：通过Claripy求解器分析路径约束条件
  - **控制流图恢复**：重建程序执行逻辑
  - **多架构支持**：x86、ARM、MIPS等多种处理器架构

- **使用示例**：
  ```python
  import angr
  # 加载二进制文件
  project = angr.Project('/bin/bash')
  # 创建初始状态
  initial_state = project.factory.entry_state()
  # 创建仿真管理器
  simgr = project.factory.simulation_manager(initial_state)
  # 执行符号执行
  simgr.explore(find=lambda s: b"target_string" in s.posix.dumps(1))
  ```

- **应用场景**：
  - **CTF挑战**：自动寻找满足特定条件的输入
  - **漏洞挖掘**：发现缓冲区溢出、逻辑错误等安全问题
  - **恶意代码分析**：理解恶意软件的行为逻辑
  - **协议逆向**：分析网络通信协议结构

### 3. detect-secrets
**核心功能**：**企业级敏感信息检测工具**，用于检测和防止代码中的秘密信息（如密码、API密钥）<refer>user</refer>。

- **工作原理**：
  - 扫描代码库中的文件
  - 使用正则表达式和机器学习模型识别敏感信息模式
  - 提供预提交钩子防止敏感信息提交到版本控制系统

- **典型应用场景**：
  - CI/CD流水线中的安全检查
  - 代码仓库的敏感信息审计
  - 开发团队的安全培训

### 4. difuze
**核心功能**：专为**Linux内核驱动**设计的模糊测试框架<refer>user</refer>。

- **工作原理**：
  - 通过系统调用接口向内核驱动发送变异输入
  - 监控内核崩溃和异常行为
  - 使用覆盖率引导策略优化测试用例生成

- **应用场景**：
  - Linux设备驱动安全测试
  - 内核模块漏洞挖掘
  - 系统稳定性验证

### 5. darkvuf
**核心功能**：**基于虚拟化的无代理二进制分析系统**，通过硬件虚拟化技术实现隐蔽分析。

- **技术特点**：
  - 依赖Intel CPU的VT-x和EPT功能
  - 支持Windows 7-10（64位）和多种Linux内核
  - 无需在目标环境中安装任何软件
  - 提供图形化界面和自动化沙箱功能

- **应用场景**：
  - 高隐蔽性恶意软件分析
  - 固件检测与监控
  - 操作系统内核行为审计

### 6. dyninst
**核心功能**：**二进制插桩、分析和修改工具集**<refer>user</refer>。

- **技术特点**：
  - 支持动态二进制插桩
  - 提供API用于修改二进制代码
  - 支持多种架构（x86、ARM、MIPS等）

- **应用场景**：
  - 性能分析和优化
  - 安全漏洞修复
  - 二进制代码逆向工程

### 7. edb-debugger
**核心功能**：**Linux平台图形化调试器**<refer>user</refer>。

- **主要特点**：
  - 提供直观的图形界面
  - 支持断点设置、变量查看和程序执行控制
  - 集成反汇编功能
  - 支持多种Linux发行版

- **应用场景**：
  - Linux应用程序调试
  - 逆向工程分析
  - 安全漏洞验证

### 8. ghidra
**核心功能**：**开源反汇编和反编译工具**，由NSA开发，功能类似IDA Pro<refer>user</refer>。

- **主要特点**：
  - 支持多种处理器架构（x86、ARM、MIPS等）
  - 提供反汇编和反编译功能
  - 支持脚本扩展
  - 跨平台（Windows、Linux、macOS）

- **应用场景**：
  - 恶意软件分析
  - 漏洞挖掘
  - 逆向工程
  - 固件分析

### 9. IDA Pro
**核心功能**：**行业标准的交互式反汇编器和调试器**。

- **主要特点**：
  - 支持数十种CPU指令集（x86、ARM、MIPS、PowerPC等）
  - 提供反汇编和反编译功能（通过Hex-Rays Decompiler插件）
  - 支持交互式分析和手动调整反汇编结果
  - 内置FLIRT签名库可识别软件框架

- **版本信息**：
  - 最新版本为IDA 9.0（截至2024年）
  - 支持Windows、Linux、macOS平台

- **应用场景**：
  - 恶意代码分析
  - 漏洞研究
  - 商用现货验证
  - 隐私保护分析

### 10. libc-database
**核心功能**：**libc版本识别数据库**<refer>user</refer>。

- **主要用途**：
  - 识别不同Linux发行版中使用的libc版本
  - 提供libc函数地址和偏移量
  - 支持漏洞利用开发

### 11. LibcSearcher
**核心功能**：**识别特定libc版本的工具**<refer>user</refer>。

- **工作原理**：
  - 通过分析程序使用的libc函数和符号
  - 匹配已知libc版本的特征
  - 提供版本识别和函数地址查询

- **应用场景**：
  - CTF竞赛中的pwn题目
  - 漏洞利用开发
  - 逆向工程分析

### 12. pintools
**核心功能**：**Intel Pin框架的插桩工具**<refer>user</refer>。

- **主要特点**：
  - 支持动态二进制插桩
  - 提供丰富的分析API
  - 支持多种架构（x86、x64、ARM等）

- **应用场景**：
  - 性能分析
  - 安全漏洞检测
  - 代码覆盖率分析

### 13. pwndbg
**核心功能**：**GDB增强插件**，专为安全研究和逆向工程设计<refer>user</refer>。

- **主要特点**：
  - 提供丰富的调试命令
  - 支持内存分析、寄存器查看
  - 集成漏洞利用开发功能
  - 支持多种架构

- **应用场景**：
  - CTF竞赛中的pwn题目
  - 漏洞利用开发
  - 二进制分析

### 14. PyAna
**核心功能**：**Windows shellcode分析工具**<refer>user</refer>。

- **主要特点**：
  - 分析Windows shellcode行为
  - 提供执行路径跟踪
  - 支持恶意代码检测

- **应用场景**：
  - 恶意软件分析
  - 漏洞利用检测
  - 安全研究

### 15. syzkaller
**核心功能**：**无监督覆盖引导内核模糊测试器**<refer>user</refer>。

- **工作原理**：
  - 自动生成系统调用序列
  - 通过覆盖率引导优化测试用例
  - 监控内核崩溃和异常行为

- **应用场景**：
  - Linux内核漏洞挖掘
  - 系统稳定性测试
  - 驱动程序安全验证

### 16. trinity
**核心功能**：**Linux系统调用模糊测试工具**<refer>user</refer>。

- **工作原理**：
  - 向系统调用传递半智能参数
  - 监控系统响应和异常行为
  - 使用变异策略优化测试用例

- **应用场景**：
  - Linux系统调用接口测试
  - 内核稳定性验证
  - 安全漏洞挖掘

### 17. uncompyle2
**核心功能**：**Python字节码反编译器**<refer>user</refer>。

- **主要特点**：
  - 将Python字节码转换为可读的Python源代码
  - 支持多种Python版本
  - 提供反编译结果的语法高亮

- **应用场景**：
  - Python程序逆向工程
  - 恶意Python脚本分析
  - 代码恢复

### 18. usb-device-fuzzing
**核心功能**：**USB设备模糊测试框架**<refer>user</refer>。

- **工作原理**：
  - 生成异常的USB协议数据
  - 向USB设备发送变异输入
  - 监控设备响应和异常行为

- **应用场景**：
  - USB设备安全测试
  - 驱动程序漏洞挖掘
  - 协议实现验证

### 19. wifuzz
**核心功能**：**WiFi协议模糊测试工具**<refer>user</refer>。

- **工作原理**：
  - 生成异常的WiFi数据包
  - 向WiFi设备发送变异输入
  - 监控设备响应和异常行为

- **应用场景**：
  - WiFi设备安全测试
  - 协议栈漏洞挖掘
  - 无线网络安全评估

### 20. pwntools
**核心功能**：**Pwn安全研究的Python库**<refer>user</refer>。

- **主要特点**：
  - 提供丰富的漏洞利用开发功能
  - 支持多种架构和协议
  - 集成调试和交互功能

- **应用场景**：
  - CTF竞赛中的pwn题目
  - 漏洞利用开发
  - 安全研究

### 21. ollvm
**核心功能**：**代码混淆工具**，用于保护软件免受逆向工程<refer>user</refer>。

- **主要特点**：
  - 提供多种混淆策略（控制流扁平化、虚假控制流等）
  - 支持LLVM编译器
  - 可定制混淆强度

- **应用场景**：
  - 软件保护
  - 防止逆向分析
  - 版权保护

这些工具在安全研究、漏洞挖掘和逆向工程领域各司其职，通常需要**组合使用**以达到最佳效果。例如，AFL可用于发现程序漏洞，angr用于深入分析漏洞成因，而IDA或ghidra则用于逆向工程分析。在实际应用中，选择合适的工具组合是提高安全研究效率的关键。

## CTF
CTF学习，CTF脚本分享
* how2heap - heap漏洞利用学习

## CVE
日常遇到的CVE，poc，exp以供后续遇到使用
* dedecms
* dnsmasq
* ffmpeg-avi-m3u-xbin
* goahead
* iis
* imageaMagick
* joomula
* memcached
* zabbix_web

## IOT
IOT，硬件相关工具和软件
* bladeRF - bladeRF SDR
* blue_hydra - a Bluetooth device discovery service built on top of the bluez library
* buildroot - generate embedded Linux systems through cross-compilation构建IOT设备文件系统
* canbus - canbus协议工具
* firmwalker -Script for searching the extracted firmware file system for goodies查找固件中的敏感信息
* firmware-analysis-toolkit Toolkit to emulate firmware and analyse it for security vulnerabilities几个工具的集合
* firmware-mod-kit -  extract and rebuild linux based firmware images 类似QEMU集合脚本
* gnuradio - SDR
* gr-gsm - gsm嗅探工具
* imx_usb_loader - USB & UART loader for i.MX5/6/7/8 series
* kalibrate-bladeRF - kalibrate bladeRF支持，获取频率
* openlte - LTE
* pybombs - like apt for SDR
* SubversiveBTS - GSM/CDBA BTS
* ubertooth - bluetooth工具


## Pentest
渗透测试工具（recon，scanning，enumerate,system hack，Post pentest）
* Recon - 信息收集
  * SocialEngineer
    * blackeye - 钓鱼工具
  * SubDomain
    * Sublist3r - 从公共API上进行sub domain枚举
  * OSINT
    * gOSINT - golang osint 工具
    * GitHack - githack
    * github - github hack
    * GitMiner - gitminer命令行git数据泄漏
    * pagodo - google hack
    * pwnedOrNot - OSINT Tool to Find Passwords for Compromised Email Addresses
    * spiderfoot - spiderfoot
    * Zeus-Scanner - Advanced reconnaissance utility
* Scanning - 扫描工具
  * Dirs
    * dirsearch - dirsearch
  * Allscanner - 数据库和其他服务的弱端口的弱口令检测以及未授权访问的集成检测工具
  * AutoSploit - Automated Mass Exploiter
  * WpsScan - wordpress scanner
  * bscan - an asynchronous target enumeration tool
  * chomp-scan - reconnaissance scan
  * CMSmap - CMS指纹识别
  * dzscan - web vul scan
  * Sitadel - web application scanner
  * SRCHunter - 联合扫描
  * ssh-auditor - ssh弱密码扫描
  * ssrf - ssrf工具
  * w8scan - w8scan
  * w9scan - w9scan
  * WPSeku - Wordpress Security Scanner
* Enumerate
  * BruteForce - bruteforce 工具
  * ds_store_exp - ds_store泄漏工具
  * dvcs-ripper - dvcs各种工具
  * medusa - medusa爆破工具
  * patator - Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
  * SvnHack - svn hack
* System hack
  * MysqlUDF - mysql getshell
* Post Pentest
  * Empire - Empire is a PowerShell and Python post-exploitation agent.
  * koadic - Koadic C3 COM Command & Control - JScript RAT
  * n00bRAT - Remote Administration Toolkit (or Trojan) for POSiX (Linux/Unix) system working as a Web Service
  * metasploit - msf

## Web
web相关工具，web漏洞，扫描工具，代码审计工具等
* Burpsuite - Burpsuite
* fiddler - fiddler
* sqlmap - sqlmap
* HQLmap - hql注入工具
* NoSQLMap - nosql注入
* tplmap - 模板注入
* owtf - owtf
* JavaID - java id
* AntSwords - webshell 工具
* cobra - cobra代码审计
* POC-T - poc漏洞利用工具（大部分为web）
* WebShell - webshell
* Jenkins - Jenkins
* Jetleak-Testing-Script - Jetleak
* jetty - jetty
* jexboss - jexboss
* mitmproxy - 代理工具
* Photon - photonjs
* phpenv - php环境配置切换工具
* phpRandom - php伪随机hack
* javaRandomHack - java伪随机hack
* phpvulhunter - php vul hack
* Postman - postman
* pyshell - pyshell
* Struts2 - s2
* WeBaCoo - Web Backdoor Cookie Script-Kit
* web-log-parser - web log parser

## Others
其他工具
* Bashfuscator - bash混淆工具
* dirscraper - 提取文件中疑似的link
* LinkFinder - 提取文件中疑似的link
* dnscat2  - dns隧道工具
* impacket - 各种协议客户端，服务器
* DNSTunnel - dns隧道
* gost - gost 代理工具
* RSB-Framework - reverse shell backdoor
* Sn1per - Automated pentest framework for offensive security experts
* tcpproxy - tcpproxy
* tidos-framework - The Offensive Manual Web Application Penetration Testing Framework
* trojanizer - Trojanize your payload - WinRAR (SFX) automatization - under Linux distros

## 工具部署
github上存在的项目默认会从github上拉取，部分非github工具将保存在该备份仓库中。



## Work-Computer
```
.
├── App
│   ├── 360vulscanner_offical.apk
│   ├── AFLogical-OSE_1.5.2
│   ├── AXMLPrinter2.S.jar
│   ├── AndroidKiller
│   ├── ApkIDE_v3.3
│   ├── ApkScan-PKID查壳工具
│   ├── ApkToolBox_v1.6.4
│   ├── Arm汇编转换器
│   ├── Brida_0.2.jar
│   ├── Bytecode-Viewer-2.10.16.jar
│   ├── ClassyShark.jar
│   ├── DexFixer
│   ├── Drony_102.apk
│   ├── FUPK
│   ├── GDA3.85
│   ├── GDA3.85.zip
│   ├── GDAE3.85.pro.exe
│   ├── JadxFindJNI-v0.1
│   ├── JadxFindJNI-v0.1.zip
│   ├── Mobile-Security-Framework-MobSF
│   ├── ReflectMaster_3.0.apk
│   ├── SO Helper 1.2
│   ├── SocketMontior_two
│   ├── TraceReader
│   ├── abe-all.jar
│   ├── burp
│   ├── classyshark.properties
│   ├── classyshark_recents.properties
│   ├── classyshark_ui.properties
│   ├── dumpdex
│   ├── dwarf
│   ├── frida
│   ├── intentfuzzer
│   ├── jadx-0.9.0
│   ├── jadx-gui-1.0.0-with-jre-windows
│   ├── jadx-gui-1.0.0-with-jre-windows.zip
│   ├── jadx-gui-1.0.0.exe
│   ├── jadx_v0.7.0
│   ├── jd-gui-1.4.0.jar
│   ├── jeb-2.2.7.201608151620_crack_qtfreet00
│   ├── jeb-pro-floating-3.28.0.202012242154-JIANGRUOFU-115629772726217854
│   ├── jeb-pro-floating-3.28.0.202012242154-JIANGRUOFU-115629772726217854.zip
│   ├── jni_helper-master
│   ├── jni_helper-master.zip
│   ├── libso修复
│   ├── luyten-0.5.3.jar
│   ├── qtrace
│   ├── recaf-2.17.4-J8-jar-with-dependencies.jar
│   ├── scrcpy-win64
│   ├── simplify-1.2.0.jar
│   ├── smalivm-1.2.0.jar
│   ├── socket-moitor
│   ├── tcpdump
│   ├── 刷机root
│   ├── 取证
│   ├── 安卓逆向工具箱v1.1.zip
│   ├── 应用app tools
│   └── 易开发
├── Binary
│   ├── 010Editor
│   ├── BDGandCrabDecryptTool.exe
│   ├── Cutter-v1.7.4-x64.Windows
│   ├── Cutter-v1.7.4-x64.Windows.zip
│   ├── Export
│   ├── IDA
│   ├── IDA 7.0
│   ├── IDA 7.0 - backup
│   ├── IDA.7z
│   ├── IDAGolangHelper-master
│   ├── IDAGolangHelper-master.zip
│   ├── IDA_Pro_v6.8_and_Hex-Rays_Decompiler_(ARM,x64,x86)_Green.rar
│   ├── IDA插件
│   ├── OllyICE.1.10
│   ├── OllyICE.1.10.zip
│   ├── Rekall_1.7.2.p1_Hurricane.Ridge_x64.exe
│   ├── TscanCode-master
│   ├── TscanCode-master.zip
│   ├── WinDbg10.0.18362.1
│   ├── WinDbg10.0.18362.1.zip
│   ├── ZipCenOp.jar
│   ├── bindiff5.msi
│   ├── deflat.py
│   ├── desquirr-20070130-bin-ida_v5_0
│   ├── desquirr-20070130-bin-ida_v5_0.zip
│   ├── ffdec_11.2.0
│   ├── ffdec_11.2.0.zip
│   ├── ghidra_9.0.4_PUBLIC_20190516
│   ├── ghidra_9.0.4_PUBLIC_20190516.zip
│   ├── ghidra_9.0_PUBLIC_20190228
│   ├── ghidra_9.0_PUBLIC_20190228.zip
│   ├── ida6.8
│   ├── ida脚本
│   ├── imunityDbg
│   ├── kanal23
│   ├── kanal23.zip
│   ├── lazagne.exe
│   ├── patoolkit-master.zip
│   ├── pin-3.7-97619-g0d0c92f4f-msvc-windows
│   ├── pin-3.7-97619-g0d0c92f4f-msvc-windows.zip
│   ├── processhacker-2.39-bin
│   ├── processhacker-2.39-bin.zip
│   ├── processhacker-2.39-setup.exe
│   ├── pwintools
│   ├── radare2
│   ├── radare2_installer-msvc_32-3.3.0.exe
│   ├── rekall-1.7.2rc1.tar.gz
│   ├── resource_hacker
│   ├── resource_hacker.zip
│   ├── retdec-v3.1-windows-64b
│   ├── static-binary
│   ├── swfretools_140
│   ├── swfretools_140.zip
│   ├── winchecksec
│   ├── winchecksec.zip
│   ├── x64dbg
│   ├── x64dbg.7z
│   ├── yaraScan
│   └── 加壳
├── C#Net
│   ├── AntiBox
│   ├── ConfuserEx-GUI
│   ├── ConfuserEx-GUI.zip
│   ├── DNGuard_Trial.exe
│   ├── ILSpy_binaries_4.0.1.4530
│   ├── ILSpy_binaries_4.0.1.4530.zip
│   ├── LoGiC.NET
│   ├── LoGiC.NET.zip
│   ├── SharpCradle-master
│   ├── de4dot-net35
│   ├── de4dot-netcoreapp2.1
│   ├── de4dot-netcoreapp2.1.zip
│   ├── dnSpy-net472
│   ├── dnSpy-net472.zip
│   ├── obfuscar-master
│   ├── obfuscar-master.zip
│   ├── obfuscar.globaltool.2.2.30
│   ├── obfuscar.globaltool.2.2.30.nupkg
│   └── obfuscar_softradar-com.zip
├── CTF
│   ├── CTFCrackTools3.1.6
│   ├── CTFCrackTools3.1.6.zip
│   ├── RSA
│   ├── Tools
│   └── stegosuite-0.7-win_amd64.jar
├── Cloud Native
│   ├── cdk_linux_amd64
│   ├── clair-scanner_linux_amd64
│   ├── grype_0.11.0_darwin_amd64.zip
│   ├── grype_0.11.0_linux_amd64.tar.gz
│   ├── kubectl
│   ├── kubectl.exe
│   └── trivy_0.16.0_Linux-64bit.tar.gz
├── Forensic
│   ├── DumpIt.exe
│   ├── DumpIt.zip
│   ├── README.txt
│   ├── sample
│   ├── volatility_2.6_win64_standalone
│   └── volatility_2.6_win64_standalone.zip
├── HardWare
│   ├── EAGLE
│   ├── ESP8266_Deauther_v2.0.5_DSTIKE_Deauther_OLED_v1-v1.5.bin
│   ├── Frontline15.11-18.11.17745.20002_signed.exe
│   ├── Mac终端健康检测工具.zip
│   ├── PortMon
│   ├── PortMon.zip
│   ├── TempestSDR-master
│   ├── arduino-1.8.5-windows
│   ├── bluetooth
│   ├── cebal
│   ├── mt76x7-uploader-master
│   ├── no.nordicsemi.android.mcp_108_apps.evozi.com.apk
│   ├── openocd-0.10.0
│   ├── openocd-0.10.0.zip
│   ├── rufus-3.5.exe
│   ├── rufus_files
│   ├── sdrsharp-bladerf-master
│   ├── sdrsharp-x86
│   ├── uvision5_79273
│   ├── uvision5_79273.rar
│   ├── wifi
│   └── zadig_v2.0.1.160
├── IOS
│   ├── altinstaller
│   ├── mac_os_security.zip
│   └── unc0ver_Release_6.1.1.ipa
├── IOT下渗透工具
│   └── arm架构
├── Linux
│   ├── LinEnum.sh
│   ├── Pythonshell
│   ├── Pythonshell-master-0ce5ab7531dea5a31034881be0268e4d29edf07b.zip
│   ├── Pythonshell.zip
│   ├── chrome-linux.zip
│   ├── godoh-master.zip
│   ├── gost-linux-amd64-2.11.1
│   ├── linpeas.sh
│   ├── linux-exploit-suggester-master
│   ├── linuxprivchecker.py
│   ├── memShell_for_linux_v0.2.zip
│   ├── memfd-examples-master.zip
│   ├── merlinServer-Linux-x64.7z
│   ├── mongotui
│   ├── pspy64
│   ├── run-embedded-elf-from-memory-master
│   ├── run-embedded-elf-from-memory-master.zip
│   ├── sliver
│   ├── unix-privesc-check
│   ├── unix-privesc-check-1.4
│   ├── unix-privesc-check-1.4.tar.gz
│   └── x-crack_linux_amd64
├── System
│   ├── Windows-Exploit-Suggester
│   ├── ossec-hids-master
│   ├── ossec-hids-master.zip
│   └── wesng
├── Web
│   ├── AntSword
│   ├── AntiHoneypot-Chrome-simple-master
│   ├── AntiHoneypot-Chrome-simple-master.zip
│   ├── BaiLu-SED-Tool-v1.1
│   ├── Behinder_v3.0_Beta_9_fixed
│   ├── Behinder_v3.0_Beta_9_fixed.zip
│   ├── BlueKeep
│   ├── Browser
│   ├── BurpSuite-2.0
│   ├── BurpSuite-2.0.rar
│   ├── CVE-2020-11651-poc
│   ├── Cobalt Strike 4.2
│   ├── Cobalt Strike 4.2.zip
│   ├── CobaltStrikeParser-master (1)
│   ├── CodeReview
│   ├── CyberChef_v9.11.12
│   ├── CyberChef_v9.11.12.zip
│   ├── Decrypt_Weblogic_Password-master
│   ├── Decrypt_Weblogic_Password-master.zip
│   ├── Demo
│   ├── Demo.zip
│   ├── DependencyCheck
│   ├── DruidCrack-master
│   ├── DruidCrack-master.zip
│   ├── FofaCollect.jar
│   ├── Hessian-Deserialize-RCE-master
│   ├── Hessian-Deserialize-RCE-master.zip
│   ├── HessianTest
│   ├── HessianTest.war
│   ├── InstallerFileTakeOver-main
│   ├── JBoss-exp-master.zip
│   ├── JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
│   ├── Java.V1.7
│   ├── Java.V1.7.zip
│   ├── JavaDeserializationScanner05.jar
│   ├── Java_xmlhack-master.zip
│   ├── JavauditGUI
│   ├── Ladon.lnx
│   ├── MemoryAnalyzer-1.11.0.20201202-win32.win32.x86_64.zip
│   ├── Multiple.Database.Utilization.Tools.-.v2.0.7
│   ├── Multiple.Database.Utilization.Tools.-.v2.0.7.zip
│   ├── NimScan.exe
│   ├── Pythonshell-master-0ce5ab7531dea5a31034881be0268e4d29edf07b
│   ├── Pythonshell.zip
│   ├── RedisModules-ExecuteCommand-for-Windows-main
│   ├── RedisModules-ExecuteCommand-for-Windows-main.zip
│   ├── SeayDzend
│   ├── SeayDzend.rar
│   ├── SerializationDumper-v1.13 (1).jar
│   ├── SerializationDumper-v1.13.jar
│   ├── ShiroExploit.V2.51.7z
│   ├── SiteCopy
│   ├── SiteCopy-master
│   ├── SiteCopy-master.zip
│   ├── SoapUI-x64-5.6.0.exe
│   ├── SpringBootExploit-1.1-SNAPSHOT-all.jar
│   ├── Struts2-Scan-master
│   ├── TideFinger
│   ├── TrackRay-master
│   ├── TrackRay-master.zip
│   ├── TxPortMap_windows_x64.exe
│   ├── VanDyke_SecureCRT_decrypt.py
│   ├── WebLogicPasswordDecryptor
│   ├── WebShell
│   ├── WeblogicScan
│   ├── amass_windows_amd64
│   ├── amass_windows_amd64.zip
│   ├── apereo-cas-attack-1.0-SNAPSHOT-all.jar
│   ├── attackRMI.jar
│   ├── awesome-jenkins-rce-2019-master.zip
│   ├── chromehead
│   ├── cobaltstrike4.1
│   ├── cobaltstrike4.1.7z
│   ├── cobaltstrike4.1.zip
│   ├── cobaltstrike4.4_csagent
│   ├── cobaltstrike4.4_csagent.zip
│   ├── codeql
│   ├── codeql.zip
│   ├── druid-1.1.10.jar
│   ├── electron-ssr-0.2.6.exe
│   ├── eyeballer
│   ├── fofaviewer_1.0.8_
│   ├── fofaviewer_1.0.8_.zip
│   ├── frp_0.38.0_linux_amd64.tar.gz
│   ├── frp_0.38.0_windows_amd64
│   ├── frp_0.38.0_windows_amd64.zip
│   ├── frpc-63047
│   ├── frpc-63047.zip
│   ├── gobuster-all
│   ├── gobuster-all.7z
│   ├── goby-win-x64-1.8.202
│   ├── goby-win-x64-1.8.202.zip
│   ├── godoh-master
│   ├── godzilla4
│   ├── gost-master
│   ├── gost_2.8.1_windows_amd64
│   ├── gost_2.8.1_windows_amd64.zip
│   ├── headless-chrome-crawler
│   ├── hessiancpp-hessiancpp-1.1.0.tar
│   ├── httpx_1.0.9_windows_amd64.zip
│   ├── idea_exploit
│   ├── ja3-master
│   ├── jumpserver_rce
│   ├── jumpserverrce.py
│   ├── jumpserverrce2.py
│   ├── jweevely-master
│   ├── jweevely-master.zip
│   ├── ksubdomain
│   ├── mRemoteNG-Decrypt-master
│   ├── mRemoteNG-Decrypt-master.zip
│   ├── mRemoteNG_password_decrypt-master
│   ├── mRemoteNG_password_decrypt-master.zip
│   ├── maltergo
│   ├── mitmproxy-4.0.4-windows-installer.exe
│   ├── naabu_2.0.5_linux_amd64
│   ├── ncDecode-main
│   ├── ncDecode-main.zip
│   ├── npc.exe
│   ├── nuclei-templates-8.4.0
│   ├── nuclei-templates-8.4.0.zip
│   ├── nuclei_2.4.0_windows_amd64
│   ├── nuclei_2.4.0_windows_amd64.zip
│   ├── passive-scan-client.0.1.jar
│   ├── poc_CVE-2018-1002105-master
│   ├── pocassist_windows_amd64
│   ├── ql-1.21.1
│   ├── ql-1.21.1.zip
│   ├── rce-over-spark
│   ├── redis-rogue-server-master (1).zip
│   ├── reverse-shell-generator-main
│   ├── reverse-shell-generator-main.zip
│   ├── rmiallexp-0.0.1-SNAPSHOT-all.jar
│   ├── rmiserver.jar
│   ├── robo3t-1.4.3-windows-x86_64-48f7dfde.exe
│   ├── shiro attack工具个人修改版
│   ├── shiro_attack_2.2
│   ├── shiro_attack_2.2.zip
│   ├── sliver-server_linux.zip
│   ├── sliver-server_windows
│   ├── sonarqube-developer-7.9.1
│   ├── sonarqube-developer-7.9.1.zip
│   ├── spiderfoot
│   ├── spiderfoot-2.12
│   ├── spiderfoot-master
│   ├── spiderfoot-master.zip
│   ├── springboot heapdump解析
│   ├── struts-scan-master
│   ├── subfinder
│   ├── trackray-3.1.0.bin
│   ├── trackray-3.1.0.bin.zip
│   ├── typecho_install_rce_getshell_via_searchEngine
│   ├── weakpass-main
│   ├── weblogicScanner
│   ├── weblogic_exploit-1.0-SNAPSHOT-all.jar
│   ├── xray_windows_amd64.exe
│   ├── xray_windows_amd64.exe.zip
│   ├── yak_windows_amd64.exe
│   ├── ysoserial-mangguogan-master.zip
│   ├── ysoserial-master-30099844c6-1.jar
│   ├── ysoserial-master-8eb5cbfbf6-1.jar
│   ├── ysoserial.net
│   ├── zeek-4.0.4.tar.gz
│   ├── zip解压缩漏洞
│   ├── 代理工具
│   ├── 反序列化
│   ├── 哥斯拉
│   ├── 子域名
│   ├── 安恒struts2工具
│   ├── 安恒struts2工具.zip
│   ├── 超级弱口令检查工具
│   └── 超级弱口令检查工具.zip
├── Windows
│   ├── ADExplorer.exe
│   ├── API Monitor v2.0 Alpha-r13 (32+64) 汉化版
│   ├── API Monitor v2.0 Alpha-r13 (32+64) 汉化版.rar
│   ├── API Monitor v2.0 Alpha-r13 (32+64) 汉化版.zip
│   ├── APIMonitor_12112.zip
│   ├── AdFind
│   ├── AdFind.zip
│   ├── Advanced_Port_Scanner_2.5.3680.exe
│   ├── ArmaGeddon_2.0
│   ├── ArmaGeddon_2.0.rar
│   ├── AspDotNetWrapper
│   ├── AttackSurfaceAnalyzerASA_win_2.3.268
│   ├── AttackSurfaceAnalyzerASA_win_2.3.268.zip
│   ├── Bat To Exe Converter 3.0.11.0
│   ├── Bat To Exe Converter 3.0.11.0.zip
│   ├── BeaconEye
│   ├── BloodHound-win32-x64
│   ├── BloodHound-win32-x64.zip
│   ├── BruteSharkCli.exe
│   ├── CVE-2019-0841-BYPASS-master
│   ├── CVE-2019-1388-master
│   ├── CobaltStrikeParser-master (2).zip
│   ├── CobaltStrikeScan
│   ├── CobaltStrikeScan.zip
│   ├── Doge-AliveCheck.exe
│   ├── Doge-Assembly-main.zip
│   ├── DuckMemoryScan-master
│   ├── Dump-Clear-Password-after-KB2871997-installed
│   ├── FredUnYP1.02
│   ├── FredUnYP1.02.zip
│   ├── Fscan
│   ├── HiveJack.exe
│   ├── IMG-Stego.exe
│   ├── ImHex_1.6.1_Windows.zip
│   ├── InstallerFileTakeOver-main.zip
│   ├── Invoke-TheHash-master
│   ├── Invoke-TheHash-master.zip
│   ├── JuicyPotato-main
│   ├── Ladon.exe
│   ├── Ladon64.exe
│   ├── Ladon7.0
│   ├── MDAT-v1.2.jar
│   ├── MailSniper
│   ├── Mailget-master
│   ├── Mailget-master.zip
│   ├── PE Lab.zip
│   ├── PEiD 0.95
│   ├── PEiD 0.95.zip
│   ├── PEx64-Injector
│   ├── PSTools
│   ├── PSTools.zip
│   ├── Pentesting_Active_directory.xmind
│   ├── PopCalc-master
│   ├── PowerSploit-3.0.0
│   ├── PowerSploit-3.0.0.zip
│   ├── PrintNightmare-main
│   ├── PrintNightmare-main.zip
│   ├── Procdump
│   ├── Procdump.zip
│   ├── ProcessExplorer
│   ├── ProcessExplorer.zip
│   ├── ProcessMonitor
│   ├── QuarksPwDump_v0.2b
│   ├── QuarksPwDump_v0.2b.zip
│   ├── Rubeus-1.6.4
│   ├── Rubeus-1.6.4.zip
│   ├── RunasCs
│   ├── RunasCs.zip
│   ├── ShadowSteal.exe
│   ├── SocksOverRDP-master.zip
│   ├── SocksOverRDP-x64.zip
│   ├── SocksOverRDP-x86
│   ├── SocksOverRDP-x86.zip
│   ├── SpoolSample-master.zip
│   ├── Sunflower_get_Password-main.zip
│   ├── Talon_2.0.1_windows_amd64.exe
│   ├── Win-PS2EXE-master
│   ├── Win-PS2EXE-master.zip
│   ├── WinPwnage-master
│   ├── WinPwnage-master.zip
│   ├── WindowsExploits
│   ├── adduser
│   ├── bat2exe.exe
│   ├── blackwater.exe
│   ├── bmc-tools-master
│   ├── bmc-tools-master.zip
│   ├── boxcutter.exe
│   ├── capa-v1.6.1-windows
│   ├── capa-v1.6.1-windows.zip
│   ├── depends22_x64
│   ├── depends22_x64.zip
│   ├── dfirtriage-master
│   ├── exchange
│   ├── getSystem-master
│   ├── getSystem-master.zip
│   ├── getsystem-offline-master.zip
│   ├── go-mimikatz-master
│   ├── how-does-Xmanager-encrypt-password-master
│   ├── how-does-Xmanager-encrypt-password-master.zip
│   ├── impacket-examples-windows
│   ├── impacket.zip
│   ├── kekeo
│   ├── kekeo - 副本.7z
│   ├── kekeo.7z
│   ├── kerbrute_windows_amd64.exe
│   ├── krbrelayx-master.zip
│   ├── mimikatz_trunk
│   ├── mimikatz_trunk.7z
│   ├── nbtscan.exe
│   ├── netcat_windows_amd64.exe
│   ├── nishang-0.7.6
│   ├── nishang-0.7.6.zip
│   ├── officeparser-master
│   ├── officeparser-master.zip
│   ├── powercat
│   ├── printnightmare打印机漏洞组合
│   ├── px.exe
│   ├── rustdesk-1.1.2.exe
│   ├── windows-kernel-exploits-master
│   ├── windows-kernel-exploits-master.zip
│   ├── x86_64-pc-windows-msvc-simple-http-server.exe
│   ├── yara-v4.0.5-1554-win64
│   ├── 免杀
│   ├── 共享文件扫描
│   ├── 提权
│   └── 标记克隆
├── bin
│   ├── axmlprinter.bat
│   ├── cssh.bat
│   ├── jadx.bat.lnk
│   ├── jdb.exe.lnk
│   └── wget.bat
├── cfr.bat
├── 一把梭
│   ├── C2
│   ├── linux下常用工具
│   ├── springboot
│   ├── userpassall
│   ├── userpassall.7z
│   ├── web
│   ├── windows下常用工具
│   ├── 代理
│   ├── 加壳压缩
│   ├── 扫描工具
│   └── 漏洞利用武器库
├── 字典
│   ├── Blasting_dictionary
│   ├── Probable-Wordlists
│   ├── RW_Password
│   ├── SecLists-master
│   ├── SecLists-master.zip
│   ├── SuperWordlist-master
│   ├── SuperWordlist-master.zip
│   ├── Web-Fuzzing-Box-main
│   ├── Web-Fuzzing-Box-main.zip
│   ├── bottleneckOsmosis
│   ├── fuzzDicts
│   ├── fuzz_dict
│   ├── tool
│   ├── 外部字典
│   ├── 子域名字典.txt
│   ├── 密码字典.txt
│   ├── 用户名字典.txt
│   └── 目录爆破字典.txt
└── 钓鱼邮件
    ├── Extract-Macro-master
    ├── IMG-Stego.exe
    ├── excel钓鱼+PASO+远程模板
    ├── html.html
    ├── note.txt
    ├── word钓鱼
    ├── word钓鱼+PASO
    ├── word钓鱼+投诉+PASO
    ├── 加密钓鱼
    ├── 水坑钓鱼
    └── 钓鱼网站
```


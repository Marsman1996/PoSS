# 键盘钩子程序
一个带反虚拟机反调试的键盘钩子，检测到虚拟机或调试状态会立刻关机，运行时会隐藏窗口
1. 键盘钩子原理  
使用 *SetWindowsHookEx()* 函数捕获键盘消息   
dllmain.cpp 中 有捕获键盘消息的存储位置  
![](./pic/hook.PNG)

2. 虚拟机检测  
查看当前运行的进程  
查看vmtool安装路径  
I/O通信端口: in指令  
~~查看MAC~~: 真实机器上也会有VMware网卡  
~~Red Pill~~: 多核机器可能会出现问题  
~~No Pill~~:   
~~str~~:
3. 反调试  
调用Windows API: *IsDebuggerPresent()* (其实还有*CheckRemoteDebuggerPresent()*, *NtQueryInformationProcess()*, etc)  
检测PEB(进程环境块)  
插入int 3: 检测到int 3指令, 系统首先从断点链表中寻找对应的断点信息结构体(SEH)，若没有找到则直接退出/报错  
修改PE头:
4. 提权  
~~*AdjustTokenPrivileges()*~~ *RtlAdjustPrivilege()*
5. 永久驻留  
通过加注册表实现开机自启 *RegCreateKeyEx()*  
~~添加服务?~~ In windows 7 service cannot interact with user desktop. So it is impossible. [ref](https://stackoverflow.com/questions/16665852/keyboard-hook-as-a-windows-service)





## Environment
虚拟机: Win XP SP3 + VS2010 + ANSI  
实机: Win 10 + VS2017 + ANSI

## REFERENCE
键盘钩子: 《恶意代码分析实战》CH12.4  
虚拟机检测: 《恶意代码分析实战》CH17; Analysis of the Intel Pentium’s Ability to Support a Secure Virtual Machine Monit A virtual machine monitor; [详解反虚拟机技术](https://blog.csdn.net/qq_32400847/article/details/52830990)  
反调试: 《恶意代码分析实战》CH15; [详解反调试技术](https://blog.csdn.net/qq_32400847/article/details/52798050)  
提权: [利用未文档化API：RtlAdjustPrivilege 提权实现自动关机](https://www.bbsmax.com/A/1O5EpZKbJ7/); [权限ID对照表](https://blog.csdn.net/zwfgdlc/article/details/52794551)  
![](./pic/refbook.PNG)

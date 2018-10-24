# 键盘钩子程序
1. 键盘钩子原理  
使用 *SetWindowsHookEx()* 函数捕获键盘消息   
dllmain.cpp 中 有捕获键盘消息的存储位置
2. 虚拟机检测  
查看当前运行的进程  
查看vmtool安装路径  
I/O通信端口: in指令  
~~查看MAC~~: 真实机器上也会有VMware网卡  
~~Red Pill~~: 多核机器可能会出现问题  
~~No Pill~~:   
~~str~~:
<!-- <details>
  <summary><s>~~Red Pill~~</s></summary>
  <p> - 测试 测试测试</p>
  <pre><code>  title，value，callBack可以缺省  </code>  </pre>
</details> -->
3. 反调试  
调用Windows API: *IsDebuggerPresent()* (其实还有*CheckRemoteDebuggerPresent()*, *NtQueryInformationProcess()*, etc)  
检测PEB(进程环境块)  
插入int 3: 检测到int 3指令, 系统首先从断点链表中寻找对应的断点信息结构体(SEH)，若没有找到则直接退出/报错  
修改PE头:
4. 提权  
*AdjustTokenPrivileges()*




## Environment
虚拟机: Win XP SP3 + VS2010 + ANSI  
实机: Win 10 + VS2017 + ANSI

## Problems
- 如何漂亮得显示捕获的消息从哪个程序来？
- ~~win10下无法在C盘存储消息~~ MMP先创建一个文件夹再在文件夹里创建log
- ~~win10下无法对notepad.exe捕获消息，只能对一些用户程序(?)捕获~~ win10下使用*PeekMessageA()*处理msg否则会卡死?

## TODO
- [ ] 权限
- [x] 虚拟机检测
- [ ] 混淆 
- [x] 反调试技术 
- [ ] 永久驻留 （添加服务？）

## REFERENCE
键盘钩子:   
虚拟机检测: 《恶意代码分析实战》CH17; Analysis of the Intel Pentium’s Ability to Support a Secure Virtual Machine Monit A virtual machine monitor  
反调试: 《恶意代码分析实战》CH15;   

# 键盘钩子程序
1. 键盘钩子原理  
使用 *SetWindowsHookEx()* 函数捕获键盘消息  
main.cpp 中 lpszProcessName 表示目标程序  
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
3. 混淆

## Environment
Win XP SP3 + VS2010

Win 10 + VS2017
## 存在的问题
- win10下无法在C盘存储消息
- win10下无法对notepad.exe捕获消息，只能对一些用户程序(?)捕获

## TODO
- [ ] 权限
- [ ] 全局信息捕获？
- [x] 虚拟机检测
- [ ] 混淆
- [ ] 永久驻留 （添加服务？）

## REFERENCE
键盘钩子：  
虚拟机检测：《恶意代码分析实战》CH17; Analysis of the Intel Pentium’s Ability to Support a Secure Virtual Machine Monit A virtual machine monitor

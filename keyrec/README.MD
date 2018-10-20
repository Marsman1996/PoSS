# 键盘钩子程序
使用 *SetWindowsHookEx()* 函数捕获键盘消息  
main.cpp 中 lpszProcessName 表示目标程序  
dllmain.cpp 中 有捕获键盘消息的存储位置

## 测试环境
Win XP SP3 + VS2010

Win 10 + VS2017
## 存在的问题
- win10下无法在C盘存储消息
- win10下无法对notepad.exe捕获消息，只能对一些用户程序(?)捕获

## 改进目标？
- [ ] 权限？
- [ ] 全局信息捕获？
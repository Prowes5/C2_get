# C2_get
> 用来提取CS样本中的C&C服务器IP，防止出现VMP而无法人工分析的问题，且可以一定程度上增加工作效率。

```
将internet.dll Hook到指定的进程中并记录通信的IP和端口
Usage:
    loaddll.exe [install|-h] [processname]
    -h          显示帮助
    install     指定进程名做hook
```

原理：
CS木马大多数为调用wininet.dll中的`InternetOpenA->InternetConnectA->HttpOpenRequestA->HttpSendRequestA`。故hook掉对应进程的InternetConnectA，即可将通信C2提取出来。

使用方式：
以这次的FileHistory样本为例，这个样本是加了VMP壳的，人工很难分析。

先启动loaddll.exe。
```
loaddll.exe install FileHistory.exe
```
![](img\1.png)
这时候程序会被挂起，启动`FileHistory.exe`。DLL注入成功就会弹出弹窗。
![](img\2.png)
这时候就会在当前目录下生成一个host.txt

![](img\3.png)

(注：使用时internet.dll和loaddll.exe需与想要提取的样本存放到同一目录下，且样本名称不宜过长。不建议在正常应用程序使用。)
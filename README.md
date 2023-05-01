# Socks5-Server
Windows C/C++ Socks5 Server

一个用标准socket接口实现的socks5服务器，原本打算用IOCP实现，发现在小规模连接下，效率反而不如select模型。

监听地址： 127.0.0.1:2805

可以通过浏览器插件SwitchyOmega连接此socks5服务器进行测试
# 网络安全
## IP安全

### IP欺骗

#### 概念

> TCP/IP网络中的每一个数据包都包含源主机和目的主机的IP地址，攻击者通过伪造数据包，获得未被授权访问的信息，或者使伪造的信息被目的主机信任并接收。

#### 实现方法
- IP欺骗的主要表现形式有两种，一种是攻击者伪造的IP地址不可达或者根本不存在。另一种IP欺骗则着眼于目标主机和其它主机之间的信任关系。

1. 简单的ip地址

    > 攻击者伪造为受害主机ip与通信主机进行通信，

2. 源路由攻击

    > TCP/IP报头中的源路由选项明确指明了报文的传输路径，允许指定数据包发送后服务器返回的数据要通过的路由表，数据包发送者可以自己定义数据包头来伪装成信任主机，和目标机器信任连接。
    
3. Unix中的信任关系 **(补充)**

    >  在Unix系统中可以建立基于IP地址的信任关系，通过它可以使用R开头的远程调用命令，如；rlogin、rcall、rsh等，而无口令验证的烦恼。这中策略给攻击者提供了机会。

#### 防范方法 (补充)

1. 抛弃基于地址的信任策略，不允许R类远程调用命令的使用，删除rhosts文件；清空／etc／hosts．equic文件。这将使所有用户使用其它远程通信手段。

2. 进行包过滤：若网络是经路由器接入lnternet的那可以利用路由器来进行包过滤。确信只有内部LAN可以使用信任关系，而对于LAN以外的主机要慎重处理。路由器可以滤掉所有来自于外部而希望与内部建立连接的请求。

3. 使用随机化的初始序列号：攻击者之所以能够达到攻击目的，一个重要因素就是序列号不是随机选择的或随机增加的，所以，使用随机化的序列号能有效防止攻击。

__阻止IP欺骗的另一种明显的方法是在通信时进行加密传输和验证。加密和认证技术具体可分为IPsec和SSL，基于这它们可构建IPsec VPN和SSL__

1. IPSec   
    
> IPSec 提供了两种安全机制：认证和加密。认证机制使IP通信的数据接收方能够确认数据发送方的真实身份以及数据在传输过程中是否遭篡改。加密机制通过对据进行编码来保证数据的机密性，以防数据在传输过程中被窃听。
       
- AH协议定义了认证的应用方法，提供数据源认证和完整性保证；
- ESP协议定义了加密和可选认证的应用方法，提供可靠性保证。
- IKE协议用于密钥交换。
 
2. SSL
 
> SSL协议实现的安全机制包含：

- 传输数据的机密性：利用对称密钥算法对传输的数据进行加密。
- 身份验证机制：基于证书利用数字签名方法对server和client进行身份验证，当中client的身份验证是可选的。
- 消息完整性验证：消息传输过程中使用MAC算法来检验消息的完整性。

3. 适用范围
- IPSec适用于网对网的VPN连接（Site-Site），广泛应用于VPN路由器部署中。
- SSL比较适用于移动用户的远程接入（Client-Site），广泛应用于网络安全交易和远程控制。

#### 相关研究
- Systems and methods for ip source address spoof detection
- Towards a SDN-Based Integrated Architecture for Mitigating IP Spoofing Attack
- FHSD: An Improved IP Spoof Detection Method for Web DDoS Attacks
- 常用工具: nmap、hping、spoofer等

## DNS安全

## 传统DoS
**DoS**: 向目标发送大量信息使其崩溃的攻击方式  
**DDoS**: 进攻源不止一个的DoS
### SYN Flood攻击  

#### 实现原理
使用伪造的IP地址或者只进行三次握手协议中的第一次握手。因为SYN数据包用来打开一个TCP连接，所以受害者的机器会向伪造的地址发送一个SYN/ACK数据包作为回应，并等待预期的ACK响应。每个处于等待状态，半开的连接队列都将进入空间有限的待处理队列。此时将无法处理新的请求

#### 实现步骤

1. 需要安装的工具
    * Mininet
    * Netwox <br>`sudo apt-get install netwox`
    * openbsd-inetd <br>`sudo apt-get install openbsd-inetd`
    * telnetd <br>`sudo apt-get install telnetd`
2. 启动mininet创建带有1个路由器*s1*和3个终端*h1, h2, h3*的网络 <br>`python setnet.py`  
   再为*h2*启动telnet <br>`sudo /etc/init.d/openbsd-inetd restart`
3. *h3*telnet链接*h2*验证正常状态下可以链接
4. *h1*使用netwox攻击*h2* <br>`sudo netwox 76 -i "10.0.0.2" -p "23"`

#### 结果观测
<img src="SYN1.PNG" width = 30% height = 30% /> <br> *h1*向*h2*发动攻击后，*h3*无法再链接*h2*  
<img src="SYN2.PNG" width = 30% height = 30% /> <br> 使用wireshark发现大量SYN包  
<img src="SYN3.PNG" width = 30% height = 30% /> <br> wireshark发现大量包传输行为  

或者视频？

#### 防御手段
开启SYN_COOKIES  
开启SYN_COOKIES后半开的连接队列并不会被分配实际的空间，而是根据这个SYN包计算出一个cookie值。在收到TCP ACK包时，TCP服务器在根据那个cookie值检查这个TCP ACK包的合法性。如果合法，再分配专门的数据区进行处理未来的TCP连接。  

#### REFERENCE
https://blog.csdn.net/sinat_26599509/article/details/51455350

### ACK FLOOD攻击

### CC(Challenge Collapsar)攻击

### UDP FLOOD攻击

## 新型DoS

### 反射型DDoS

### websocket DDoS

## DoS防御

## Credits
[Marsman1996](https://github.com/Marsman1996)<br>
[n3vv](https://github.com/n3vv)<br>


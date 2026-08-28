# NalTool

A lightweight cross-platform encryption tool.  

---

## English

### Introduction

NalTool is a lightweight encryption and decryption tool that supports both text and file operations.  
It provides both command-line arguments and an interactive interface, making it suitable for script automation and manual use.  
Written in Rust, it is distributed as a single binary file with no external dependencies.  

### Features

- Encrypt and decrypt text
- Encrypt and decrypt files
- Optional Gzip compression
- NalKey key file management support

### Quick Start

First, download the appropriate executable file and installation script from the [Releases](https://github.com/Kacefier/NalTool/releases) page.  
Then run the installation script to install.  
During installation, the script will prompt you to enter the path to the executable file—simply provide the path to the downloaded executable.  

If you cannot find a suitable executable in Releases, try cloning the repository and building manually.

### Usage Examples

| Command | Description |
|---------|-------------|
| `naltool -v` | Show version information |
| `naltool -i` | Enter interactive interface |
| `naltool -h` | Show help information |
| `naltool -e file.txt -k "key"` | Encrypt file |
| `naltool -d file.nalfile -k "key"` | Decrypt file |
| `naltool -e "Hello" --text -k "key"` | Encrypt text |
| `naltool -d "ciphertext" --text -k "key"` | Decrypt text |
| `naltool -e file.txt -n keyfile.nalkey` | Encrypt file using NalKey |
| `naltool -d file.nalfile -n keyfile.nalkey` | Decrypt file using NalKey |
| `naltool -e file.txt -c -l 6 -k "key"` | Compress and encrypt |
| `naltool --new` | Generate a new NalKey file |

### Pre-compiled Platforms

Pre-compiled executables for the following platforms are available on the Releases page:  

- Windows (amd64)
- Linux (amd64)

If your operating system is not listed, please try building manually.  
Additionally, the repository provides installation and uninstallation scripts for both Windows and macOS/Linux platforms.  

### Open Source License

This program is free software, licensed under the GNU General Public License v3.0.  

### Author

Kacefier  

GitHub: https://github.com/Kacefier  
Email: kacefier@zohomail.com  

---

## 中文

### 简介

NalTool 是一款轻量级加解密工具，支持文本和文件加解密。  
同时提供命令行参数和交互式界面，方便脚本调用和手动使用。  
使用 Rust 编写，以单文件二进制形式分发，无需外部依赖。  

### 功能

- 加密和解密文本  
- 加密和解密文件  
- 可选的 Gzip 压缩  
- 支持 NalKey 密钥文件管理  

### 快速开始

请先到 [Releases](https://github.com/Kacefier/NalTool/releases) 页面下载合适的可执行文件和安装脚本。  
然后运行安装脚本进行安装。  
安装时，安装脚本会提示输入可执行文件的路径，输入下载的可执行文件的路径即可。  

如果你没有在 Releases 里找到合适的可执行文件，请尝试克隆仓库后手动编译。  

### 使用示例

| 命令 | 说明 |
|------|------|
| `naltool -v` | 显示版本信息 |
| `naltool -i` | 进入交互界面 |
| `naltool -h` | 显示帮助信息 |
| `naltool -e 文件.txt -k "密钥"` | 加密文件 |
| `naltool -d 文件.nalfile -k "密钥"` | 解密文件 |
| `naltool -e "Hello" --text -k "密钥"` | 加密文本 |
| `naltool -d "密文" --text -k "密钥"` | 解密文本 |
| `naltool -e 文件.txt -n 密钥文件.nalkey` | 使用 NalKey 加密文件 |
| `naltool -d 文件.nalfile -n 密钥文件.nalkey` | 使用 NalKey 解密文件 |
| `naltool -e 文件.txt -c -l 6 -k "密钥"` | 压缩并加密 |
| `naltool --new` | 生成新的 NalKey 文件 |

### 预编译平台

发布页提供以下平台的预编译可执行文件：  

- Windows（amd64）
- Linux（amd64）

如果没有你使用的操作系统，请尝试手动编译。  
同时，仓库也提供 Windows 和 macOS/Linux 平台的安装与卸载脚本。  

### 开源许可证

本程序是自由软件，采用 GNU 通用公共许可证 v3.0 授权。  

### 作者

Kacefier  

GitHub：https://github.com/Kacefier  
邮箱：kacefier@zohomail.com  

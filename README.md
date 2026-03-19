# AWVS-Love
适配AWVS14版本
一款基于AWVS14 API的自动化扫描任务调度工具，支持定时检测扫描状态并自动补充扫描任务，适用于大规模资产管理和持续安全监测。

AWVS作为强大的商业化漏洞扫描器在打点和漏扫中非常常见，但是再处理大规模资产批量扫描时最多只能一次扫描50个目标，扫描完成后需要手动添加后续需要扫描的资产，对实现自动化监测十分不友好，同时vps性能普遍较差，在vps中部署awvs时往往需要降低并发扫描数量防止服务器内存占用过高。

为了实现完全自动化的扫描，开发了这款自动化脚本，可以实现对扫描资产的定时检测和补充，用户指定检测间隔和并发扫描上限后，脚本会自动检测当前正在进行的扫描任务数量，并动态进行添加实现扫描自动化。
用户只需要在目标中添加需要扫描的大规模资产，启动脚本根据提示配置好参数，就可以躺平收洞了。

v2.0版本优化了翻页逻辑，修复了获取目标数缺失的问题

```
-h, --help            show this help message and exit
-t TIME, --time TIME  检测间隔（秒），默认60秒
--target TARGET       AWVS主机地址（必填）
-p PORT, --port PORT  AWVS端口，默认3443
-k KEY, --key KEY     AWVS API Key（必填）
--threads THREADS     最大并发扫描数，默认5
--size                扫描数量安全上限（超过则暂停），默认5
--profile-id          PROFILE_ID扫描配置文件ID，默认全扫描(11111111-1111-1111-1111-111111111111)
）
```
  
<img width="1785" height="899" alt="image" src="https://github.com/user-attachments/assets/4a0227a7-274a-4e68-83a2-bc7a0d9eb64b" />

脚本会定期对扫描中的目标数量进行检测，在扫描中目标数量少于设定阈值时自动拉取目标创建扫描：

<img width="1732" height="1037" alt="image" src="https://github.com/user-attachments/assets/2c93ae33-1810-4a4f-858b-126fb2ef5edb" />

仅用于合法授权的环境，使用前请确保已获得相关权限。作者不对任何非法使用造成的后果负责！

# Docker安装AWVS14
```
拉取： docker pull  xiaomimi8/docker-awvs-14.7.220401065

启动： docker run -it -d -p 13443:3443 xiaomimi8/docker-awvs-14.7.220401065

登录： Username:admin@admin.com password:Admin123
```

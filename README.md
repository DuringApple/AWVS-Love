# AWVS-Love

一款基于AWVS API的自动化扫描任务调度工具，支持定时检测扫描状态并自动补充扫描任务，适用于大规模资产管理和持续安全监测。

AWVS作为强大的商业化漏洞扫描器在打点和漏扫中非常常见，但是再处理大规模资产批量扫描时最多只能一次扫描50个目标，扫描完成后需要手动添加后续需要扫描的资产，对实现自动化监测十分不友好，同时vps性能普遍较差，在vps中部署awvs时往往需要降低并发扫描数量防止服务器内存占用过高。

为了实现完全自动化的扫描，开发了这款自动化脚本，可以实现对扫描资产的定时检测和补充，用户指定检测间隔和并发扫描上限后，脚本会自动检测当前正在进行的扫描任务数量，并动态进行添加实现扫描自动化。
用户只需要在目标中添加需要扫描的大规模资产，启动脚本根据提示配置好参数，就可以躺平收洞了。

```
  -t TIME, --time TIME  检测间隔（默认60秒）
  --target TARGET       AWVS主机地址
  -p PORT, --port PORT  AWVS端口（默认3443）
  -k KEY, --key KEY     AWVS API Key
  --threads THREADS     目标并发扫描数（默认5）
  --size SIZE           扫描目标数量上限（默认10）
```
  
<img width="1734" height="927" alt="image" src="https://github.com/user-attachments/assets/b7357e00-5df2-422e-bf22-0c1184ab8926" />

脚本会定期对扫描中的目标数量进行检测：

<img width="2304" height="870" alt="image" src="https://github.com/user-attachments/assets/82154737-4fd0-4c07-b53f-d147c130e39c" />

脚本会在扫描中目标数量少于设定阈值时自动拉取目标创建扫描：

<img width="2302" height="555" alt="image" src="https://github.com/user-attachments/assets/fac5aace-3906-46a0-8850-aa79a7e6f228" />

仅用于合法授权的环境，使用前请确保已获得相关权限。作者不对任何非法使用造成的后果负责！

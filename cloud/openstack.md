
> [docs](https://docs.openstack.org/)

#### OpenStack 核心服务

##### 计算

- Nova:虚拟化设施资源管理
- ZUN:容器管理
- QINLING:Serveless Function

##### 裸金属
- IRONIC:裸金属资源管理
- CYBORDF:计算加速资源管理框架(various types of accelerators such as GPU, FPGA, ASIC, NP, SoCs, NVMe/NOF SSDs, ODP, DPDK/SPDK and so on)

##### 存储

- SWIFT:对象存储
- CINDER:块存储
- MANILA:共享文件系统----

##### 网络

- NEUTRON:网络
- OCTAVIA:负载均衡
- DESIGNATE:DNS服务

##### 共享的服务

- KEYSTONE:身份验证
- GLANCE:镜像管理服务
- BARBICAN:秘钥管理
- KARBOR:应用数据保护服务
- SEARCHLIGHT:索引和查询

##### 编排

- HEAT:云应用资源编排
- SENLIN:集群服务
- MISTRAL:工作流服务
- ZAQAR:消息队列
- BLAZAR:资源保持预留服务
- AODH:预警服务

##### 负载配给

- MAGNUM:容器编排引擎配给
- SAHARA:大数据处理框架配给
- DROVE:数据库服务

##### 应用生命周期

- MASAKARI:实例高可用:自动恢复实例
- HURANO:应用目录
- SOLUM:软件开发生命周期自动化，automating the source-to-image process
- FREEZER:备份、恢复、灾备

##### API代理

- EC2API

##### Web前端

- HORIZON:控制面板

#### 运维服务

##### 运维工具

- CEILOMETER:量化与数据收集服务
- PANKO:事件、元数据索引服务
- MONASCA:监控

##### 优化和策略工具

- WATCHER:可伸缩资源优化服务
- VITRAGE:根本原因分析服务
- CONGRESS:治理服务:收集数据检查是否符合策略
- RALLY:性能检查与分析

##### 计费与商务逻辑

- CLOUDKITTY:计费与退款

##### 多Region工具

- TRICIRCLE:多Region部署的网络自动化

#### 插件服务

##### Swift 插件

- STORLETS:可计算对象存储

#### 周边技术桥接

##### 容器

- KURYR:OpenStack与容器的网络集成
- TRACKER:NFV编排

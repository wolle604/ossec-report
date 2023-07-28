# ossec_report
A Python Script for simple Reporting of OSSEC Alerts
# installation
A ossec installation is requierd. I used version 3.7.0.   
Move main.py to ```/var/ossec/bin/```
Move config.toml to ```/var/ossec/etc/```   
install following packages:
- python3.9 or higher
- toml (Included in Python 3.11)
- python-regex 
   
Modify alerts json log path in cofnig.toml:
```
alertspath = "/var/ossec/logs/alerts/alerts.json"
agentstate = "/var/ossec/logs/not_connected"
```
After that you have to insert your agentnames in config.toml:  
```
hosts = ["dbserver", "webserver","testsystem"]
```
and modify config.toml path in main.py:
```
config = toml.load("/var/ossec/ect/config.toml")
```
Configure your email client, i use msmtp
## crontab
 ```
*/10 * * * * /var/ossec/bin/list_agents -n > /var/ossec/logs/not_connected #write every 10 mins agent state to file
55 23 * * * python3 /var/ossec/bin/main.py | mail -s "OSSEC Report from <YourSYSTEM>" <YourEMAIL> #report everyday at 23:55
   ```
## ossec config 
for more accurate check, change the following attribute to lower value in ```/var/ossec/etc/internal_options.conf```
  ```
  monitord.notify_time=180
  ```
To activate json logging add the following into ```/var/ossec/etc/ossec.conf``` at global options:
```
<jsonout_output>yes</jsonout_output>
```
# How it works, and customization:
The script has following features:  
- Reporting alerts
  - Duplicated alerts will be suspressed except syscheck (FIM) (Every alert is a change in your system, and shouldn't be suspressed). Only the first alert will be shown. The script will append the "Duplicated messages suspressed!" and the total amount of this alert.
  - If decoder is unknown (=means no processed fields), alert 1002 (Unknown problem...) is raised or alert is a Windows alert, the script will append full log to line.
    Because of different timestamp an format of it, it is very difficulty to check if the same alert is alredy displayed. Because of this i used the following bash script that removes the leading timestamp of the full_log field. There is a possibility that, suspressen wouldn't work well because of differences in the log message.
  - At the end of report you get the number of all alerts, and the number of logs in the mail. You also get the state of your agents (Ok, when all connected or lists disconnected agents).
- The script displays only existing fields, but you can configure in config.toml wich fields you want to see:
   ```
   <!--
      - Allowed fields:
      - location - where the log came from (only on FTS)
      - srcuser  - extracts the source username
      - dstuser  - extracts the destination (target) username
      - user     - an alias to dstuser (only one of the two can be used)
      - srcip    - source ip
      - dstip    - dst ip
      - srcport  - source port
      - dstport  - destination port
      - protocol - protocol
      - id       - event id
      - url      - url of the event
      - action   - event action (deny, drop, accept, etc)
      - status   - event status (success, failure, etc)
      - extra_data     - Any extra data
     -->
     ```
     Technically you can display all fields in alerts.json, wich aren't in groups.
     Finally, I would like to mention that ossec and my script go hand in hand. A lot of missing information can also be solved using ossec decoder.
## example email
```
System: dbserver 
------------------
Time: 2022 Jun 08 00:45:02, Host: dbserver, Rule: 1002, Desc: Unknown problem somewhere in the system., Logfile: /var/ossec/logs/ossec.log, Full log:  2022/06/08 00:45:02 ossec-remoted: WARN: Duplicate error:  global: 29, local: 2479, saved global: 29, saved local:2480 , Decoder: Unkown Duplicated messages suspressed! Total: 108
Time: 2022 Jun 08 18:19:45, Host: dbserver, Rule: 5715, Desc: SSHD authentication success., Logfile: /var/log/auth.log, SrcIP: Private :-), User: root, Decoder: sshd Duplicated messages suspressed! Total: 3
Time: 2022 Jun 08 18:19:45, Host: dbserver, Rule: 5501, Desc: Login session opened., Logfile: /var/log/auth.log, User: root(uid=0), Decoder: pam Duplicated messages suspressed! Total: 5
Time: 2022 Jun 08 18:34:31, Host: dbserver, Rule: 502, Desc: Ossec server started., Logfile: ossec-monitord, Decoder: ossec Duplicated messages suspressed! Total: 5
Time: 2022 Jun 08 19:35:54, Host: dbserver, Rule: 5901, Desc: New group added to the system, Logfile: /var/log/auth.log, User: tcpdump, Decoder: groupadd
Time: 2022 Jun 08 19:35:54, Host: dbserver, Rule: 5902, Desc: New user added to the system, Logfile: /var/log/auth.log, User: tcpdump, Decoder: useradd
Time: 2022 Jun 08 19:36:11, Host: dbserver, Rule: 552, Desc: Integrity checksum changed again (3rd time)., Path: /etc/group-, Logfile: syscheck, Decoder: syscheck_integrity_changed
Time: 2022 Jun 08 19:36:19, Host: dbserver, Rule: 552, Desc: Integrity checksum changed again (3rd time)., Path: /etc/group, Logfile: syscheck, Decoder: syscheck_integrity_changed
Time: 2022 Jun 08 19:36:21, Host: dbserver, Rule: 552, Desc: Integrity checksum changed again (3rd time)., Path: /etc/gshadow-, Logfile: syscheck, Decoder: syscheck_integrity_changed
Time: 2022 Jun 08 19:36:29, Host: dbserver, Rule: 552, Desc: Integrity checksum changed again (3rd time)., Path: /etc/gshadow, Logfile: syscheck, Decoder: syscheck_integrity_changed
Time: 2022 Jun 08 19:36:38, Host: dbserver, Rule: 5104, Desc: Interface entered in promiscuous(sniffing) mode., Logfile: /var/log/messages, Decoder: iptables Duplicated messages suspressed! Total: 3
Time: 2022 Jun 08 20:42:47, Host: dbserver, Rule: 5502, Desc: Login session closed., Logfile: /var/log/auth.log, User: root, Decoder: pam Duplicated messages suspressed! Total: 5
------------------

System: webserver 
------------------
Time: 2022 Jun 08 01:43:16, Host: webserver, Rule: 10155, Desc: Attempt to access forbidden file or directory., Logfile: /var/log/apache2/error.log, SrcIP: 120.77.65.226, URL: /var/www/html/index.php, Decoder: apache-errorlog-denied
Time: 2022 Jun 08 01:43:18, Host: webserver, Rule: 10155, Desc: Attempt to access forbidden file or directory., Logfile: /var/log/apache2/error.log, SrcIP: 120.77.65.226, URL: /var/www/html/phpmyadmin, Decoder: apache-errorlog-denied
Time: 2022 Jun 08 02:40:30, Host: webserver, Rule: 10155, Desc: Attempt to access forbidden file or directory., Logfile: /var/log/apache2/error.log, SrcIP: 124.135.85.132, URL: /var/www/html/editBlackAndWhiteList, Decoder: apache-errorlog-denied
Time: 2022 Jun 08 02:41:04, Host: webserver, Rule: 10155, Desc: Attempt to access forbidden file or directory., Logfile: /var/log/apache2/error.log, SrcIP: 183.157.84.244, URL: /var/www/html/, Decoder: apache-errorlog-denied
Time: 2022 Jun 08 17:16:15, Host: webserver, Rule: 10155, Desc: Attempt to access forbidden file or directory., Logfile: /var/log/apache2/error.log, SrcIP: 106.75.251.164, URL: /var/www/html/, Decoder: apache-errorlog-denied
------------------

System: testsystem 
------------------
OK. No alerts found for testsystem
------------------

Total lines of alerts: 265
filtered alerts: 32
OK. All agents are connected. 
```
Here is a example line if a agent isn't connected:
```
webserver-1.2.3.4 is not active.
```

# intention
In my main job I'm a systemadministrator. In my freetime I like to programming, so don't blame my unprofessional skills ^^. I tried to develop a more useful reporting tool for OSSEC than the built-in reporting function and i didn't found a project wich supports my requirements. I work according to the kiss principle and I have tried to apply it here as well.

# feedback
Please feel free to leave your feedback :-)

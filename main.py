import json
import re
import toml
from os.path import exists
from Levenshtein import ratio  # for string similarity

config = toml.load("config.toml")
hosts = config['options']['hosts']
logs = []
logswnumber = []
length = 0
fields = config['options']['fields']
field_text = config['options']['field_text']
alertlevel = config['options']['alertlevel']
ruleids = config['options']['dontreportrules']
sysloghost = config['options']['sysloghosts']
displayFullLog = config['options']['displayFullLogifDecoderUnknown']
fullogstrings = config['options']['ConfigureFulllogstrings']

def checkIP(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if (re.search(regex, ip)):
        return True
    else:
        return False

if exists(config['options']['alertspath']):  # Only do if logs exist
    with open(config['options']['alertspath'],
              encoding='windows-1252') as logfilejson:  # Windows encoding for windows logs necessary...
        for logline in logfilejson:
            jsonlog = json.loads(logline)
            if jsonlog['rule']['level'] >= alertlevel:
                rule = str(jsonlog['rule']['sidid'])
                agent = str(jsonlog['agent_name'])
                logfile = str(jsonlog['logfile'])
                isSyslog = False
                if checkIP(logfile) and logfile in sysloghost:
                    isSyslog = True
                    agent = list(sysloghost.keys())[list(sysloghost.values()).index(logfile)]
                comment = str(jsonlog['rule']['comment'])
                decoder = ""
                pattern_log = ""
                index = ""
                index_field = ""
                sep = {39: None, 91: None, 93: None}
                length = length + 1
                condition = True
                pattern = r'Host: ' + agent + ', Rule: ' + rule + ', Desc: ' + comment + ', Logfile: ' + logfile
                logdetails = []
                if not re.search(r"'decoder':",
                                 str(jsonlog)):  # if the logline has no decoder, it has no extra fields
                    decoder = "Unknown"
                else:
                    decoder = str(jsonlog["decoder"])
                for field in fields:  # check if configured fields in logline, and append to logdetails if they exist
                    pattern_field = field
                    if re.search(re.compile(r"'" + field + r"':"), str(jsonlog)):
                        index_field = [i for i, field in enumerate(fields) if
                                       re.search(pattern_field, str(field), re.IGNORECASE)]
                        if index_field:
                            logdetails.append(str(field_text[int(index_field[0])]) + " " + str(jsonlog[field]))
                if [string for string in fullogstrings if(string in str(jsonlog))] or decoder == "Unknown" and displayFullLog:  # in special cases i want to append whole original log
                    logdetails.append(f"Full log: StartFullLog {jsonlog['full_log']} EndFullLog")
                if int(rule) in ruleids:
                    condition = False
                for log in logs:  # check if logline which should be inserted already exists. If the whole log line is appended, only an approximation is possible because of the different timestamp formats.
                    if int(rule) in ruleids:
                        condition = False
                        break
                    levenshtein = 0  # conditon true means = insert and false = no insertion, but count for logline
                    if str(log).__contains__("StartFullLog"):
                        logfulllog = str(log).split("StartFullLog ", 1)[1].split(" EndFullLog", 1)[0]
                        jsonlogfulllog = str(jsonlog['full_log'])
                        new_metric = ratio(logfulllog, jsonlogfulllog)
                        if (new_metric >= levenshtein):
                            levenshtein = new_metric  # levenshtein decimal betwenn 1=equal and 0=nothing equal
                    if logdetails:
                        pattern_log = f"{pattern}, {str(logdetails).translate(sep)}"
                    if re.search(re.escape(pattern), str(log), re.IGNORECASE):
                        if re.search(re.escape(pattern_log), str(log), re.IGNORECASE) or levenshtein > 0.92:
                            condition = False
                            break
                        else:
                            condition = True
                    else:
                        condition = True
                if condition:  # insertion of uniqe logline
                    if decoder.__contains__("syscheck_integrity"):
                        logs.append(
                            f"Time: {jsonlog['timestamp']}, Host: {agent}, Rule: {jsonlog['rule']['sidid']}, "
                            f"Desc: {jsonlog['rule']['comment']}, Path: {jsonlog['SyscheckFile']['path']}, Logfile: "
                            f"{jsonlog['logfile']}, Decoder: {decoder}")
                    elif not logdetails:
                        logs.append(
                            f"Time: {jsonlog['timestamp']}, Host: {agent}, Rule: {jsonlog['rule']['sidid']}, "
                            f"Desc: {jsonlog['rule']['comment']}, Logfile: {jsonlog['logfile']}, Decoder: "
                            f"{decoder}")
                    else:
                        logs.append(
                            f"Time: {jsonlog['timestamp']}, Host: {agent}, Rule: {jsonlog['rule']['sidid']}, "
                            f"Desc: {jsonlog['rule']['comment']}, Logfile: {jsonlog['logfile']}, {str(logdetails).translate(sep)}, Decoder: "
                            f"{decoder}")
                elif not condition:  # Suspression for duplicated logs. Appending "+ More" to processed logline, because logline alredy exists
                    fullloginlog = False
                    for detail in logdetails:
                        if detail.__contains__("Full log:"):
                            fullloginlog = True
                            break
                    if fullloginlog:  # if full log line is appended wie use levenshtein to determine the equality.
                        pattern_details = pattern + ", " + str(logdetails).translate(sep)
                        index = [i for (i, log) in enumerate(logs) if (ratio(pattern_details,
                                                                             str(re.sub(r', Decoder: .*', "",
                                                                                        str(re.sub(r'^Time(.*?), ',
                                                                                                   "",
                                                                                                   log))))) >= 0.92)]
                        if index:
                            temp = logs[int(index[0])]
                            logs[int(index[0])] = f"{str(temp)} + More"
                    else:
                        if logdetails:
                            pattern = pattern + ", " + str(logdetails).translate(sep)
                        index = [i for i, log in enumerate(logs) if
                                 re.search(re.escape(pattern), str(log), re.IGNORECASE)]
                        if index:
                            temp = logs[int(index[0])]
                            logs[int(index[0])] = f"{str(temp)} + More"

        for log in logs:  # count "+ Mores" and replace with counted number
            temp = log
            morecount = temp.count("+ More")
            if morecount > 0:
                logswnumber.append(
                    f"{str(log.replace(' + More', ''))} Duplicated messages suspressed! Total: {str(morecount + 1)}")
            else:
                logswnumber.append(str(log))

# Print entrys for each host
for host in hosts:
    print(f"System: {host} \n------------------")
    printok = ""
    for log in logswnumber:
        if re.search(re.escape("Host: " + str(host)), str(log), re.IGNORECASE):
            print(str(log).replace(' StartFullLog', '').replace('EndFullLog', ''))
            printok = True
    if not printok:
        print(f"OK. No alerts found for {host}")
    print("------------------\n")
# Print entrys for each syslog host
for host in list(sysloghost.keys()):
    print(f"Agentless System: {host} \n------------------")
    printok = ""
    for log in logswnumber:
        if re.search(re.escape("Host: " + str(host)), str(log), re.IGNORECASE):
            print(str(log).replace(' StartFullLog', '').replace('EndFullLog', ''))
            printok = True
    if not printok:
        print(f"OK. No alerts found for {host}")
    print("------------------\n")
print(f"Total lines of alerts: {length}")
print(f"filtered alerts: {len(logswnumber)}")

# Check agent state
if exists(config['options']['agentstate']):  # Only do if file exists
    with open(config['options']['agentstate'], encoding='utf-8') as agentstates:
        allconnected = True
        for agentstate in agentstates:
            if str(agentstate).__contains__("No agent available"):
                allconnected = True
            else:
                allconnected = False
                print(str(agentstate))
    if allconnected:
        print("OK. All agents are connected.")

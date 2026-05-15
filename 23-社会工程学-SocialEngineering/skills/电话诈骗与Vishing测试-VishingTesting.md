---
id: 23-002
title: "📞 电话诈骗与Vishing测试 (Vishing Testing)"
category: 社会工程学
category_en: "Social Engineering"
difficulty: ★★★★
tools: "SET (Social Engineering Toolkit), Twilio, Asterisk, CallerID Spoofer"
last_updated: 2025-07
tags: ["social-engineering", "phishing", "vishing", "physical-security", "awareness"]
subdomain: social-engineering
nist_csf: ["PR.AT-01", "PR.AT-02"]
mitre_attack: ["T1566", "T1598", "T1204"]
---
# 📞 电话诈骗与Vishing测试 (Vishing Testing)

## 概述

Vishing（语音钓鱼）是通过电话进行的社交工程攻击。测试人员模拟可信实体（IT支持、银行、供应商）通过电话获取敏感信息。本节涵盖脚本编写、通话自动化、录音分析和防御策略。

## 核心技能

### 1. Vishing 脚本编写

```markdown
# Vishing 剧本: "IT支持密码重置"

## 呼叫目标: IT部门普通员工
## 难度: 中等
## 目标信息: 域账户密码

### 开场白（建立信任）
"您好，我是IT支持中心的王工，工号TK-7854。"
"我们检测到您的邮箱账户有异常登录尝试，"
"为了安全考虑，需要您配合验证一下账户信息。"

### 话术流程
1. 建立紧急感
   "这个问题比较紧急，如果不在30分钟内处理，"
   "您的账户将被临时锁定。"

2. 信息收集
   "我这边需要确认您的身份："
   "您的工号是？" → 验证已知信息
   "您上次修改密码是什么时候？"
   "目前使用的是哪个域的账号？"

3. 获取凭证
   "系统需要验证您的当前密码以确认身份，"
   "请您提供当前的域密码。"

4. 应对质疑
   - "为什么是电话不是工单？" 
     → "因为时间紧急，我们后补工单"
   - "我要先确认你的身份"
     → "您可以挂断后拨打IT热线并转接我，工号7854"

## 成功指标
- [ ] 获取目标密码
- [ ] 获取目标回答安全问题的答案
- [ ] 获取目标访问内部系统的凭据
```

### 2. 自动化Vishing系统 (Twilio)

```python
#!/usr/bin/env python3
# 使用Twilio API自动化Vishing

from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse, Gather
import time

class VishingBot:
    def __init__(self, account_sid, auth_token, caller_id):
        self.client = Client(account_sid, auth_token)
        self.caller_id = caller_id
    
    def make_call(self, target_number, twiml_url):
        """发起vishing电话"""
        call = self.client.calls.create(
            url=twiml_url,
            to=target_number,
            from_=self.caller_id,
            machine_detection='DetectMessageEnd',
            machine_detection_timeout=5
        )
        return call.sid
    
    def create_ivr_menu(self, company_name):
        """创建交互式语音菜单"""
        response = VoiceResponse()
        
        # 开场白
        response.say(
            f"您好，这里是{company_name}安全中心。"
            f"我们检测到您的账户可能存在安全风险，"
            f"请按语音提示进行身份验证。",
            voice='alice', language='zh-CN'
        )
        
        # 收集按键输入
        gather = Gather(
            num_digits=6,
            action='/verify',
            method='POST',
            timeout=10
        )
        gather.say("请输入您的6位员工编号，以井号键结束。")
        response.append(gather)
        
        # 超时处理
        response.say("输入超时，请稍后再试。")
        response.hangup()
        
        return str(response)
    
    def get_call_recording(self, call_sid):
        """获取通话录音"""
        recordings = self.client.recordings.list(call_sid=call_sid)
        if recordings:
            recording = recordings[0]
            return f"https://api.twilio.com{recording.uri.replace('.json', '.mp3')}"
        return None

# 使用示例
bot = VishingBot("ACxxxx", "auth_token", "+8613800138000")
call_sid = bot.make_call("+8613900139000", "http://your-server.com/ivr")
time.sleep(30)
recording = bot.get_call_recording(call_sid)
```

### 3. Caller ID 欺骗

```bash
# 使用Asterisk进行Caller ID欺骗
# 安装Asterisk
apt-get install asterisk

# 配置SIP trunk (sip.conf)
cat << 'EOF' >> /etc/asterisk/sip.conf
[general]
context=public
allowoverlap=no
udpbindaddr=0.0.0.0:5060
tcpenable=no

[trunk-provider]
type=peer
host=sip.provider.com
username=your-account
secret=your-password
fromuser=your-account
insecure=port,invite
dtmfmode=rfc2833
canreinvite=no
EOF

# 创建拨号计划 (extensions.conf)
cat << 'EOF' >> /etc/asterisk/extensions.conf
[default]
exten => _X.,1,NoOp(拨出呼叫)
 same => n,Set(CALLERID(num)=010-88888888)  # 伪造来电显示
 same => n,Set(CALLERID(name)=XX银行客服)
 same => n,Dial(SIP/trunk-provider/${EXTEN})
 same => n,Hangup()
EOF

# 发起呼叫
asterisk -rx 'channel originate SIP/trunk-provider/13800138000 application echo'
```

### 4. 语音分析与社会工程评估

```python
#!/usr/bin/env python3
# Vishing通话分析工具

import speech_recognition as sr
from pydub import AudioSegment
import json

class VishingAnalyzer:
    def __init__(self):
        self.recognizer = sr.Recognizer()
    
    def transcribe_call(self, audio_file):
        """语音转文字"""
        audio = AudioSegment.from_file(audio_file)
        text = []
        
        # 分片处理长录音
        chunk_length_ms = 30000  # 30秒片段
        for i in range(0, len(audio), chunk_length_ms):
            chunk = audio[i:i+chunk_length_ms]
            chunk_path = f"temp_chunk_{i}.wav"
            chunk.export(chunk_path, format="wav")
            
            with sr.AudioFile(chunk_path) as source:
                audio_data = self.recognizer.record(source)
                try:
                    chunk_text = self.recognizer.recognize_google(audio_data, language='zh-CN')
                    text.append(chunk_text)
                except:
                    pass
        
        return ' '.join(text)
    
    def extract_sensitive_info(self, transcript):
        """提取对话中泄露的敏感信息"""
        import re
        
        patterns = {
            'password': r'(密码[是为:：]?\s*[\w@!#$%^&*]+)',
            'username': r'(用户名[是为:：]?\s*\w+)',
            'id_card': r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
            'phone': r'1[3-9]\d{9}',
            'bank_card': r'\b\d{16,19}\b',
            'verification_code': r'(验证码[是为:：]?\s*\d{4,6})'
        }
        
        findings = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, transcript)
            if matches:
                findings[name] = matches
        
        return findings

# 使用示例
analyzer = VishingAnalyzer()
transcript = analyzer.transcribe_call('vishing_call.mp3')
findings = analyzer.extract_sensitive_info(transcript)
print(json.dumps(findings, indent=2, ensure_ascii=False))
```

### 5. 防御策略与员工培训

```markdown
# Vishing 防御要点

## 员工应知应会
1. **绝不透露密码** - IT部门不会通过电话索要密码
2. **回拨验证** - 挂断后拨打官方号码确认
3. **双因素验证** - 对任何电话请求使用第二通道验证
4. **报告机制** - 可疑电话立即报告安全团队

## 技术控制措施
- [ ] 部署来电显示验证系统
- [ ] 实施呼叫密码（Calling Party Number验证）
- [ ] 配置PBX级别的异常呼叫检测
- [ ] 建立内部验证码系统（电话+短信双重确认）

## 测试频率建议
- 季度社会工程测试
- 新员工入职30天内测试
- 安全事件后专项测试
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Twilio | 语音API平台 | https://www.twilio.com/ |
| Asterisk | PBX电话系统 | https://www.asterisk.org/ |
| SET Voice Module | 社会工程工具包语音模块 | https://github.com/trustedsec/social-engineer-toolkit |
| WAVES | 自动化语音攻击框架 | https://github.com/ustayready/waves |

## 参考资源

- [MITRE ATT&CK T1598 — Phishing for Information](https://attack.mitre.org/techniques/T1598/)
- [CISA Social Engineering Guide](https://www.cisa.gov/social-engineering)
- [NIST SP 800-61 — Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

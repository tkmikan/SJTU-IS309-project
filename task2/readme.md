
### Requirements
- python 3.6+
- flask, for server
- requests, for client to make requests
- pycrypto, for AES implementation
- pwntools, optional, only for the pretty logs when attacking
- mitmproxy, optional, continue reading

```
pip install flask requests pycrypto pwntools mitmproxy
```

### Usage
#### Single Attack
1. Run server. 
    - NOTE: RSA key differs for each session, and all keys are expired when server stops or restarts.
```
python3 wupserver.py
```
2. Set up a mitm proxy at port 8080, with tools like mitmproxy or burp suite.
    - To use other ports, please modify the proxy port in `wupclient.py`.
    - Or modify the client to print data directly, so no proxy is needed.
3. Run client.
    - The client will generate an AES key and a WUP packet, and send encrypted data to server.
    - The proxy needs to capture encrypted AES key, encrypted WUP packet and the session cookie.
```
python3 wupclient.py
```
4. Put the encrypted data and session cookie in `cca2.py`, and launch the attack!
    - `pwntools` is used for its fascinating log module, but it is shipped with a lot of other stuff. To remove this dependency, just replace `log.success`, `log.progress` and `p.status` with `print`. The `with ... as p` part should also be removed.
    - Current values won't work, because RSA key must have changed, as metioned above.

#### Multiple Attacks
1. Run server. 
```
python3 wupserver.py
```
2. Run proxy with the attack script.
```
mitmdump -s mitm.py -q
```
3. Change proxy settings if necessary. Run client for several times.
    - Every time when the encrypted data is sent, the proxy will carry out the attack automatically.
```
python3 client.py
python3 client.py
......
```
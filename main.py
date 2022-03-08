import asyncio
import base64
import hashlib
import hmac
import os
import time
import urllib.parse

import httpx


async def send_msg(msg, title, secret, dingding_url):
    """
    发送钉钉消息

    :param msg: 消息内容
    :param title: 消息标题
    :param secret: 钉钉秘钥
    :param dingding_url: 钉钉 URL
    """

    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode('utf-8')

    string_to_sign_enc = f'{timestamp}\n{secret}'.encode('utf-8')

    code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(code))
    body = {"msgtype": "markdown", "markdown": {"title": title, "text": msg}, "at": {"isAtAll": "true"}}

    async with httpx.AsyncClient() as client:
        await client.post(dingding_url, json=body, params={'timestamp': timestamp, 'sign': sign})


if __name__ == "__main__":
    ding_secret = os.getenv("PLUGIN_DDSECRET", default="")
    dingding_base_url = os.getenv("PLUGIN_DDBASEURL", default="")
    drone_build_status = os.getenv("DRONE_BUILD_STATUS", default="failed")

    try:
        message = 'build is success' if drone_build_status == "success" else 'build is failed'
        asyncio.run(send_msg(message, 'drone build', ding_secret, dingding_base_url))
        print("msg send success")
    except Exception as e:
        print(e)
        print("msg send failed")

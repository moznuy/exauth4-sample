import logging
import time

import requests


def main():
    success, failures = 0, 0
    while True:
        try:
            resp = requests.post(
                "https://auth.s1.XXXXXX/token/v2/",
                headers={"auth-token": "rqouSTUwTrmNVCQK8Lt/lw=="},
                json={"room_name": "abcde", "test": True},
                timeout=5,
            )
            resp.raise_for_status()
        except Exception:
            logging.exception("!")
            failures += 1
        else:
            success += 1
        print(success, failures)
        time.sleep(2)


if __name__ == "__main__":
    main()

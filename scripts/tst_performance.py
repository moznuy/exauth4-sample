import asyncio
import datetime
import logging
import random
import string
from typing import Iterable
from typing import Set

import aiohttp
import numpy


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return "".join(random.choice(chars) for _ in range(size))


# TIMEOUTS = 0
MS = []


async def send_request(session: aiohttp.ClientSession):
    # global TIMEOUTS
    global MS
    begin = datetime.datetime.now()
    try:
        async with session.post(
            "https://auth.s1.XXXXXX/token/v2/",
            headers={"auth-token": "XXXXXX"},
            json={"room_name": id_generator(), "test": True},
        ) as request:
            await request.read()
            request.raise_for_status()
    # except asyncio.TimeoutError:
    #     TIMEOUTS += 1
    except Exception:
        logging.exception("!")
    finally:
        end = datetime.datetime.now()
        ms = int((end - begin).total_seconds() * 100)
        MS.append(ms)


async def discard_results(it: Iterable[asyncio.Task]):
    await asyncio.gather(*it)


async def main():
    max_requests_per_batch = 100
    max_requests = 10000
    conn_limit = 500

    tasks: Set[asyncio.Task] = set()
    task_count = 0

    begin = datetime.datetime.now()
    # timeout = aiohttp.ClientTimeout(total=2)
    connector = aiohttp.TCPConnector(limit=conn_limit)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            if len(tasks) < conn_limit and task_count < max_requests:
                new_task_count = min(conn_limit - len(tasks), max_requests_per_batch)
                tasks.update(
                    asyncio.create_task(send_request(session))
                    for _ in range(new_task_count)
                )
                task_count += new_task_count
            if not tasks:
                break

            print(len(tasks), task_count)
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            await discard_results(done)
            tasks = pending

    end = datetime.datetime.now()
    print(task_count / (end - begin).total_seconds())
    # print("Timeout", TIMEOUTS)
    print(f"{numpy.percentile(MS, 50)=}")
    print(f"{numpy.percentile(MS, 75)=}")
    print(f"{numpy.percentile(MS, 90)=}")
    print(f"{numpy.percentile(MS, 95)=}")
    print(f"{numpy.percentile(MS, 99)=}")
    print(f"{numpy.percentile(MS, 99.9)=}")
    print(f"{numpy.percentile(MS, 99.99)=}")


if __name__ == "__main__":
    asyncio.run(main())

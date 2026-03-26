import asyncio
import json
import os
import os.path
import re
import subprocess
import sys
from functools import wraps
from lzma import LZMADecompressor
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urljoin

import aiohttp
import click
import structlog
from appdirs import user_data_dir
from tenacity import retry, wait_exponential

logger = structlog.getLogger()


PACKAGES = [
    "firefox-unwrapped",
    "firefox-esr-unwrapped",
    "thunderbird-unwrapped",
]
PACKAGE_OUTPUT = "symbols"

PACKAGE_PATTERN = re.compile(
    rf"(?P<hash>[a-z0-9]{{32}})-(?P<name>{'|'.join(PACKAGES)})-(?P<version>[0-9.]+(?:esr)?)-{PACKAGE_OUTPUT}"
)

CHANNEL_BASE = "https://channels.nixos.org"
CACHE_BASE = "https://cache.nixos.org"

STATE = {}
STATE_DIR = user_data_dir("mach-symbols-upload")
STATE_PATH = os.path.join(STATE_DIR, "state.json")

WAIT_SHORT = wait_exponential(min=4, max=16)
WAIT_LONG = wait_exponential(min=4, max=64)


@retry(wait=WAIT_SHORT)
async def get_nixpkgs_channels(session: aiohttp.ClientSession) -> List[str]:
    response = await session.get(
        "https://prometheus.nixos.org/api/v1/query?query=channel_revision"
    )

    if response.status != 200:
        raise

    document = await response.json()
    if document["status"] != "success":
        raise

    releases = [
        item["metric"]["channel"]
        for item in document["data"]["result"]
        if item["metric"].get("status") != "unmaintained"
        and not item["metric"]["channel"].endswith("-small")
    ]

    return releases


def load_state() -> None:
    global STATE
    try:
        with open(STATE_PATH, "r") as fd:
            STATE = json.load(fd)
    except FileNotFoundError:
        STATE = {
            "version": 1,
            "last_channel_version": {},
            "last_package_hashes": [],
        }


def trim_package_hashes(keep_count: int = 64) -> None:
    # Only keep a limited number of package hashes around
    STATE["last_package_hashes"] = STATE["last_package_hashes"][keep_count * (-1) :]


def save_state() -> None:
    trim_package_hashes()

    try:
        os.makedirs(STATE_DIR)
    except FileExistsError:
        pass

    with open(STATE_PATH, "w") as fd:
        json.dump(STATE, fd)


@retry(wait=WAIT_SHORT)
async def get_channel_version(session: aiohttp.ClientSession, channel: str) -> str:
    response = await session.head(
        urljoin(CHANNEL_BASE, f"/{channel}"),
        allow_redirects=True,
        raise_for_status=True,
    )

    return response.url.path.split("/")[-1]


def channel_advanced(channel, version_now) -> bool:
    if not STATE:
        load_state()

    try:
        version_seen = STATE["last_channel_version"][channel]
    except KeyError:
        version_seen = 0

    changed = version_seen != version_now

    if changed:
        STATE["last_channel_version"][channel] = version_now

    return changed


@retry(wait=WAIT_SHORT)
async def get_store_paths(session: aiohttp.ClientSession, channel: str) -> List[str]:
    async with session.get(
        urljoin(CHANNEL_BASE, f"/{channel}/store-paths.xz")
    ) as response:
        assert response.status == 200
        return LZMADecompressor().decompress(await response.read()).decode().split()


def find_packages(store_paths: List[str]) -> Iterable[Dict]:
    for store_path in store_paths:
        if match := PACKAGE_PATTERN.search(store_path):
            yield dict(
                name=match.group("name"),
                hash=match.group("hash"),
            )


def parse_narinfo(narinfo: str) -> Dict[str, Any]:
    lines = narinfo.split("\n")
    result = dict()
    for line in lines:
        try:
            key, value = line.split(":", maxsplit=1)
        except ValueError:
            continue  # empty value
        result[key] = value.strip()
    return result


@retry(wait=WAIT_SHORT)
async def get_narinfo(session, _hash: str) -> Dict[str, Any]:
    async with session.get(
        urljoin(CACHE_BASE, f"/{_hash}.narinfo"), raise_for_status=True
    ) as response:
        narinfo = await response.text()

        return parse_narinfo(narinfo)


def package_already_uploaded(package: Dict) -> bool:
    global STATE

    uploaded = package["hash"] in STATE["last_package_hashes"]

    if not uploaded:
        STATE["last_package_hashes"].append(package["hash"])

    return uploaded


@retry(wait=WAIT_LONG)
async def upload(
    *, file: Path, session: aiohttp.ClientSession, auth_token: str
) -> aiohttp.ClientResponse:
    return await session.post(
        url="https://symbols.mozilla.org/upload/",
        data={file.name: open(file.as_posix(), "rb")},
        headers={
            "Auth-token": auth_token,
        },
    )


def coroutine(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.command()
@click.option("--auth-token", envvar="AUTH_TOKEN", required=True)
@coroutine
async def main(auth_token: str):
    async with aiohttp.ClientSession() as session:
        channels = await get_nixpkgs_channels(session)
        logger.msg(
            "Discovered channels",
            channels=channels,
        )
        for channel in channels:
            try:
                version = await get_channel_version(session, channel)
            except aiohttp.ClientError as exc:
                logger.exception(
                    "Error requesting channel version",
                    channel=channel,
                    error=str(exc),
                    exc_info=False,
                )
                continue

            if not channel_advanced(channel, version):
                logger.debug(
                    "Channel not advanced",
                    channel=channel,
                    version=version,
                )
                continue

            logger.msg(
                "Channel advanced",
                channel=channel,
                version=version,
            )

            store_paths = await get_store_paths(session, channel)

            for package in find_packages(store_paths):
                # get narinfo to find store path for hash
                try:
                    narinfo = await get_narinfo(session, package["hash"])
                except aiohttp.ClientError as exc:
                    logger.exception(
                        "Error downloading narinfo file",
                        channel=channel,
                        version=version,
                        package=package["name"],
                        hash=package["hash"],
                        error=str(exc),
                    )
                    continue

                if package_already_uploaded(package):
                    logger.msg(
                        "Package skipped",
                        channel=channel,
                        package=package["name"],
                        hash=package["hash"],
                        store_path=narinfo["StorePath"],
                    )
                    continue

                logger.msg(
                    "Package found",
                    channel=channel,
                    package=package["name"],
                    hash=package["hash"],
                    store_path=narinfo["StorePath"],
                )

                # use nix to download the store path into the local nix store
                subprocess.run(["nix-store", "--realise", narinfo["StorePath"]])

                # find symbols file
                path = Path(narinfo["StorePath"])
                files = list(path.glob("*.crashreporter-symbols.zip"))
                if len(files) != 1:
                    logger.error(
                        f"Found {len(files)} crashreporter zipfiles.",
                        channel=channel,
                        package=package["name"],
                        store_path=narinfo["StorePath"],
                    )
                    continue
                file = files.pop()

                # upload
                logger.msg(
                    "Uploading symbols",
                    channel=channel,
                    package=package["name"],
                    hash=package["hash"],
                    file=file.name,
                )

                response = await upload(
                    session=session,
                    file=file,
                    auth_token=auth_token,
                )

                if response.status != 201:  # created
                    body = await response.json()
                    logger.error(
                        "Error uploading symbols output",
                        channel=channel,
                        version=version,
                        package=package["name"],
                        hash=package["hash"],
                        error=body.get("error"),
                    )
                    sys.exit(1)

                logger.msg(
                    "Upload complete",
                    channel=channel,
                    package=package["name"],
                    hash=package["hash"],
                    file=file.name,
                )
                save_state()


if __name__ == "__main__":
    asyncio.run(main())

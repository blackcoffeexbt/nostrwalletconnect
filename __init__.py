import asyncio

from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles

from lnbits.db import Database
from lnbits.helpers import template_renderer
from lnbits.tasks import catch_everything_and_restart

db = Database("ext_nostrwalletconnect")

nostrwalletconnect_ext: APIRouter = APIRouter(prefix="/nostrwalletconnect", tags=["nostrwalletconnect"])

nostrwalletconnect_static_files = [
    {
        "path": "/nostrwalletconnect/static",
        "app": StaticFiles(packages=[("lnbits", "extensions/nostrwalletconnect/static")]),
        "name": "nostrwalletconnect_static",
    }
]


def nostrwalletconnect_renderer():
    return template_renderer(["lnbits/extensions/nostrwalletconnect/templates"])


from .tasks import wait_for_paid_invoices
from .views import *  # noqa: F401,F403
from .views_api import *  # noqa: F401,F403


def nostrwalletconnect_start():
    loop = asyncio.get_event_loop()
    loop.create_task(catch_everything_and_restart(wait_for_paid_invoices))

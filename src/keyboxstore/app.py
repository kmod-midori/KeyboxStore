"""Single-file keybox API. Upload replacement is atomic across workers."""

import asyncio
import os
import tempfile
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi import Path as APIPath
from fastapi.responses import Response

from keyboxstore.expiry import monitor_expiry
from keyboxstore.notifications import notify_upload
from keyboxstore.parser import InvalidKeybox, export, parse

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
Index = Annotated[int, APIPath(ge=0, description="Zero-based keybox index")]


def create_app(
    storage_path: str | Path | None = None, max_upload_bytes: int = MAX_UPLOAD_BYTES
) -> FastAPI:
    storage = Path(storage_path or os.environ.get("KEYBOX_FILE", "data/keybox.xml"))
    ntfy_url = os.environ.get("NTFY_URL", "").strip()
    ntfy_token = os.environ.get("NTFY_TOKEN", "").strip()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not ntfy_url:
            yield
            return
        task = asyncio.create_task(monitor_expiry(storage, ntfy_url, ntfy_token))
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(
        title="KeyboxStore",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    def current(index: int | None = None):
        try:
            root, metadata = parse(storage.read_bytes())
        except FileNotFoundError:
            raise HTTPException(404, "No keybox file has been uploaded") from None
        except InvalidKeybox:
            raise HTTPException(500, "Stored keybox file is invalid") from None
        if index is not None and index >= len(metadata):
            raise HTTPException(404, "Keybox index not found")
        return root, metadata

    @app.post("/keyboxes", status_code=201, summary="Replace the current keybox file")
    def upload(
        background_tasks: BackgroundTasks,
        file: Annotated[UploadFile, File(description="AndroidAttestation XML file")],
    ):
        try:
            data = file.file.read(max_upload_bytes + 1)
        finally:
            file.file.close()
        if len(data) > max_upload_bytes:
            raise HTTPException(413, f"File exceeds {max_upload_bytes} bytes")
        try:
            _, metadata = parse(data)
        except InvalidKeybox as exc:
            raise HTTPException(422, str(exc)) from None
        storage.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=storage.parent, prefix=".keybox-", delete=False
            ) as handle:
                temporary = Path(handle.name)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, storage)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if ntfy_url:
            background_tasks.add_task(
                notify_upload, ntfy_url, ntfy_token, len(metadata), metadata[0]
            )
        return {"count": len(metadata), "keyboxes": metadata}

    @app.get("/keyboxes", summary="Get all leaf certificate metadata")
    def list_keyboxes():
        _, metadata = current()
        return {"count": len(metadata), "keyboxes": metadata}

    @app.get("/keyboxes/{index}", summary="Get one keybox's leaf certificate metadata")
    def get_keybox(index: Index):
        _, metadata = current(index)
        return metadata[index]

    @app.get(
        "/keyboxes/{index}/export",
        summary="Download one keybox including private keys",
        response_class=Response,
        responses={200: {"content": {"application/xml": {}}}},
    )
    def export_keybox(index: Index):
        root, _ = current(index)
        return Response(
            export(root, index),
            media_type="application/xml",
            headers={
                "Cache-Control": "no-store",
            },
        )

    return app


app = create_app()

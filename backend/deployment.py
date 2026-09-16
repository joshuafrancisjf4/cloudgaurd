import re
import socket
import subprocess
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/deployment",
    tags=["Deployment"]
)


class DeployRequest(BaseModel):
    image_name: str
    container_port: int = Field(default=3000, ge=1, le=65535)
    host_port: int | None = Field(default=None, ge=1, le=65535)


class StopRequest(BaseModel):
    container_name: str


def run_command(command: list[str]):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        return result.returncode, result.stdout.strip(), result.stderr.strip()

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=500,
            detail="Docker command timed out."
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="Docker is not installed or is not available in PATH."
        )


def docker_is_running():
    code, _, _ = run_command(["docker", "info"])

    if code != 0:
        raise HTTPException(
            status_code=500,
            detail="Docker Desktop is not running."
        )


def validate_image_name(image_name: str):
    if not re.fullmatch(
        r"[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?",
        image_name
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid Docker image name."
        )


def validate_container_name(container_name: str):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", container_name):
        raise HTTPException(
            status_code=400,
            detail="Invalid container name."
        )


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@router.post("/deploy")
def deploy_container(request: DeployRequest):

    docker_is_running()

    validate_image_name(request.image_name)

    # Check whether Docker image exists
    code, _, error = run_command(
        [
            "docker",
            "image",
            "inspect",
            request.image_name
        ]
    )

    if code != 0:
        raise HTTPException(
            status_code=404,
            detail=f"Docker image '{request.image_name}' was not found."
        )

    # Automatically choose a free port if user does not provide one
    host_port = request.host_port or find_free_port()

    container_name = (
        "cloudguard-"
        + uuid.uuid4().hex[:8]
    )

    command = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-p",
        f"{host_port}:{request.container_port}",
        request.image_name
    ]

    code, container_id, error = run_command(command)

    if code != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Deployment failed.",
                "docker_error": error
            }
        )

    return {
        "status": "success",
        "message": "Application deployed successfully.",
        "image": request.image_name,
        "container_name": container_name,
        "container_id": container_id,
        "container_port": request.container_port,
        "host_port": host_port,
        "live_url": f"http://localhost:{host_port}"
    }


@router.get("/containers")
def list_cloudguard_containers():

    docker_is_running()

    code, output, error = run_command(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "name=cloudguard-",
            "--format",
            "{{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}"
        ]
    )

    if code != 0:
        raise HTTPException(
            status_code=500,
            detail=error
        )

    containers = []

    if output:
        containers = output.splitlines()

    return {
        "status": "success",
        "containers": containers
    }


@router.post("/stop")
def stop_container(request: StopRequest):

    docker_is_running()

    validate_container_name(request.container_name)

    if not request.container_name.startswith("cloudguard-"):
        raise HTTPException(
            status_code=400,
            detail="CloudGuard can only stop containers created by CloudGuard."
        )

    code, _, error = run_command(
        [
            "docker",
            "stop",
            request.container_name
        ]
    )

    if code != 0:
        raise HTTPException(
            status_code=500,
            detail=error
        )

    return {
        "status": "success",
        "message": "Container stopped successfully.",
        "container_name": request.container_name
    }


@router.delete("/remove/{container_name}")
def remove_container(container_name: str):

    docker_is_running()

    validate_container_name(container_name)

    if not container_name.startswith("cloudguard-"):
        raise HTTPException(
            status_code=400,
            detail="CloudGuard can only remove containers created by CloudGuard."
        )

    code, _, error = run_command(
        [
            "docker",
            "rm",
            "-f",
            container_name
        ]
    )

    if code != 0:
        raise HTTPException(
            status_code=500,
            detail=error
        )

    return {
        "status": "success",
        "message": "Container removed successfully.",
        "container_name": container_name
    }
import docker
import asyncio
from typing import Optional, Dict, List
from app.core.config import settings


class DockerManager:
    
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            self.client = None
            print(f"Warning: Docker client not available: {e}")
    
    def is_available(self) -> bool:
        if self.client is None:
            return False
        try:
            self.client.ping()
            return True
        except Exception:
            return False
    
    async def create_honeypot_container(
        self,
        container_name: str,
        honeypot_type: str,
        port: int,
        config: Dict,
        image: Optional[str] = None
    ) -> Optional[str]:
        if not self.is_available():
            raise RuntimeError("Docker is not available")
        
        if not image:
            image = self._get_default_image(honeypot_type)
        
        ports = {f"{port}/tcp": port}
        
        env_vars = {
            "HONEYPOT_TYPE": honeypot_type,
            "PORT": str(port),
            "SERVICE_ID": container_name,
        }
        env_vars.update(config.get("environment", {}))
        
        def _run_container():
            return self.client.containers.run(
                image=image,
                name=container_name,
                ports=ports,
                environment=env_vars,
                detach=True,
                remove=False,
                network="honeypot-isolated-network",
                restart_policy={"Name": "no"},
                labels={
                    "honeypot": "true",
                    "honeypot_type": honeypot_type,
                    "service_id": container_name
                }
            )
        
        try:
            container = await asyncio.to_thread(_run_container)
            return container.id
        except docker.errors.ImageNotFound:
            raise ValueError(f"Docker image not found: {image}")
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
    
    async def _ensure_isolated_network(self):
        network_name = "honeypot-isolated-network"
        
        def _get_network():
            return self.client.networks.get(network_name)
        
        def _create_network():
            return self.client.networks.create(
                network_name,
                driver="bridge",
                check_duplicate=True
            )
        
        try:
            await asyncio.to_thread(_get_network)
        except docker.errors.NotFound:
            await asyncio.to_thread(_create_network)
    
    async def create_isolated_honeypot_container(
        self,
        container_name: str,
        honeypot_type: str,
        port: int,
        service_id: str,
        config: Dict
    ) -> Optional[str]:
        if not self.is_available():
            raise RuntimeError("Docker is not available")
        
        await self._ensure_isolated_network()
        
        def _remove_existing():
            try:
                existing_container = self.client.containers.get(container_name)
                if existing_container.status == 'running':
                    existing_container.stop()
                existing_container.remove(force=True)
            except docker.errors.NotFound:
                pass
        
        await asyncio.to_thread(_remove_existing)
        
        if honeypot_type == "http":
            image_name = "honey-potter-http-honeypot"
            dockerfile_name = "Dockerfile.honeypot"
            runner_file = "honeypot_runner.py"
        elif honeypot_type == "postgres":
            image_name = "honey-potter-postgres-honeypot"
            dockerfile_name = "Dockerfile.honeypot"
            runner_file = "postgres_honeypot_runner.py"
        else:
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}")
        
        import os
        dockerfile_path = os.path.join(os.path.dirname(__file__), "../../../", dockerfile_name)
        if not os.path.exists(dockerfile_path):
            raise RuntimeError(f"{dockerfile_name} not found")
        
        def _remove_image():
            try:
                self.client.images.remove(image_name, force=True)
            except docker.errors.ImageNotFound:
                pass
            except Exception as e:
                print(f"[DOCKER] Warning: Could not remove old image: {e}")
        
        await asyncio.to_thread(_remove_image)
        
        def _build_image():
            return self.client.images.build(
                path=os.path.dirname(dockerfile_path),
                dockerfile="Dockerfile.honeypot",
                tag=image_name,
                rm=True,
                forcerm=True
            )
        
        runner_path = os.path.join(os.path.dirname(dockerfile_path), runner_file)
        if not os.path.exists(runner_path):
            raise RuntimeError(f"{runner_file} not found")
        
        print(f"[DOCKER] Building honeypot image: {image_name}")
        await asyncio.to_thread(_build_image)
        
        ports = {f"{port}/tcp": port}
        
        def _get_gateway_ip():
            try:
                isolated_network = self.client.networks.get("honeypot-isolated-network")
                gateway_ip = "172.17.0.1"
                if isolated_network.attrs.get('IPAM', {}).get('Config'):
                    gateway_ip = isolated_network.attrs['IPAM']['Config'][0].get('Gateway', '172.17.0.1')
                return gateway_ip
            except Exception:
                return "172.17.0.1"
        
        gateway_ip = await asyncio.to_thread(_get_gateway_ip)
        
        env_vars = {
            "SERVICE_ID": service_id,
            "PORT": str(port),
            "HOST": config.get('host', '0.0.0.0'),
            "API_URL": f"http://{gateway_ip}:8000",
            "SECRET_KEY": settings.secret_key
        }
        
        def _run_isolated_container():
            cmd = ["python", f"/app/{runner_file}"]
            
            return self.client.containers.run(
                image=image_name,
                name=container_name,
                ports=ports,
                environment=env_vars,
                command=cmd,
                detach=True,
                remove=False,
                network="honeypot-isolated-network",
                restart_policy={"Name": "no"},
                labels={
                    "honeypot": "true",
                    "honeypot_type": honeypot_type,
                    "service_id": service_id
                },
                cap_drop=["ALL"],
                cap_add=["NET_BIND_SERVICE"],
                read_only=True,
                tmpfs={"/tmp": "noexec,nosuid,size=100m"}
            )
        
        try:
            container = await asyncio.to_thread(_run_isolated_container)
            return container.id
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error: {e}")
    
    async def start_container(self, container_id: str) -> bool:
        if not self.is_available():
            return False
        
        def _start():
            try:
                container = self.client.containers.get(container_id)
                container.start()
                return True
            except docker.errors.NotFound:
                return False
        
        return await asyncio.to_thread(_start)
    
    async def stop_container(self, container_id: str) -> bool:
        if not self.is_available():
            return False
        
        def _stop():
            try:
                container = self.client.containers.get(container_id)
                container.stop()
                return True
            except docker.errors.NotFound:
                return False
        
        return await asyncio.to_thread(_stop)
    
    async def remove_container(self, container_id: str) -> bool:
        if not self.is_available():
            return False
        
        def _remove():
            try:
                container = self.client.containers.get(container_id)
                container.remove(force=True)
                return True
            except docker.errors.NotFound:
                return False
        
        return await asyncio.to_thread(_remove)
    
    async def get_container_status(self, container_id: str) -> Optional[str]:
        if not self.is_available():
            return None
        
        def _get_status():
            try:
                container = self.client.containers.get(container_id)
                return container.status
            except docker.errors.NotFound:
                return None
        
        return await asyncio.to_thread(_get_status)
    
    async def get_container_logs(self, container_id: str, tail: int = 100) -> List[str]:
        if not self.is_available():
            return []
        
        def _get_logs():
            try:
                container = self.client.containers.get(container_id)
                logs = container.logs(tail=tail, timestamps=True)
                return logs.decode("utf-8").split("\n")
            except docker.errors.NotFound:
                return []
        
        return await asyncio.to_thread(_get_logs)
    
    def _get_default_image(self, honeypot_type: str) -> str:
        images = {
            "ssh": "cowrie/cowrie:latest",
            "postgres": "postgres:15-alpine",
            "http": "nginx:alpine",
        }
        return images.get(honeypot_type, f"honeypot-{honeypot_type}:latest")

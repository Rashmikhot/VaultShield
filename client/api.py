import json
import ssl
from urllib.parse import urlsplit
import httpx


class APIError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def tls_context(ca_file=None):
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ecdh_curve("prime256v1")
    # Do not honor environment-driven TLS session secret logging.
    ctx.keylog_filename = None
    return ctx


class VaultAPI:
    def __init__(self, base_url="https://localhost:8443", ca_file=None):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Server URL must be an HTTPS origin without credentials or a path")
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.tls_info = None
        self.http = httpx.Client(
            base_url=self.base_url,
            verify=tls_context(ca_file),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(10, connect=5),
            limits=httpx.Limits(max_connections=2),
        )

    def request(self, method, path, data=None):
        headers = {"Authorization": "Bearer " + self.token} if self.token else {}
        try:
            with self.http.stream(method, path, json=data, headers=headers) as response:
                stream = response.extensions.get("network_stream")
                ssl_object = stream.get_extra_info("ssl_object") if stream else None
                if ssl_object:
                    self.tls_info = {"protocol": ssl_object.version(), "cipher": ssl_object.cipher()[0]}
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 5_000_000:
                        raise APIError(0, "Server response exceeds size limit")
                if response.status_code >= 300:
                    messages = {
                        401: "Authentication failed or session expired. Log in again.",
                        404: "Item not found or access denied.",
                        409: "A newer version exists. Refresh before retrying.",
                        413: "Record or request is too large.",
                        422: "The server rejected the input format.",
                        429: "Too many authentication attempts. Wait 60 seconds.",
                    }
                    raise APIError(
                        response.status_code, messages.get(response.status_code, "Server request failed.")
                    )
                return json.loads(raw) if raw else None
        except httpx.HTTPError:
            raise APIError(0, "Secure connection failed. Check server, hostname and trusted CA.") from None
        except (ValueError, UnicodeError):
            raise APIError(0, "Invalid server response.") from None

    def run_simulation(self, kind):
        return self.request("POST", "/security/simulations", {"kind": kind})

    def simulation_history(self):
        return self.request("GET", "/security/simulations")

    def logout(self):
        try:
            self.request("POST", "/auth/logout")
        except APIError as exc:
            raise APIError(
                exc.status,
                "Signed out locally, but server revocation was not confirmed. The session will expire automatically.",
            ) from None
        finally:
            self.token = None

    def close(self):
        self.token = None
        self.http.close()

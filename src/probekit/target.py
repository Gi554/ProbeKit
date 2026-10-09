from dataclasses import dataclass
import ipaddress
from urllib.parse import quote, urlsplit, urlunsplit


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "Target":
        if any(ord(char) < 32 for char in value):
            raise ValueError("Caractères de contrôle interdits dans l'URL.")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("L'URL doit commencer par http:// ou https://.")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Hôte requis ; les identifiants intégrés à l'URL ne sont pas pris en charge.")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
                   or not all(char.isalnum() or char == "-" for char in part)
                   for part in host.rstrip(".").split(".")):
                raise ValueError("Nom d'hôte invalide.") from None
            host = host.rstrip(".")
            rendered_host = host
        else:
            rendered_host = f"[{host}]" if address.version == 6 else host
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("Port invalide.")
        authority = rendered_host
        if parsed.port is not None:
            authority += f":{port}"
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="%:@!$&'()*+,;=/?-._~")
        url = urlunsplit((parsed.scheme, authority, path, query, ""))
        return cls(url, parsed.scheme, host, port)

    def accepts_redirect(self, destination: str) -> bool:
        try:
            other = Target.parse(destination)
        except ValueError:
            return False
        return (other.scheme, other.host, other.port) == (self.scheme, self.host, self.port)

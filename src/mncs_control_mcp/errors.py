from __future__ import annotations


class ControlError(RuntimeError):
    """Expected, structured failure at the control boundary."""

    def __init__(self, code: str, message: str, *, details: object | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"error": self.code, "message": self.message}
        if self.details is not None:
            result["details"] = self.details
        return result

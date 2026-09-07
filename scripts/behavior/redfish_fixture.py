from openubmc_upgrade.runtime_backend import RedfishResponse


class FakeRedfishSession:
    def __init__(self, number: int, *, simple_update: bool = False) -> None:
        self.number = number
        self.simple_update = simple_update
        self.calls: list[tuple[str, str]] = []

    def request_json(self, method: str, path: str, **_kwargs) -> RedfishResponse:
        self.calls.append((method, path))
        if path == "/redfish/v1/UpdateService":
            if self.simple_update:
                return RedfishResponse(
                    status=200,
                    headers={},
                    payload={
                        "Actions": {
                            "#UpdateService.SimpleUpdate": {
                                "target": "/redfish/v1/UpdateService/Actions/SimpleUpdate"
                            }
                        }
                    },
                )
            return RedfishResponse(
                status=200,
                headers={},
                payload={"HttpPushUri": "/redfish/v1/UpdateService/upload"},
            )
        if path == "/redfish/v1/UpdateService/Actions/SimpleUpdate":
            return RedfishResponse(
                status=202,
                headers={"Location": "/redfish/v1/TaskService/Tasks/1"},
                payload={},
            )
        if path == "/redfish/v1/UpdateService/upload":
            return RedfishResponse(
                status=202,
                headers={"Location": "/redfish/v1/TaskService/Tasks/1"},
                payload={},
            )
        if path == "/redfish/v1/TaskService/Tasks/1":
            return RedfishResponse(
                status=200,
                headers={},
                payload={"TaskState": "Completed"},
            )
        if path == "/redfish/v1/Managers":
            return RedfishResponse(
                status=200,
                headers={},
                payload={"Members": [{"@odata.id": "/redfish/v1/Managers/1"}]},
            )
        if path == "/redfish/v1/Managers/1":
            return RedfishResponse(
                status=200,
                headers={},
                payload={
                    "FirmwareVersion": "2.0.0",
                    "LastResetTime": (
                        "2026-09-05T00:01:00Z" if self.number > 1
                        else "2026-09-05T00:00:00Z"
                    ),
                },
            )
        raise AssertionError(f"unexpected Redfish request: {method} {path}")


class FakeRedfishTransport:
    def __init__(self, *, simple_update: bool = False) -> None:
        self.opens = 0
        self.simple_update = simple_update
        self.sessions: list[FakeRedfishSession] = []

    def open_session(self, *, target, credentials) -> FakeRedfishSession:
        self.opens += 1
        session = FakeRedfishSession(
            self.opens,
            simple_update=self.simple_update,
        )
        self.sessions.append(session)
        return session

    @staticmethod
    def request(session, _operation: str, **kwargs):
        return kwargs["callback"](session)

    @staticmethod
    def is_authentication_failure(_error: BaseException) -> bool:
        return False

    @staticmethod
    def close_session(_session) -> None:
        return None


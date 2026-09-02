from Virus_Scan.scheduler.workers.ipc_lifecycle import stop_worker_heartbeat, shutdown_worker_processes


class _Stop:
    def __init__(self):
        self.called = False
    def set(self):
        self.called = True


class _Thread:
    def __init__(self, alive=False):
        self.joined = False
        self._alive = alive
    def join(self, timeout=None):
        self.joined = True
    def is_alive(self):
        return self._alive


def test_stage156_heartbeat_shutdown_is_single_authoritative_path():
    stop = _Stop()
    thread = _Thread(alive=False)
    status = stop_worker_heartbeat(stop, thread, join_timeout=0.01)
    assert status["signalled"] is True
    assert status["joined"] is True
    assert status["alive"] is False
    assert stop.called is True
    assert thread.joined is True


class _Queue:
    def __init__(self):
        self.items = []
    def put(self, item, timeout=None):
        self.items.append(item)


class _Proc:
    def __init__(self, alive_after_join=False):
        self.joined = False
        self.terminated = False
        self._alive = alive_after_join
    def join(self, timeout=None):
        self.joined = True
    def is_alive(self):
        return self._alive and not self.terminated
    def terminate(self):
        self.terminated = True


def test_stage156_worker_process_shutdown_orders_sentinel_join_then_terminate():
    q = _Queue()
    p1 = _Proc(alive_after_join=False)
    p2 = _Proc(alive_after_join=True)
    summary = shutdown_worker_processes([p1, p2], task_queue=q, exit_grace_sec=0.01)
    assert q.items == [None, None]
    assert p1.joined and p2.joined
    assert p2.terminated is True
    assert summary["sentinels"] == 2
    assert summary["joined"] == 2
    assert summary["terminated"] == 1
    assert summary["alive_after"] == 0

from traceseed import MemoryStorage, capture, register_collector


class BuildCollector:
    name = "build"

    def collect(self, exception, context, config):
        return {"build": {"version": "2026.06", "channel": "local"}}


register_collector(BuildCollector())
storage = MemoryStorage()


@capture(storage=storage)
def fail():
    raise RuntimeError("example")


if __name__ == "__main__":
    try:
        fail()
    except RuntimeError:
        print(storage.records[0].collector_errors)

from pathlib import Path

from traceseed import TraceSeedConfig, capture, configure

configure(TraceSeedConfig(output_directory=Path(".traceseeds-example")))


@capture(operation="process-payment")
def process_payment(order_id: int, password: str) -> None:
    raise ValueError(f"payment rejected for order {order_id}")


if __name__ == "__main__":
    try:
        process_payment(123, password="never-save-this")
    except ValueError as error:
        print(f"Original exception preserved: {error}")

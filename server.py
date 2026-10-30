"""Convenience entry point for the lab's HTTP receiver and dashboard."""

from detector import app


if __name__ == "__main__":
    # Bind to localhost by default. Set LAB_HOST=0.0.0.0 only when testing
    # from a second machine on a trusted, isolated lab network.
    import os

    app.run(
        host=os.environ.get("LAB_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

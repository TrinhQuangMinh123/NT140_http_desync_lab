import sys
from flask import Flask, request, Response
from gevent.pywsgi import WSGIServer

app = Flask(__name__)


@app.before_request
def log_raw_bytes():
    raw_data = request.get_data()
    print("[RAW BYTES RECEIVED]:", raw_data)
    sys.stdout.flush()


@app.route("/path1", methods=["GET", "POST"])
def path1():
    return Response("OK - path1", status=200)


@app.route("/path2", methods=["GET", "POST"])
def path2():
    return Response("OK - path2 (SMUGGLED)", status=200)


if __name__ == "__main__":
    server = WSGIServer(("0.0.0.0", 5000), app)
    server.serve_forever()

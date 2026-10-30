# Plaintext HTTP Detection Lab — Final

A local-only demo showing why credentials must not be sent over plain HTTP. Use fake values only. The server binds to `127.0.0.1` by default and does not echo or store submitted values. The detector records only credential field names, time, and severity.

## Start it on Windows

Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe server.py
```

Keep that window open. In a browser, open [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard).

## Capture a fresh request in Wireshark

1. Start Wireshark and begin capturing on **Adapter for loopback traffic capture** before sending the request. If that name is unavailable, choose the Npcap loopback adapter.
2. In a second PowerShell window, send this fake-only request:

```powershell
curl.exe -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "password=Fake123&api_key=FAKE-KEY-1234" http://127.0.0.1:5000/login
```

3. Stop the capture. Apply the display filter `http`, select `POST /login`, then expand **HTML Form URL Encoded**. Wireshark should show both fake values. Use **Follow → HTTP Stream** to inspect the complete request and response.
4. Save the capture in `evidence/` as a `.pcapng` file.

## Run the detector on a stream export

Save the Wireshark Follow HTTP Stream text to a file, then run:

```powershell
.\.venv\Scripts\python.exe detector.py path\to\stream.txt
```

The detector reports matched field names without printing their values. The dashboard displays persisted findings with severity colors. A no-credential control should report `No exposure found`.

## Included verification evidence

`evidence/` contains the loopback capture, an HTTP-filtered `.pcap`, Wireshark's decoded packet details, the request transcript, detector positive/negative output, dashboard verification notes, and screenshots. The current capture's packet-detail transcript shows the complete `FAKE-KEY-1234` value. `day2_plaintext_cred.png` is an existing same-day Wireshark Follow HTTP Stream screenshot from the earlier `FAKE-KEY` request; use the packet-detail transcript for the fresh capture's full value.

The included `findings.json` contains sanitized finding summaries only. The capture and stream evidence intentionally contain fake values in plaintext; do not replace them with real credentials or send this lab over an untrusted network.

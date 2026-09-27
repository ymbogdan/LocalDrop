# LocalDrop

Move files between a Windows PC and a phone on the local network. The phone opens a page in its browser. There is no account, and files do not go through a cloud.

The computer shows a QR code. Scanning it opens the page. The address and the access code do not have to be typed.

iPhone with Safari and Android with Chrome both use that page. There is no separate phone app.

## Pros

* The only wait is the upload. When it finishes, the file is already on the computer. There is no second download and no extra processing time.
* It stays on your network. There is no account, and the file does not pass through a cloud, which is a tighter setup than the usual sharing tools.
* It sends the original file, so the transfer stays fast and the quality stays the same.
* The saved file keeps its original date, time, and metadata.

## Requirements

* Windows 10 or 11
* Python 3.13, if you start from source
* A phone on the same network:
  * iPhone with Safari
  * Android with Chrome
* Or the phone plugged in by cable with its personal hotspot on

USB alone is not enough. The browser needs a network address. With the hotspot on, the cable provides that network, and the PC does not need internet.

## Start

From the executable:

```text
dist\LocalDrop.exe
```

From source:

```text
pip install -r requirements.txt
python -m app.main
```

To rebuild the executable:

```text
python -m PyInstaller --noconfirm LocalDrop.spec
```

The exe and the `build` folder are not part of the repository. Rebuild them locally.

## Language

The window and the phone page start in English. **EN** and **IT** sit next to the theme switch. The choice is saved on Windows and is used again on the next launch. Reload the phone page after changing it.

## From the phone to the computer

1. Start LocalDrop on the PC.
2. Scan the QR code with the phone camera.
3. The browser warns that the connection is not private. That warning is expected: the certificate is created on this PC for the local network. Continue to the page. Do not turn HTTPS off.
4. If the QR was already used, enter the 8-digit code shown on the computer.
5. Choose the files and press **Send to computer**.
6. On the PC they wait under **From the phone**. Choose which ones to keep, pick the folder, then **Save selected**. **Discard** deletes them.

Saving writes the file into the folder you chose. It does not send it back to the phone.

A file the phone already uploaded stays under **Already sent**. **Send again** uploads it once more without picking it from the gallery.

## From the computer to the phone

1. On the PC, under **To the phone**, press **Choose files**.
2. On the phone, open the page and download the file.
3. For a photo or a video, **Save to Photos** or **Save video to Photos** opens the original.
   * On iPhone, hold the picture or video and choose **Save Image** or **Save Video**. Safari cannot write into Photos by itself.
   * On Android, Chrome downloads the original. Open the download, or save it to the gallery from the browser.

The on-screen preview is a separate image. It does not replace the file. The downloaded bytes are the original ones.

**Clear** removes the files from the phone page. They stay under **Already sent**. **Send again** publishes them without searching for them again.

## Notes

**Notes** is at the bottom of the window. Sharing is off until you turn on **Share notes**. Texts expire on their own. The minutes are in Settings, from 1 to 240, and the default is 5. The original text you copied on the phone or on the PC is not deleted. Only the copy LocalDrop is holding expires.

## The window

From top to bottom:

1. Address, QR code, and access code
2. **From the phone**, for files that just arrived
3. **To the phone**, for files you send
4. Activity
5. Notes

The theme switch chooses dark or light. Dark is the default unless you last chose light.

## Network

It works when the PC is on Ethernet and the phone is on the Wi-Fi of the same router, as long as they are on the same subnet.

The page accepts only addresses on the PC's local network. An outside address is refused. The 8-digit code is a second check, on that same network.

Ports used by the PC:

| Port | Use |
| --- | --- |
| 47823 | Phone page, HTTPS |
| 47821 | UDP discovery, PC-to-PC |
| 47822 | TLS channel between two PCs |

Windows Firewall must allow inbound LocalDrop, including the Public profile when the network is the phone hotspot.

## Security

The phone page is HTTPS. The certificate is self-signed for this computer's local address, so Safari and Chrome show a warning the first time. That warning stays. The QR code carries a short-lived token and the certificate fingerprint. The token survives the browser warning long enough for the page to open, then it is dropped. After that, the session is a cookie. The 8-digit code is the fallback when the QR is no longer valid.

The page refuses clients that are not on the local network. Uploads are stored under random ids, not under the name sent by the phone. The visible name is applied only when you save into the folder you chose.

Keys, the certificate, and paired devices live in `%APPDATA%\LocalDrop`, outside this folder. They do not belong in the repository. The private key is protected with Windows DPAPI.

A PC-to-PC path remains in the code and uses mutual TLS 1.3. The window you see is built for the phone.

## Architecture

* `app/phone` phone page, access code, uploads, previews
* `app/gui` desktop window
* `app/i18n.py` English and Italian text
* `app/controller.py` connects the window to the page
* `app/network` discovery and the PC-to-PC channel
* `app/security` identity, trust, and name checks
* `app/transfer` transfers between two PCs

## Tests

```text
python -m unittest discover -s tests
```

## Temporary limits

These are the current gaps, not a fixed ceiling.

* Folders are not sent yet. Files are.
* The page cannot place a photo into the gallery by itself yet. On iPhone you hold the original and choose Save Image or Save Video. On Android you save the download.
* The cable alone is not a network yet. The phone hotspot has to be on, or both devices have to share a router.

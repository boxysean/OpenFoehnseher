Open Foehnseher
===============

## About

A software knock off of Julian Oliver's piece [Foenseher](http://julianoliver.com/foehnseher/).

This code sniffs for network HTTP image request packets, downloads a copy of image to the images directory, and displays the image on a simple GUI.

## Disclaimer

This software sniffs for packets in promiscuous mode. Know your network terms and conditions before running this software.

## Installation Instructions

1. Grab code
2. Ensure you have libraries libpcap, libcurl, pcre, gtk, and glib
3. Run `make`
4. Run `sudo ./openfoehnseher [network-interface]` (if no network interface is specified, it will pick the first one -- which isn't necessary the right one)

## Usage

This software was tested on OS X 10.5. Libraries installed using [MacPorts](https://www.macports.org/).

The software will run on networks where packets may be openly read. It was tested and works on a WEP network and an open network, however it will not work on WPA networks. [More](http://www.irongeek.com/i.php?page=security/AQuickIntrotoSniffers)

## Open to the reader

This code finds Alice's image URL download request and sends a request to download the same image. One major improvement for this code would be to use the response to Alice's request so as not to duplicate packets and to be a passive listener.


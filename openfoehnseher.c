/*
 * openfoehnseher.c
 *
 * A software knock off of Julian Oliver's piece "Foenseher", by boxysean
 *
 * This code sniffs for network HTTP image request packets, downloads a
 * copy of image to the images directory, and displays the image on a simple
 * GUI.
 *
 * DISCLAIMER: This software sniffs for packets in promiscuous mode. Know
 * your network terms and conditions before running this software.
 *
 * 2011-01-14 boxysean.com
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 */


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcre.h>
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <glib.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*void
print_app_usage(void);*/

int
find_get_request(const u_char *payload, int len, const u_char *url);

int
download_image(const u_char *url, const u_char *filename);

void
make_window(void);

static void
draw_image(GtkWidget *widget, char *filename);

/*
 * find get request in the payload
 */

#define OVECCOUNT 6    /* should be a multiple of 3 */

int ovector_get[OVECCOUNT];
int ovector_host[OVECCOUNT];

int
find_get_request(const u_char *payload, int len, const u_char *url) {
	pcre *re_get, *re_host;
	int rc_get, rc_host;

	const char *error;
	int erroffset;

	re_get = pcre_compile(".*GET (\\S+.(png|PNG|jpg|JPG|gif|GIF)).*", 0, &error, &erroffset, NULL);

	if (re_get == NULL) {
		printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		return 0;
	} 

	re_host = pcre_compile(".*Host: (\\S+).*", 0, &error, &erroffset, NULL);

	if (re_host == NULL) {
		printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
		return 0;
	} 

	rc_get = pcre_exec(re_get, NULL, payload, len, 0, 0, ovector_get, OVECCOUNT);
	rc_host = pcre_exec(re_host, NULL, payload, len, 0, 0, ovector_host, OVECCOUNT);

	if (rc_get < 0 || rc_host < 0) {
		if (rc_get == PCRE_ERROR_NOMATCH || rc_host == PCRE_ERROR_NOMATCH) {
//			printf("No match\n");
		} else {
			printf("Matching error %d, %d\n", rc_get, rc_host);
		}
		free(re_get);     /* Release memory used for the compiled pattern */
		free(re_host);    /* Release memory used for the compiled pattern */
		return 0;
	}

//	printf("\nMatch succeeded at offset %d, %d\n", ovector_get[0], ovector_host[0]);

	sprintf(url, "%.*s%.*s", ovector_host[3] - ovector_host[2], payload + ovector_host[2],
				 ovector_get[3]  - ovector_get[2] , payload + ovector_get[2]);

/*	for (i = 0; i < rc_get; i++) {
		char *substring_start = payload + ovector_get[2*i];
		int substring_length = ovector_get[2*i+1] - ovector_get[2*i];
		printf("%2d: %.*s\n", i, substring_length, substring_start);
	}

	for (i = 0; i < rc_host; i++) {
		char *substring_start = payload + ovector_host[2*i];
		int substring_length = ovector_host[2*i+1] - ovector_host[2*i];
		printf("%2d: %.*s\n", i, substring_length, substring_start);
	}
*/

//	printf("1: %s\n", url);

	return 1;
}

int download_image(const u_char *url, const u_char *filename) {
//	printf("downloading: %s.\n", url);
	CURL *curl;
	CURLcode res;

	int i, end;

	for (i = 0; i < 1024; i++) {
		if (url[i] == 0) {
			end = i;
			break;
		}
	}

	for (; i >= 0; i--) {
		if (url[i] == '/') {
			i++;
			break;
		}
	}

	if (end - i > 64) {
		i = end - 64;
	}

	sprintf(filename, "images/%.*s", end - i, url + i);
	
	// printf("filename: %.*s (%d, %d)\n", end - i, url + i, i, end);

	curl = curl_easy_init();
	
	if (curl) {
		FILE *f;
		f = fopen(filename, "w");
		
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		res = curl_easy_perform(curl);
		
		/* always cleanup */
		curl_easy_cleanup(curl);
		fclose(f);
	}
	
	return 1;
}


void
destroy (void) { 
  gtk_main_quit ();
}

GHashTable *ht;

GtkWidget *window;
GtkWidget *drawing_area;
	

static GdkPixmap *pixmap = NULL;

static gint
configure_event(GtkWidget *widget, GdkEventConfigure *event) {
	if (pixmap) {
		gdk_pixmap_unref(pixmap);
	}

	pixmap = gdk_pixmap_new(widget->window,
				widget->allocation.width,
				widget->allocation.height,
				-1);

	gdk_draw_rectangle(pixmap,
			   widget->style->white_gc,
			   TRUE,
			   0, 0,
			   widget->allocation.width,
			   widget->allocation.height);

	return TRUE;
}

static gint
expose_event(GtkWidget *widget, GdkEventExpose *event) {
	gdk_draw_pixmap(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
			pixmap,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}

static void
draw_image(GtkWidget *widget, char *filename) {
        GError *err = NULL;
        GdkPixbuf *pixbuf;

        pixbuf = gdk_pixbuf_new_from_file(filename, &err);

        if (!pixbuf) {
                printf("error message: %s\n", err->message);
		return;
        }

        int width = gdk_pixbuf_get_width(pixbuf);
        int height = gdk_pixbuf_get_height(pixbuf);

	GdkRectangle update_rect;

	int window_width, window_height;

	gdk_pixmap_get_size(pixmap, &window_width, &window_height);

	update_rect.x = (window_width - width) >> 1;
	update_rect.y = (window_height - height) >> 1;
	update_rect.width = width;
	update_rect.height = height;

	gdk_draw_pixbuf(pixmap,
			widget->style->black_gc,
			pixbuf,
			0, 0,
			update_rect.x, update_rect.y,
			width, height,
			GDK_RGB_DITHER_NORMAL, 0, 0);

	gtk_widget_draw(widget, &update_rect);

        g_object_unref(pixbuf);
}

void make_window(void) {
	int i;

	gtk_init(NULL, NULL);

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(window, "OpenFoehnfeher");
	gtk_signal_connect(GTK_OBJECT (window), "destroy",
	                   GTK_SIGNAL_FUNC (destroy), NULL);

	gtk_window_set_default_size(window, 640, 480);

	drawing_area = gtk_drawing_area_new();
	gtk_drawing_area_size(drawing_area, 640, 480);

	pixmap = gdk_pixmap_new(window, 640, 480, -1);


	gtk_signal_connect(GTK_OBJECT (drawing_area), "expose_event", (GtkSignalFunc) expose_event, NULL);
	gtk_signal_connect(GTK_OBJECT(drawing_area),"configure_event", (GtkSignalFunc) configure_event, NULL);

	gtk_widget_set_events (drawing_area, GDK_EXPOSURE_MASK);

	gtk_container_add(GTK_CONTAINER(window), drawing_area);

	gtk_widget_show(drawing_area);
	gtk_widget_show(window);

	for (i = 0; i < 100; i++) { // arbitrary number of loops to make it work!
		gtk_main_iteration_do(0);
	}

//	gtk_main();
}
	


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	char url[1024];
	char filename[512];

	int i;
	
//	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
//	printf("       From: %s\n", inet_ntoa(ip->ip_src));
//	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	if (ip->ip_p != IPPROTO_TCP) {
		return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
//	printf("   Src port: %d\n", ntohs(tcp->th_sport));
//	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload <= 0) {
		return;
	}

	
//	printf("   Payload (%d bytes):\n", size_payload);
//	print_payload(payload, size_payload);

	if (!find_get_request(payload, size_payload, url)) {
		return;
	}

	// Did we see this URL already?

	if (g_hash_table_lookup(ht, g_strdup(url)) != NULL) {
		g_hash_table_remove(ht, g_strdup(url));
		return;
	}

	g_hash_table_insert(ht, g_strdup(url), g_strdup("placeholder"));

	printf("url %s filename %s\n", url, filename);

	if (!download_image(url, filename)) {
		printf("Could not download image %s\n", url);
		return;
	}

	// display images

	draw_image(drawing_area, filename);

	for (i = 0; i < 100; i++) {
		gtk_main_iteration_do(0);
	}

	return;
}

int main(int argc, char **argv)
{
	make_window();

	ht = g_hash_table_new(g_str_hash, g_str_equal);
	
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "port 80";		/* filter expression [3] */
//	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1 << 30;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
//		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}


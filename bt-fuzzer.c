#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/sco.h>

void hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        
        if (((unsigned char*)data)[i] >= ' ' && 
           ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

void init_rand(uint64_t seed) {
    if (seed == 0) {
        seed = __rdtsc();
    }

    srand(seed);
    printf("Fuzzer initialized with seed: 0x%x\n", seed);
}

int rand_range(int min, int max){
   return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

int open_l2cap_socket(int *psock, bdaddr_t *bdaddr) {
    struct sockaddr_l2 addr;
    socklen_t optlen;

    *psock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
    if (*psock < 0) {
        perror("Can't create socket");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, BDADDR_ANY);

    if (bind(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't bind socket");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, bdaddr);

    if (connect(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't connect");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    optlen = sizeof(addr);

    if (getsockname(*psock, (struct sockaddr *) &addr, &optlen) < 0) {
        perror("Can't get local address");
        goto error;
    }

    char local_dev[18];
    char target_dev[18];
    ba2str(&addr.l2_bdaddr, local_dev);
    ba2str(bdaddr, target_dev);
    printf("Fuzzing remote device %s via local device %s\n", target_dev, local_dev);

    return 0;

    error:
        close(*psock);
        return -1;
}

int open_rfcomm_socket(int *psock, bdaddr_t *bdaddr, int channel) {
    struct sockaddr_rc addr;
    socklen_t optlen;

    *psock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (*psock < 0) {
        perror("Can't create socket");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.rc_family = AF_BLUETOOTH;
    bacpy(&addr.rc_bdaddr, BDADDR_ANY);
    addr.rc_channel = (uint8_t) channel;

    if (bind(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't bind socket");
        goto error;
    }

    bacpy(&addr.rc_bdaddr, bdaddr);

    if (connect(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't connect");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    optlen = sizeof(addr);

    if (getsockname(*psock, (struct sockaddr *) &addr, &optlen) < 0) {
        perror("Can't get local address");
        goto error;
    }

    char local_dev[18];
    char target_dev[18];
    ba2str(&addr.rc_bdaddr, local_dev);
    ba2str(bdaddr, target_dev);
    printf("Fuzzing remote device %s via local device %s\n", target_dev, local_dev);

    return 0;

    error:
        close(*psock);
        return -1;
}

int open_avdtp_socket(sdp_session_t **psession, bdaddr_t *bdaddr) {
    *psession = sdp_connect(BDADDR_ANY, bdaddr, 0);
    if (*psession) {
        return 0;
    } else {
        return -1;
    }
}

int open_sco_socket(int *psock, bdaddr_t *bdaddr) {
    struct sockaddr_sco addr;
    socklen_t optlen;

    *psock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
    if (*psock < 0) {
        perror("Can't create socket");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sco_family = AF_BLUETOOTH;
    bacpy(&addr.sco_bdaddr, BDADDR_ANY);

    if (bind(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't bind socket");
        goto error;
    }

    struct bt_voice opts;

    memset(&opts, 0, sizeof(opts));
    if (rand() % 2 == 0) {
        opts.setting = 0x0060;
    } else {
        opts.setting = 0x0003;
    }

    if (setsockopt(*psock, SOL_BLUETOOTH, BT_VOICE, &opts, sizeof(opts)) < 0) {
        printf("Can't set voice socket option...\n");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sco_family = AF_BLUETOOTH;
    bacpy(&addr.sco_bdaddr, bdaddr);

    if (connect(*psock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Can't connect");
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    optlen = sizeof(addr);

    if (getsockname(*psock, (struct sockaddr *) &addr, &optlen) < 0) {
        perror("Can't get local address");
        goto error;
    }

    struct sco_conninfo conn;
    memset(&conn, 0, sizeof(conn));
    optlen = sizeof(conn);

    if (getsockopt(*psock, SOL_SCO, SCO_CONNINFO, &conn, &optlen) < 0) {
        printf("Can't get SCO connection information\n");
        goto error;
    }

    printf("Connected [handle %d, class 0x%02x%02x%02x]", conn.hci_handle,
        conn.dev_class[2], conn.dev_class[1], conn.dev_class[0]);

    char local_dev[18];
    char target_dev[18];
    ba2str(&addr.sco_bdaddr, local_dev);
    ba2str(bdaddr, target_dev);
    printf("Fuzzing remote device %s via local device %s\n", target_dev, local_dev);

    return 0;

    error:
        close(*psock);
        return -1;
}

void fuzz(uint64_t iterations, bdaddr_t *bdaddr, int proto, int rfcomm_channel, int verbose_flag) {
    int sock;
    uint64_t size;
    sdp_session_t *session;
    char *fuzz_data = NULL;

    if (iterations == -1) {
        iterations = 0xffffffffffffffff;
    }

    switch(proto) {
        case BTPROTO_L2CAP:
            if(open_l2cap_socket(&sock, bdaddr)) {
                perror("open_l2cap_socket");
                goto error;
            }
            break;
        
        case BTPROTO_RFCOMM:
            if(open_rfcomm_socket(&sock, bdaddr, rfcomm_channel)) {
                perror("open_rfcomm_socket");
                goto error;
            }
            break;
        
        case BTPROTO_AVDTP:
            if(open_avdtp_socket(&session, bdaddr)) {
                perror("open_avdtp_socket");
                goto error;
            }
            break;

        case BTPROTO_SCO:
            if(open_sco_socket(&sock, bdaddr)) {
                perror("open_sco_socket");
                goto error;
            }
            break;
    }

    fuzz_data = malloc(512);
    l2cap_cmd_hdr *l2cap_pkt = (l2cap_cmd_hdr *) fuzz_data;

    for (uint64_t i=0; i < iterations; i++) {
        size = rand() % 44;
        while (!size) {
            size = rand() % 44;
        }

        for (int j=0; j < size; j++) {
            fuzz_data[j] = (char) rand();
        }

        if (proto == BTPROTO_L2CAP) {
            // 3.2% chance to go beyond normal defined codes between 0x01-0x11
            if (rand() % 0b11111 == 0b11111) { 
                l2cap_pkt->code = (uint8_t) rand() % 256;
            } else {
                l2cap_pkt->code = (uint8_t) rand_range(0x01, 0x11);
            }

            if (rand() % 2 == 0) {
                l2cap_pkt->ident = (uint8_t) rand() % 256;
            }

            l2cap_pkt->len = htobs(size);
        }

        if (proto == BTPROTO_AVDTP) {
            sock = session->sock;
        }

        if (verbose_flag) {
            printf("Packet %d:\n", i);
            hexdump(fuzz_data, size);
        }

        if (send(sock, fuzz_data, size, 0) <= 0) {
            printf("crash? error? on packet %d\n", i);
            perror("send()");
            hexdump(fuzz_data, size);
            goto error;
            // close(sock);
            // sleep(5);
            // if(open_l2cap_socket(&sock, bdaddr)) {
                // perror("open_l2cap_socket");
                // goto error;
            // }
        }
    }

    printf("Fuzz iterations complete...\n");

    error:
        close(sock);
        if (fuzz_data)
            free(fuzz_data);
}

void usage (FILE *fp, const char *path) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    fprintf (fp, "Usage: %s [options] -p <prototype> -b <XX:XX:XX:XX:XX:XX>\n", basename);
    fprintf (fp, "  -h\tPrint this help and exit\n");
    fprintf (fp, "  -s");
    fprintf (fp, "  \tProvide a fixed seed to reproduce a test case\n");
    fprintf (fp, "  -i");
    fprintf (fp, "  \tNumber of iterations to fuzz \n");
    fprintf (fp, "  -p");
    fprintf (fp, "  \tPrototype socket to fuzz (l2cap, rfcomm, avdtp, sco)\n");
    fprintf (fp, "  -c");
    fprintf (fp, "  \tChannel (Required if rfcomm protocol)\n");
    fprintf (fp, "  -v");
    fprintf (fp, "  \tVerbose\n");
    fprintf (fp, "  -b");
    fprintf (fp, "  \tBluetooth Device Hardware ID to fuzz (XX:XX:XX:XX:XX:XX)\n");
}

int main(int argc, char *argv[]) {
    uint64_t seed = 0;
    int help_flag = 0;
    int opt;
    int iterations = -1;
    int device_flag = 0;
    int n;
    int proto = -1;
    int rfcomm_channel = -1;
    int verbose_flag = 0;
    bdaddr_t bdaddr;

    while (1) {
        opt = getopt(argc, argv, "h:s:i:b:c:p:v::");

        if (opt == -1) {
            break;
        }

        switch (opt) {
            case 'h':
                help_flag = 1;
                break;

            case 's':
                n = sscanf(optarg, "%llx", &seed);
                if (n != 1) {
                    printf("Invalid seed!\n");
                    help_flag = 1;
                }
                break;

            case 'i':
                iterations = atoi(optarg);
                break;

            case 'c':
                rfcomm_channel = atoi(optarg);
                break;

            case 'b':
                if (str2ba(optarg, &bdaddr)) {
                    printf("Invalid baddr!\n");
                    help_flag = 1;
                }
                device_flag = 1;
                break;

            case 'p':
                if (strncmp("l2cap", optarg, 5) == 0) {
                    proto = BTPROTO_L2CAP;
                } else if (strncmp("rfcomm", optarg, 6) == 0) {
                    proto = BTPROTO_RFCOMM;
                } else if (strncmp("avdtp", optarg, 5) == 0) {
                    proto = BTPROTO_AVDTP;
                } else if (strncmp("sco", optarg, 3) == 0) {
                    proto = BTPROTO_SCO;
                } else {
                    printf("Invalid prototype!\n");
                    help_flag = 1;
                }
                break;

            case 'v':
                verbose_flag = 1;
                break;

            case '?':
                usage (stderr, argv[0]);
                return 1;

            default:
                break;
        }
    }

    if (help_flag || !device_flag || proto == -1 || (proto == BTPROTO_RFCOMM && rfcomm_channel == -1)) {
        usage (stdout, argv[0]);
        return 1;
    }

    if(getuid() != 0) {
        printf("root privileges required for RAW socket usage\n");
        return 1;
    }

    init_rand(seed);
    fuzz(iterations, &bdaddr, proto, rfcomm_channel, verbose_flag);

    return 0;
}
/* Test peer for iec104-tls: a lib60870-C outstation or master over TLS
 * (lib60870 built with mbedTLS 3.6), written against lib60870's public API
 * for this crate's interop tests. It runs as a separate process; nothing of
 * lib60870 is part of the crate.
 *
 * usage: tls_peer server|client PORT SECONDS CERT KEY CA [option...]
 *   allow=FILE     accept only this peer certificate (on top of the chain)
 *   version=12|13  TLS 1.2 or 1.3 only
 *   renegotiate=MS TLS 1.2 session renegotiation every MS milliseconds
 *   crl=FILE       check the peer against this CRL
 *   minkey=BITS    minimum peer public key length (lib60870's default is
 *                  2048, which it applies to EC keys too)
 *
 * server: an outstation on 127.0.0.1:PORT, CA 1, answering a station
 *         interrogation with M_ME_NB_1 1234 at IOA 0x0102.
 * client: a master to 127.0.0.1:PORT that starts data transfer, sends a
 *         station interrogation and prints what comes back, then stays
 *         connected for SECONDS, sending a test command every second.
 *
 * Lines on stdout, flushed:
 *   peer: listening | peer: connection opened|closed|activated|deactivated
 *   event: <level> <code> <message>     lib60870's TLS security events
 *   got type=T cot=C [ioa=I value=V]     client: an ASDU received
 *   peer: connect failed | peer: done */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "cs104_slave.h"
#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "tls_config.h"

static CS101_AppLayerParameters al;

static void on_event(void* p, TLSEventLevel level, int code, const char* message, TLSConnection con) {
    printf("event: %d %d %s", level, code, message);
    if (con)
        printf(" (%s)", TLSConfigVersion_toString(TLSConnection_getTLSVersion(con)));
    printf("\n");
    fflush(stdout);
}

static bool gi(void* p, IMasterConnection c, CS101_ASDU asdu, uint8_t qoi) {
    IMasterConnection_sendACT_CON(c, asdu, false);
    CS101_ASDU out = CS101_ASDU_create(al, false, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);
    InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, 0x0102, 1234, IEC60870_QUALITY_GOOD);
    CS101_ASDU_addInformationObject(out, io);
    InformationObject_destroy(io);
    IMasterConnection_sendASDU(c, out);
    CS101_ASDU_destroy(out);
    IMasterConnection_sendACT_TERM(c, asdu);
    return true;
}

static void peer_events(void* p, IMasterConnection c, CS104_PeerConnectionEvent e) {
    const char* name[] = {"opened", "closed", "activated", "deactivated"};
    printf("peer: connection %s\n", e < 4 ? name[e] : "?");
    fflush(stdout);
}

static void client_events(void* p, CS104_Connection c, CS104_ConnectionEvent e) {
    const char* name[] = {"opened", "closed", "activated", "deactivated", "failed"};
    printf("peer: connection %s\n", e < 5 ? name[e] : "?");
    fflush(stdout);
}

static bool on_asdu(void* p, int address, CS101_ASDU asdu) {
    int type = CS101_ASDU_getTypeID(asdu);
    printf("got type=%d cot=%d", type, CS101_ASDU_getCOT(asdu));
    if (type == M_ME_NB_1 && CS101_ASDU_getNumberOfElements(asdu) > 0) {
        InformationObject io = CS101_ASDU_getElement(asdu, 0);
        printf(" ioa=%d value=%d", InformationObject_getObjectAddress(io),
               MeasuredValueScaled_getValue((MeasuredValueScaled) io));
        InformationObject_destroy(io);
    }
    printf("\n");
    fflush(stdout);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 7) return 2;
    bool server = strcmp(argv[1], "server") == 0;
    int port = atoi(argv[2]);
    int seconds = atoi(argv[3]);

    TLSConfiguration tls = TLSConfiguration_create();
    TLSConfiguration_setEventHandler(tls, on_event, NULL);
    TLSConfiguration_setChainValidation(tls, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tls, false);
    if (!TLSConfiguration_setOwnCertificateFromFile(tls, argv[4]) ||
        !TLSConfiguration_setOwnKeyFromFile(tls, argv[5], NULL) ||
        !TLSConfiguration_addCACertificateFromFile(tls, argv[6])) {
        printf("peer: cannot load certificates\n");
        return 3;
    }
    for (int i = 7; i < argc; i++) {
        if (strncmp(argv[i], "allow=", 6) == 0) {
            TLSConfiguration_setAllowOnlyKnownCertificates(tls, true);
            TLSConfiguration_addAllowedCertificateFromFile(tls, argv[i] + 6);
        } else if (strncmp(argv[i], "version=", 8) == 0) {
            TLSConfigVersion v = atoi(argv[i] + 8) == 13 ? TLS_VERSION_TLS_1_3 : TLS_VERSION_TLS_1_2;
            TLSConfiguration_setMinTlsVersion(tls, v);
            TLSConfiguration_setMaxTlsVersion(tls, v);
        } else if (strncmp(argv[i], "renegotiate=", 12) == 0) {
            TLSConfiguration_setRenegotiationTime(tls, atoi(argv[i] + 12));
        } else if (strncmp(argv[i], "minkey=", 7) == 0) {
            TLSConfiguration_setMinimumKeyLength(tls, atoi(argv[i] + 7));
        } else if (strncmp(argv[i], "crl=", 4) == 0) {
            TLSConfiguration_addCRLFromFile(tls, argv[i] + 4);
        } else {
            printf("peer: unknown option %s\n", argv[i]);
            return 2;
        }
    }

    if (server) {
        CS104_Slave slave = CS104_Slave_createSecure(100, 100, tls);
        CS104_Slave_setLocalAddress(slave, "127.0.0.1");
        CS104_Slave_setLocalPort(slave, port);
        al = CS104_Slave_getAppLayerParameters(slave);
        CS104_Slave_setInterrogationHandler(slave, gi, NULL);
        CS104_Slave_setConnectionEventHandler(slave, peer_events, NULL);
        CS104_Slave_start(slave);
        if (!CS104_Slave_isRunning(slave)) {
            printf("peer: failed to start\n");
            return 1;
        }
        printf("peer: listening\n");
        fflush(stdout);
        Thread_sleep(seconds * 1000);
        CS104_Slave_stop(slave);
        CS104_Slave_destroy(slave);
    } else {
        CS104_Connection con = CS104_Connection_createSecure("127.0.0.1", port, tls);
        CS104_Connection_setASDUReceivedHandler(con, on_asdu, NULL);
        CS104_Connection_setConnectionHandler(con, client_events, NULL);
        bool connected = false;
        for (int i = 0; i < 30 && !(connected = CS104_Connection_connect(con)); i++)
            Thread_sleep(100);
        if (!connected) {
            printf("peer: connect failed\n");
            fflush(stdout);
            CS104_Connection_destroy(con);
            TLSConfiguration_destroy(tls);
            return 4;
        }
        CS104_Connection_sendStartDT(con);
        Thread_sleep(300);
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
        for (int s = 0; s < seconds; s++) {
            Thread_sleep(1000);
            struct sCP56Time2a t;
            CP56Time2a_createFromMsTimestamp(&t, Hal_getTimeInMs());
            CS104_Connection_sendTestCommandWithTimestamp(con, 1, (uint16_t) s, &t);
        }
        CS104_Connection_destroy(con);
    }
    TLSConfiguration_destroy(tls);
    printf("peer: done\n");
    fflush(stdout);
    return 0;
}

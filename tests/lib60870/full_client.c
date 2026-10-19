/* Test peer: a lib60870-C master that exercises every procedure against an
 * outstation at 127.0.0.1:PORT, CA 1, and prints what comes back.
 * usage: full_client PORT */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"

static bool on_asdu(void* p, int address, CS101_ASDU asdu) {
    int n = CS101_ASDU_getNumberOfElements(asdu);
    int type = CS101_ASDU_getTypeID(asdu);
    printf("got type=%d cot=%d neg=%d n=%d", type, CS101_ASDU_getCOT(asdu), CS101_ASDU_isNegative(asdu), n);
    for (int i = 0; i < n; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;
        printf(" ioa=%d", InformationObject_getObjectAddress(io));
        if (type == M_ME_NB_1)
            printf(" value=%d", MeasuredValueScaled_getValue((MeasuredValueScaled) io));
        if (type == M_IT_NA_1)
            printf(" total=%d", BinaryCounterReading_getValue(IntegratedTotals_getBCR((IntegratedTotals) io)));
        InformationObject_destroy(io);
    }
    printf("\n");
    fflush(stdout);
    return true;
}

static void pause_ms(int ms) { Thread_sleep(ms); }

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    CS104_Connection con = CS104_Connection_create("127.0.0.1", atoi(argv[1]));
    CS104_Connection_setASDUReceivedHandler(con, on_asdu, NULL);
    for (int i = 0; i < 30 && !CS104_Connection_connect(con); i++) pause_ms(100);
    CS104_Connection_sendStartDT(con);
    pause_ms(300);

    printf("send gi\n"); fflush(stdout);
    CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
    pause_ms(300);
    printf("send ci\n"); fflush(stdout);
    CS104_Connection_sendCounterInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QCC_RQT_GENERAL);
    pause_ms(300);
    printf("send read\n"); fflush(stdout);
    CS104_Connection_sendReadCommand(con, 1, 0x0102);
    pause_ms(300);

    printf("send select\n"); fflush(stdout);
    InformationObject sc = (InformationObject) SingleCommand_create(NULL, 0x0500, true, true, 0);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, sc);
    pause_ms(300);
    printf("send execute\n"); fflush(stdout);
    SingleCommand_create((SingleCommand) sc, 0x0500, true, false, 0);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, sc);
    InformationObject_destroy(sc);
    pause_ms(300);

    printf("send setpoint select\n"); fflush(stdout);
    InformationObject se = (InformationObject) SetpointCommandScaled_create(NULL, 0x0300, -1234, true, 0);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, se);
    pause_ms(300);
    printf("send setpoint execute\n"); fflush(stdout);
    SetpointCommandScaled_create((SetpointCommandScaled) se, 0x0300, -1234, false, 0);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, se);
    InformationObject_destroy(se);
    pause_ms(300);

    printf("send parameter\n"); fflush(stdout);
    InformationObject pm = (InformationObject) ParameterScaledValue_create(NULL, 0x0400, 250, 1);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, pm);
    InformationObject_destroy(pm);
    pause_ms(300);

    struct sCP56Time2a t;
    CP56Time2a_createFromMsTimestamp(&t, Hal_getTimeInMs());
    printf("send test\n"); fflush(stdout);
    CS104_Connection_sendTestCommandWithTimestamp(con, 1, 4242, &t);
    pause_ms(300);
    printf("send clock\n"); fflush(stdout);
    CS104_Connection_sendClockSyncCommand(con, 1, &t);
    pause_ms(300);
    printf("send reset process\n"); fflush(stdout);
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1,
        (InformationObject) ResetProcessCommand_create(NULL, 0, 1));
    pause_ms(500);
    printf("done\n"); fflush(stdout);
    CS104_Connection_destroy(con);
    return 0;
}

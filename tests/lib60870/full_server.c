/* Test peer: a lib60870-C outstation serving every procedure, CA 1.
 * usage: full_server PORT SECONDS
 * One redundancy group (104 cl.10): several connections, one started. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "cs101_file_service.h"
#include "cs104_slave.h"
#include "cs101_information_objects.h"
#include "hal_thread.h"
#include "hal_time.h"

static CS104_Slave slave;
static CS101_AppLayerParameters al;

static void say(const char* what, CS101_ASDU asdu) {
    printf("peer: %s type=%d cot=%d\n", what, CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCOT(asdu));
    fflush(stdout);
}

static bool gi(void* p, IMasterConnection c, CS101_ASDU asdu, uint8_t qoi) {
    say("interrogation", asdu);
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

static bool ci(void* p, IMasterConnection c, CS101_ASDU asdu, QualifierOfCIC qcc) {
    say("counter interrogation", asdu);
    IMasterConnection_sendACT_CON(c, asdu, false);
    CS101_ASDU out = CS101_ASDU_create(al, false, CS101_COT_REQUESTED_BY_GENERAL_COUNTER, 0, 1, false, false);
    struct sBinaryCounterReading bcr;
    BinaryCounterReading_create(&bcr, 4711, 3, false, false, false);
    InformationObject io = (InformationObject) IntegratedTotals_create(NULL, 0x0200, &bcr);
    CS101_ASDU_addInformationObject(out, io);
    InformationObject_destroy(io);
    IMasterConnection_sendASDU(c, out);
    CS101_ASDU_destroy(out);
    IMasterConnection_sendACT_TERM(c, asdu);
    return true;
}

static bool read_handler(void* p, IMasterConnection c, CS101_ASDU asdu, int ioa) {
    say("read", asdu);
    CS101_ASDU out = CS101_ASDU_create(al, false, CS101_COT_REQUEST, 0, 1, false, false);
    InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, ioa, -77, IEC60870_QUALITY_GOOD);
    CS101_ASDU_addInformationObject(out, io);
    InformationObject_destroy(io);
    IMasterConnection_sendASDU(c, out);
    CS101_ASDU_destroy(out);
    return true;
}

static bool clock_handler(void* p, IMasterConnection c, CS101_ASDU asdu, CP56Time2a t) {
    say("clock sync", asdu);
    return true;
}

static bool asdu_handler(void* p, IMasterConnection c, CS101_ASDU asdu) {
    int type = CS101_ASDU_getTypeID(asdu);
    say("asdu", asdu);
    if (CS101_ASDU_getCOT(asdu) != CS101_COT_ACTIVATION)
        return false;
    switch (type) {
    case C_SC_NA_1: case C_SE_NB_1: case C_SE_NC_1: case C_DC_NA_1:
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
        IMasterConnection_sendASDU(c, asdu);
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_TERMINATION);
        IMasterConnection_sendASDU(c, asdu);
        return true;
    case P_ME_NB_1: case P_AC_NA_1:
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
        IMasterConnection_sendASDU(c, asdu);
        return true;
    }
    return false;
}

/* --- one transparent file, 2 sections of 400 octets, at IOA 30000 --- */
static uint8_t sections[2][400];
static uint64_t file_date(CS101_IFileProvider s) { return 0; }
static int file_size(CS101_IFileProvider s) { return 800; }
static int section_size(CS101_IFileProvider s, int n) { return n < 2 ? 400 : 0; }
static bool segment_data(CS101_IFileProvider s, int n, int off, int size, uint8_t* d) {
    if (n > 1) return false;
    for (int i = 0; i < size; i++) d[i] = sections[n][off + i];
    return true;
}
static void transfer_complete(CS101_IFileProvider s, bool ok) {
    printf("peer: file transfer complete ok=%d\n", ok); fflush(stdout);
}
static struct sCS101_IFileProvider file;
static CS101_IFileProvider next_file(void* p, CS101_IFileProvider after) {
    return after == NULL ? &file : NULL;
}
static CS101_IFileProvider get_file(void* p, int ca, int ioa, uint16_t nof, int* err) {
    return (ca == file.ca && ioa == file.ioa) ? &file : NULL;
}

static void events(void* p, IMasterConnection c, CS104_PeerConnectionEvent e) {
    const char* name[] = {"opened", "closed", "activated", "deactivated"};
    printf("peer: connection %s\n", e < 4 ? name[e] : "?"); fflush(stdout);
}

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    for (int n = 0; n < 2; n++)
        for (int i = 0; i < 400; i++) sections[n][i] = (uint8_t)(i * (n + 1));
    slave = CS104_Slave_create(100, 100);
    CS104_Slave_setLocalAddress(slave, "127.0.0.1");
    CS104_Slave_setLocalPort(slave, atoi(argv[1]));
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
    CS104_Slave_setMaxOpenConnections(slave, 4);
    al = CS104_Slave_getAppLayerParameters(slave);
    CS104_Slave_setInterrogationHandler(slave, gi, NULL);
    CS104_Slave_setCounterInterrogationHandler(slave, ci, NULL);
    CS104_Slave_setReadHandler(slave, read_handler, NULL);
    CS104_Slave_setClockSyncHandler(slave, clock_handler, NULL);
    CS104_Slave_setASDUHandler(slave, asdu_handler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, events, NULL);

    file.ca = 1; file.ioa = 30000; file.nof = CS101_NOF_TRANSPARENT_FILE; file.object = NULL;
    file.getFileSize = file_size; file.getFileDate = file_date; file.getSectionSize = section_size;
    file.getSegmentData = segment_data; file.transferComplete = transfer_complete;
    CS101_FileServer fs = CS101_FileServer_create(al);
    struct sCS101_FilesAvailable avail = { .getFile = get_file, .getNextFile = next_file, .parameter = NULL };
    CS101_FileServer_setFilesAvailableIfc(fs, &avail);
    CS104_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(fs));

    CS104_Slave_start(slave);
    if (!CS104_Slave_isRunning(slave)) { printf("peer: failed to start\n"); return 1; }
    printf("peer: listening\n"); fflush(stdout);
    Thread_sleep(atoi(argv[2]) * 1000);
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    CS101_FileServer_destroy(fs);
    return 0;
}

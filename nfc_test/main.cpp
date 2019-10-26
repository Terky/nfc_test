#include <iostream>
#include <ctime>

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>

void print_bytes(BYTE * bytes, BYTE bytes_size)
{
    for (BYTE i=0; i<bytes_size; ++i) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}

int main() {
    // This variavle should have type LONG (according to PCSC documentation)
    // But in macOS it have this type for some reason and it is longer that LONG
    // Constants, that are defining errors, have the same type too
    uint32_t rv;

    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;

    // Connecting to the card
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (rv == SCARD_S_SUCCESS) {
        time_t t = clock();
        // Hardcoded for specific NFC-reader that I have at the moment
        rv = SCardConnect(hContext, "ACS ACR122U PICC Interface", SCARD_SHARE_SHARED,
                          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
        while (rv != SCARD_S_SUCCESS) {
            rv = SCardConnect(hContext, "ACS ACR122U PICC Interface", SCARD_SHARE_SHARED,
                              SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
            double dif = double(clock() - t) / CLOCKS_PER_SEC;
            // Timer
            if (dif > 1) {
                std::cout << "Timeout reached" << std::endl;
                return 1;
            }
        }

        if (rv == SCARD_S_SUCCESS) { // Protocol choosing
            SCARD_IO_REQUEST* request;
            switch (dwActiveProtocol) {
                case SCARD_PROTOCOL_T1:
                    request = SCARD_PCI_T1;
                    break;
                case SCARD_PROTOCOL_T0:
                    request = SCARD_PCI_T0;
                    break;
                default:
                    request = nullptr;
                    break;
            } // Protocol choosing

            // Get UID for ISO
            //BYTE sendBuf[] = { 0x00, 0xA4, 0x04, 0x00, 0x05, 0xF2, 0x22, 0x22, 0x22, 0x22 };
            // Get UID for MIFARE
            //BYTE sendBuf[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };

            /*
            BYTE UID[6];
            DWORD UIDLength = sizeof(UID);
            BYTE getUID[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
            DWORD getUIDLength = sizeof(getUID);
            rv = SCardTransmit(hCard, request, getUID, getUIDLength, NULL, UID, &UIDLength);
            */


            { // Uploading key А
                BYTE loadKeyRes[2];
                DWORD recvBufLength = sizeof(loadKeyRes);
                // After key changing we need to use the same writing order as it was in reading
                BYTE loadKeyCmd[] = { /* Command */ 0xFF, 0x82, 0x00, 0x00,
                                      /* Key length */ 0x06,
                                      /* Key value */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBC };
                DWORD sendBufLength = sizeof(loadKeyCmd);
                rv = SCardTransmit(hCard, request, loadKeyCmd, sendBufLength, NULL, loadKeyRes, &recvBufLength);

                if (rv == SCARD_S_SUCCESS)
                    std::cout << "Load key success" << std::endl;
                else
                    std::cout << "Load key error" << std::endl;
            } // Uploading key А

            { // Sector auth
                BYTE generalAuthRes[2];
                DWORD recvBufLength = sizeof(generalAuthRes);
                // Key type should have first byte = 0x60 in case of using А key and 0x61 in case of В key
                BYTE generalAuthCmd[] = {
                    /* Auth command */ 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00,
                    /* Block address */ 0x13,
                    /* Key type */ 0x61, 0x00
                };
                DWORD sendBufLength = sizeof(generalAuthCmd);

                rv = SCardTransmit(hCard, request, generalAuthCmd, sendBufLength, NULL, generalAuthRes, &recvBufLength);

                if (rv == SCARD_S_SUCCESS)
                    std::cout << "Authenticate success" << std::endl;
                else
                    std::cout << "Authenticate error" << std::endl;
            } // Sector auth

            { // Reading a sector
                // Initializing with zeros for easier error handling
                BYTE readBlockRes[18] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                };
                DWORD recvBufLength = sizeof(readBlockRes);
                BYTE readBlockCmd[] = {
                    /* Command */ 0xFF, 0xB0, 0x00,
                    /* BLock address */ 0x13,
                    /* Expected response length */ 0x10
                };
                // In response 2 bytes should be ingored: SW1 and SW2, that are used for error indication
                // In any case the buffer should have that 2 redundant bytes, otherwise the SCARD_E_INSUFFICIENT_BUFFER error occures
                DWORD sendBufLength = sizeof(readBlockCmd);
                rv = SCardTransmit(hCard, request, readBlockCmd, sendBufLength, NULL, readBlockRes, &recvBufLength);

                // Error handeling
                if (rv == SCARD_S_SUCCESS) {
                    //unsigned int* i = (unsigned int*)UID;
                    std::cout << "Success"/* << *i*/ << std::endl;
                    print_bytes(readBlockRes, recvBufLength);
                } else {
                    switch (rv) {
                        case SCARD_E_INSUFFICIENT_BUFFER:
                            std::cout << "SCARD_E_INSUFFICIENT_BUFFER" << std::endl;
                            break;
                        case SCARD_E_INVALID_HANDLE:
                            std::cout << "SCARD_E_INVALID_HANDLE" << std::endl;
                            break;
                        case SCARD_E_INVALID_PARAMETER:
                            std::cout << "SCARD_E_INVALID_PARAMETER" << std::endl;
                            break;
                        case SCARD_E_INVALID_VALUE:
                            std::cout << "SCARD_E_INVALID_VALUE" << std::endl;
                            break;
                        case SCARD_E_NO_SERVICE:
                            std::cout << "SCARD_E_NO_SERVICE" << std::endl;
                            break;
                        case SCARD_E_NOT_TRANSACTED:
                            std::cout << "SCARD_E_NOT_TRANSACTED" << std::endl;
                            break;
                        case SCARD_E_PROTO_MISMATCH:
                            std::cout << "SCARD_E_PROTO_MISMATCH" << std::endl;
                            break;
                        case SCARD_E_READER_UNAVAILABLE:
                            std::cout << "SCARD_E_READER_UNAVAILABLE" << std::endl;
                            break;
                        case SCARD_F_COMM_ERROR:
                            std::cout << "SCARD_F_COMM_ERROR" << std::endl;
                            break;
                        case SCARD_W_RESET_CARD:
                            std::cout << "SCARD_W_RESET_CARD" << std::endl;
                            break;
                        case SCARD_W_REMOVED_CARD:
                            std::cout << "SCARD_W_REMOVED_CARD" << std::endl;
                            break;
                        default:
                            std::cout << "WHAT?!" << std::endl;
                            break;
                    }
                std::cout << "Transmission error" << std::endl;
                return 1;
            } // Error handeling
        } // Reading a sector

            { // Writing to a sector
                BYTE writeBlockRes[2];
                DWORD recvBufLength = sizeof(writeBlockRes);
                BYTE writeBlockCmd[] = {
                    /* Command */ 0xFF, 0xD6, 0x00,
                    /* Block address */ 0x13,
                    /* New block (blocks) size */ 0x10,
                    /* Blocks (block) to write */
                        /* Key A */ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                        /* Access bits and auxillary info */ 0xFF, 0x07, 0x80, 0x69,
                        /* Key B */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBC
                };
                // Block size should be 0x10 or more, if reqiured to write more than one block
                // Multiple block writing works. with data block only, not with key block
                DWORD sendBufLength = sizeof(writeBlockCmd);
                //rv = SCardTransmit(hCard, request, writeBlockCmd, sendBufLength, NULL, writeBlockRes, &recvBufLength);
                print_bytes(writeBlockRes, recvBufLength);
        } // Writing to a sector

        } else { // Handking card connection error
            std::cout << rv << " Card connection error" << std::endl;
            return 1;
        }
        SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
    } else {
        std::cout << "Establishing connection error" << std::endl;
        return 1;
    } // Connecting to the card
    SCardReleaseContext(hContext);
    
    return 0;
}

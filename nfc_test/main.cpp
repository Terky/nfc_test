#include <iostream>
#include <ctime>

// Только для macOS, для остальных надо искать PCSC
// Для Linux точно есть PCSC-lite
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
    // По идее должен быть тип LONG (если следовать документации PCSC)
    // Но в macOS функция возвращает этот тип
    // Этого же типа константы, которые позволяют определить ошибки
    uint32_t rv;

    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;

    // Соединение с картой
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (rv == SCARD_S_SUCCESS) {
        time_t t = clock();
        rv = SCardConnect(hContext, "ACS ACR122U PICC Interface", SCARD_SHARE_SHARED,
                          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
        while (rv != SCARD_S_SUCCESS) {
            rv = SCardConnect(hContext, "ACS ACR122U PICC Interface", SCARD_SHARE_SHARED,
                              SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
            double dif = double(clock() - t) / CLOCKS_PER_SEC;
            // Таймер
            if (dif > 1) {
                std::cout << "Timeout reached" << std::endl;
                return 1;
            }
        }

        if (rv == SCARD_S_SUCCESS) { // Выбор протокола
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
            } // Выбор протокола

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


            { // Загрузка ключа А
                BYTE loadKeyRes[2];
                DWORD recvBufLength = sizeof(loadKeyRes);
                // После смены ключа, для аутентификации необходимо использовать
                // запись ключа в том же порядке, что и при записи
                BYTE loadKeyCmd[] = { /* Команда */ 0xFF, 0x82, 0x00, 0x00,
                                      /* Длина ключа */ 0x06,
                                      /* Ключ */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBC };
                DWORD sendBufLength = sizeof(loadKeyCmd);
                rv = SCardTransmit(hCard, request, loadKeyCmd, sendBufLength, NULL, loadKeyRes, &recvBufLength);

                if (rv == SCARD_S_SUCCESS)
                    std::cout << "Load key success" << std::endl;
                else
                    std::cout << "Load key error" << std::endl;
            } // Загрузка ключа А

            { // Аутентификация сектора
                BYTE generalAuthRes[2];
                DWORD recvBufLength = sizeof(generalAuthRes);
                // В типе ключа 1 байт = 0x60, если выбран ключ А и 0x61, если ключ В
                BYTE generalAuthCmd[] = {
                    /* Команда на аутентификацию */ 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00,
                    /* Адрес блока */ 0x13,
                    /* Тип ключа */ 0x61, 0x00
                };
                DWORD sendBufLength = sizeof(generalAuthCmd);

                rv = SCardTransmit(hCard, request, generalAuthCmd, sendBufLength, NULL, generalAuthRes, &recvBufLength);

                if (rv == SCARD_S_SUCCESS)
                    std::cout << "Authenticate success" << std::endl;
                else
                    std::cout << "Authenticate error" << std::endl;
            } // Аутентификация сектора

            { // Чтение сектора
                // Записываю нули чтобы было проще отслеживать ошибки
                BYTE readBlockRes[18] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                };
                DWORD recvBufLength = sizeof(readBlockRes);
                BYTE readBlockCmd[] = {
                    /* Команда */ 0xFF, 0xB0, 0x00,
                    /* Адрес блока */ 0x13,
                    /* Ожидаемая длина ответа */ 0x10
                };
                // В ожидаемой длине ответа не учитываются 2 байта SW1 и SW2, указывающие на ошибки при обработке команд
                // При этом длина буфера ответа должна учитывать эти байты, иначе возникает ошибка SCARD_E_INSUFFICIENT_BUFFER
                DWORD sendBufLength = sizeof(readBlockCmd);
                rv = SCardTransmit(hCard, request, readBlockCmd, sendBufLength, NULL, readBlockRes, &recvBufLength);

                // Проверка ошибок чтения сектора
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
            } // Проверка ошибок чтения сектора
        } // Чтение сектора

            { // Запись сектор
                BYTE writeBlockRes[2];
                DWORD recvBufLength = sizeof(writeBlockRes);
                BYTE writeBlockCmd[] = {
                    /* Команда */ 0xFF, 0xD6, 0x00,
                    /* Адрес блока */ 0x13,
                    /* Длина нового блока (блоков) */ 0x10,
                    /* Блок (блоки) на запись */
                        /* Ключ А */ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                        /* Биты доступа и дополнительня информация */ 0xFF, 0x07, 0x80, 0x69,
                        /* Ключ В */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBC
                };
                // Длина блока должна быть равна 0x10 или более, если требуется запись сразу нескольких блоков
                // Запись нескольких блоков работает только для блоков с данными, но не для блоков с ключами
                DWORD sendBufLength = sizeof(writeBlockCmd);
                //rv = SCardTransmit(hCard, request, writeBlockCmd, sendBufLength, NULL, writeBlockRes, &recvBufLength);
                print_bytes(writeBlockRes, recvBufLength);
        } // Запись сектора

        } else { // Проверка ошибок соединения с картой
            std::cout << rv << " Card connection error" << std::endl;
            return 1;
        }
        SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
    } else {
        std::cout << "Establishing connection error" << std::endl;
        return 1;
    } // Соединение с картой
    SCardReleaseContext(hContext);
    
    return 0;
}

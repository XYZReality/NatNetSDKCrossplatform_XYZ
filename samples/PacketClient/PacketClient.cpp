/*
Copyright � 2012 NaturalPoint Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */
/**
 * \page   PacketClient.cpp
 * \file   PacketClient.cpp
 * \brief  Example of how to decode NatNet packets directly. 
 * Decodes NatNet packets directly.
 * Usage [optional]:
 *  PacketClient [ServerIP] [LocalIP]
 *     [ServerIP]			IP address of server ( defaults to local machine)
 *     [LocalIP]			IP address of client ( defaults to local machine)
 */


#include <cstdio>
#include <cinttypes>
#include <string>
#include <map>
#include <cassert>
#include <chrono>
#include <thread>
#include <vector>


#pragma warning( disable : 4996 )

#include <cstring>
#include <cstdlib>
#include <vector>

using std::min;

// non-standard/optional extension of C; define an unsafe version here
// to not change example code below
int strcpy_s(char *dest, size_t destsz, const char *src)
{
    strcpy(dest, src);
    return 0;
}

template <size_t size>
int strcpy_s(char (&dest)[size], const char *src)
{
    return strcpy_s(dest, size, src);
}

template <typename... Args>
int sprintf_s(char *buffer, size_t bufsz, const char *format, Args... args)
{
    return sprintf(buffer, format, args...);
}

#define MAX_NAMELENGTH              256
#define MAX_ANALOG_CHANNELS          32

// NATNET message ids
#define NAT_CONNECT                 0 
#define NAT_SERVERINFO              1
#define NAT_REQUEST                 2
#define NAT_RESPONSE                3
#define NAT_REQUEST_MODELDEF        4
#define NAT_MODELDEF                5
#define NAT_REQUEST_FRAMEOFDATA     6
#define NAT_FRAMEOFDATA             7
#define NAT_MESSAGESTRING           8
#define NAT_DISCONNECT              9
#define NAT_KEEPALIVE               10
#define NAT_UNRECOGNIZED_REQUEST    100
#define UNDEFINED                   999999.9999


#define MAX_PACKETSIZE				100000	// max size of packet (actual packet size is dynamic)

// This should match the multicast address listed in Motive's streaming settings.
#define MULTICAST_ADDRESS		"239.255.42.99"

// Requested size for socket
#define OPTVAL_REQUEST_SIZE 0x10000

// NatNet Command channel
#define PORT_COMMAND            1510

// NatNet Data channel
#define PORT_DATA  			    1511                

int gNatNetVersion[4] = { 0,0,0,0 };
int gNatNetVersionServer[4] = { 0,0,0,0 };
int gServerVersion[4] = { 0,0,0,0 };
char gServerName[MAX_NAMELENGTH] = { 0 };
bool gCanChangeBitstream = false;
bool gBitstreamVersionChanged = false;
bool gBitstreamChangePending = false;

// sender
struct sSender
{
    char szName[MAX_NAMELENGTH];            // sending app's name
    unsigned char Version[4];               // sending app's version [major.minor.build.revision]
    unsigned char NatNetVersion[4];         // sending app's NatNet version [major.minor.build.revision]
};

struct sPacket
{
    unsigned short iMessage;                // message ID (e.g. NAT_FRAMEOFDATA)
    unsigned short nDataBytes;              // Num bytes in payload
    union
    {
        unsigned char  cData[MAX_PACKETSIZE];
        char           szData[MAX_PACKETSIZE];
        unsigned long  lData[MAX_PACKETSIZE / 4];
        float          fData[MAX_PACKETSIZE / 4];
        sSender        Sender;
    } Data;                                 // Payload incoming from NatNet Server
};

struct sConnectionOptions
{
    bool subscribedDataOnly;
    uint8_t BitstreamVersion[4];
#if defined(__cplusplus)
    sConnectionOptions() : subscribedDataOnly( false ), BitstreamVersion{ 0,0,0,0 } {}
#endif
};

// Packet unpacking functions
char* Unpack( char* pPacketIn );
char* UnpackPacketHeader( char* ptr, int& messageID, int& nBytes, int& nBytesTotal );
char* UnpackDataSize(char* ptr, int major, int minor, int& nBytes, bool skip = false );

// Frame data
char* UnpackFrameData( char* inptr, int nBytes, int major, int minor );
char* UnpackFramePrefixData( char* ptr, int major, int minor );
char* UnpackMarkersetData( char* ptr, int major, int minor );
char* UnpackRigidBodyData( char* ptr, int major, int minor );
char* UnpackSkeletonData( char* ptr, int major, int minor );
char* UnpackLabeledMarkerData( char* ptr, int major, int minor );
char* UnpackForcePlateData( char* ptr, int major, int minor );
char* UnpackDeviceData( char* ptr, int major, int minor );
char* UnpackFrameSuffixData(char* ptr, int major, int minor);
char* UnpackAssetData(char* ptr, int major, int minor);
char* UnpackAssetMarkerData(char* ptr, int major, int minor);
char* UnpackAssetRigidBodyData(char* ptr, int major, int minor);
char* UnpackLegacyOtherMarkers(char* ptr, int major, int minor);

// Descriptions
char* UnpackDescription( char* inptr, int nBytes, int major, int minor );
char* UnpackMarkersetDescription( char* ptr, char* targetPtr, int major, int minor );
char* UnpackRigidBodyDescription( char* ptr, char* targetPtr, int major, int minor );
char* UnpackSkeletonDescription( char* ptr, char* targetPtr, int major, int minor );
char* UnpackForcePlateDescription( char* ptr, char* targetPtr, int major, int minor );
char* UnpackDeviceDescription( char* ptr, char* targetPtr, int major, int minor );
char* UnpackCameraDescription(char* ptr, char* targetPtr, int major, int minor);
char* UnpackAssetDescription(char* ptr, char* targetPtr, int major, int minor);
char* UnpackMarkerDescription(char* ptr, char* targetPtr, int major, int minor);

#ifdef ORIGINAL_SDK
/**
* \brief WSA Error codes:
* https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
*/
std::map<int, std::string> wsaErrors = {
    { 10004, " WSAEINTR: Interrupted function call."},
    { 10009, " WSAEBADF: File handle is not valid."},
    { 10013, " WSAEACCESS: Permission denied."},
    { 10014, " WSAEFAULT: Bad address."},
    { 10022, " WSAEINVAL: Invalid argument."},
    { 10024, " WSAEMFILE: Too many open files."},
    { 10035, " WSAEWOULDBLOCK: Resource temporarily unavailable."},
    { 10036, " WSAEINPROGRESS: Operation now in progress."},
    { 10037, " WSAEALREADY: Operation already in progress."},
    { 10038, " WSAENOTSOCK: Socket operation on nonsocket."},
    { 10039, " WSAEDESTADDRREQ Destination address required."},
    { 10040, " WSAEMSGSIZE: Message too long."},
    { 10041, " WSAEPROTOTYPE: Protocol wrong type for socket."},
    { 10047, " WSAEAFNOSUPPORT: Address family not supported by protocol family."},
    { 10048, " WSAEADDRINUSE: Address already in use."},
    { 10049, " WSAEADDRNOTAVAIL: Cannot assign requested address."},
    { 10050, " WSAENETDOWN: Network is down."},
    { 10051, " WSAEWSAENETUNREACH: Network is unreachable."},
    { 10052, " WSAENETRESET: Network dropped connection on reset."},
    { 10053, " WSAECONNABORTED: Software caused connection abort."},
    { 10054, " WSAECONNRESET: Connection reset by peer."},
    { 10060, " WSAETIMEDOUT: Connection timed out."},
    { 10093, " WSANOTINITIALIZED: Successful WSAStartup not yet performed."}
};

/**
 * \brief - Send command to get bitream version.
 * \return - Success or failure.
*/
bool GetBitstreamVersion()
{
    int result = SendCommand( "Bitstream" );
    if( result != 0 )
    {
        printf( "Error getting Bitstream Version" );
        return false;
    }
    return true;
}

/**
 * \brief - Request bitstream version from Motive
 * \param major - Major version
 * \param minor - Minor Version
 * \param revision - Revision
 * \return 
*/

/**
 * .
 * 
 * \param major
 * \param minor
 * \param revision
 * \return 
 */
bool SetBitstreamVersion( int major, int minor, int revision )
{
    gBitstreamChangePending = true;
    char szRequest[512];
    sprintf( szRequest, "Bitstream,%1.1d.%1.1d.%1.1d", major, minor, revision );
    int result = SendCommand( szRequest );
    if( result != 0 )
    {
        printf( "Error setting Bitstream Version" );
        gBitstreamChangePending = false;
        return false;
    }

    // query to confirm
    GetBitstreamVersion();

    return true;
}

/**
 * \brief - Get Windows Sockets error codes as a string.
 * \param errorValue - input error code
 * \return - returns error as a string.
*/
std::string GetWSAErrorString( int errorValue )
{
    // Additional values can be found in Winsock2.h or
    // https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2

    std::string errorString = std::to_string( errorValue );
    // loop over entries in map
    auto mapItr = wsaErrors.begin();
    for( ; mapItr != wsaErrors.end(); ++mapItr )
    {
        if( mapItr->first == errorValue )
        {
            errorString += mapItr->second;
            return errorString;
        }
    }

    // If it gets here, the code is unknown, so show the reference link.																		
    errorString += std::string( " Please see: https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2" );
    return errorString;
}
#endif

/**
 * \brief - make sure the string is printable ascii
 * \param szName - input string
 * \param len - string length
*/
void MakeAlnum( char* szName, int len )
{
    int i = 0, i_max = len;
    szName[len - 1] = 0;
    while( ( i < len ) && ( szName[i] != 0 ) )
    {
        if( szName[i] == 0 )
        {
            break;
        }
        if( isalnum( szName[i] ) == 0 )
        {
            szName[i] = ' ';
        }
        ++i;
    }
}

void buildConnectPacket(std::vector<char> &buffer)
{
    sPacket packet;
    packet.iMessage = NAT_CONNECT;
    // packet.iMessage = NAT_REQUEST_MODELDEF;
    // packet.iMessage = NAT_REQUEST ;
    packet.nDataBytes = 0;
    buffer.resize(4);
    memcpy(buffer.data(), &packet, 4);
}

void UnpackCommand(char *pData)
{
    const sPacket *replyPacket = reinterpret_cast<const sPacket *>(pData);

    // handle command
    switch (replyPacket->iMessage)
    {
    case NAT_MODELDEF:
        Unpack(pData);
        break;
    case NAT_FRAMEOFDATA:
        Unpack(pData);
        break;
    case NAT_SERVERINFO:
        for (int i = 0; i < 4; i++)
        {
            gNatNetVersion[i] = (int)replyPacket->Data.Sender.NatNetVersion[i];
            gServerVersion[i] = (int)replyPacket->Data.Sender.Version[i];
        }
        printf("NatNetVersion: %d.%d.%d.%d\n", gNatNetVersion[0], gNatNetVersion[1], gNatNetVersion[2], gNatNetVersion[3]);
        printf("ServerVersion: %d.%d.%d.%d\n", gServerVersion[0], gServerVersion[1], gServerVersion[2], gServerVersion[3]);
        break;
    // case NAT_RESPONSE:
    //     gCommandResponseSize = PacketIn.nDataBytes;
    //     if(gCommandResponseSize==4)
    //         memcpy(&gCommandResponse, &PacketIn.Data.lData[0], gCommandResponseSize);
    //     else
    //     {
    //         memcpy(&gCommandResponseString[0], &PacketIn.Data.cData[0], gCommandResponseSize);
    //         printf("Response : %s", gCommandResponseString);
    //         gCommandResponse = 0;   // ok
    //     }
    //     break;
    // case NAT_UNRECOGNIZED_REQUEST:
    //     printf("[Client] received 'unrecognized request'\n");
    //     gCommandResponseSize = 0;
    //     gCommandResponse = 1;       // err
    //     break;
    // case NAT_MESSAGESTRING:
    //     printf("[Client] Received message: %s\n", PacketIn.Data.szData);
    //     break;
    default:
        printf("Unknown command response!");
        break;
    }
}

/**
 * \brief Funtion that assigns a time code values to 5 variables passed as arguments
 * Requires an integer from the packet as the timecode and timecodeSubframe
 * \param inTimecode - input time code
 * \param inTimecodeSubframe - input time code sub frame
 * \param hour - output hour
 * \param minute - output minute
 * \param second - output second
 * \param frame - output frame number 0 to 255
 * \param subframe - output subframe number
 * \return - true
*/
bool DecodeTimecode( unsigned int inTimecode, unsigned int inTimecodeSubframe, int* hour, int* minute, int* second, int* frame, int* subframe )
{
    bool bValid = true;

    *hour = ( inTimecode >> 24 ) & 255;
    *minute = ( inTimecode >> 16 ) & 255;
    *second = ( inTimecode >> 8 ) & 255;
    *frame = inTimecode & 255;
    *subframe = inTimecodeSubframe;

    return bValid;
}

/**
 * \brief Takes timecode and assigns it to a string
 * \param inTimecode  - input time code
 * \param inTimecodeSubframe - input time code subframe
 * \param Buffer - output buffer
 * \param BufferSize - output buffer size
 * \return 
*/
bool TimecodeStringify( unsigned int inTimecode, unsigned int inTimecodeSubframe, char* Buffer, int BufferSize )
{
    bool bValid;
    int hour, minute, second, frame, subframe;
    bValid = DecodeTimecode( inTimecode, inTimecodeSubframe, &hour, &minute, &second, &frame, &subframe );

    sprintf_s( Buffer, BufferSize, "%2d:%2d:%2d:%2d.%d", hour, minute, second, frame, subframe );
    for( unsigned int i = 0; i < strlen( Buffer ); i++ )
        if( Buffer[i] == ' ' )
            Buffer[i] = '0';

    return bValid;
}

/**
 * \brief Decode marker ID
 * \param sourceID - input source ID
 * \param pOutEntityID - output entity ID
 * \param pOutMemberID - output member ID
*/
void DecodeMarkerID( int sourceID, int* pOutEntityID, int* pOutMemberID )
{
    if( pOutEntityID )
        *pOutEntityID = sourceID >> 16;

    if( pOutMemberID )
        *pOutMemberID = sourceID & 0x0000ffff;
}

/**
 * \brief Receives pointer to byes of a data description and decodes based on major/minor version
 * \param inptr - input 
 * \param nBytes - input buffer size 
 * \param major - NatNet Major version
 * \param minor - NatNet Minor version
 * \return - pointer to after decoded object
*/
char* UnpackDescription( char* inptr, int nBytes, int major, int minor )
{
    char* ptr = inptr;
    char* targetPtr = ptr + nBytes;
    long long nBytesProcessed = (long long) ptr - (long long) inptr;
    // number of datasets
    int nDatasets = 0; memcpy( &nDatasets, ptr, 4 ); ptr += 4;
    printf( "Dataset Count : %d\n", nDatasets );
    bool errorDetected = false;
    for( int i = 0; i < nDatasets; i++ )
    {
        printf( "Dataset %d\n", i );

        // Determine type and advance
        // The next type entry is inaccurate 
        // if data descriptions are out of date
        int type = 0;
        memcpy( &type, ptr, 4 ); ptr += 4;
        
        // size of data description (in bytes)
        // Unlike frame data, in which all data for a particular type
        // is bundled together, descriptions are not guaranteed to be so,
        // so the size here is per description, not for 'all data of a type'
        int sizeInBytes = 0;
        memcpy(&sizeInBytes, ptr, 4); ptr += 4;

        switch( type )
        {
        case 0: // Markerset
        {
            printf( "Type: 0 Markerset\n" );
            ptr = UnpackMarkersetDescription( ptr, targetPtr, major, minor );
        }
        break;
        case 1: // rigid body
            printf( "Type: 1 Rigid Body\n" );
            ptr = UnpackRigidBodyDescription( ptr, targetPtr, major, minor );
            break;
        case 2: // skeleton
            printf( "Type: 2 Skeleton\n" );
            ptr = UnpackSkeletonDescription( ptr, targetPtr, major, minor );
            break;
        case 3: // force plate
            printf( "Type: 3 Force Plate\n" );
            ptr = UnpackForcePlateDescription( ptr, targetPtr, major, minor );
            break;
        case 4: // device
            printf( "Type: 4 Device\n" );
            ptr = UnpackDeviceDescription( ptr, targetPtr, major, minor );
            break;
        case 5: // camera
            printf( "Type: 5 Camera\n" );
            ptr = UnpackCameraDescription( ptr, targetPtr, major, minor );
            break;
        case 6: // asset
            printf( "Type: 6 Asset\n");
            ptr = UnpackAssetDescription(ptr, targetPtr, major, minor);
            break;
        default: // unknown type
            printf( "Type: %d UNKNOWN\n", type );
            printf( "ERROR: Type decode failure\n" );
            errorDetected = true;
            break;
        }
        if( errorDetected )
        {
            printf( "ERROR: Stopping decode\n" );
            break;
        }
        if( ptr > targetPtr )
        {
            printf( "UnpackDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
            return ptr;
        }
        printf( "\t%d datasets processed of %d\n", ( i + 1 ), nDatasets );
        printf( "\t%lld bytes processed of %d\n", ( (long long) ptr - (long long) inptr ), nBytes );
    }   // next dataset

    return ptr;
}


/**
 * \brief Unpack markerset description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackMarkersetDescription( char* ptr, char* targetPtr, int major, int minor )
{
    // name
    char szName[MAX_NAMELENGTH];
    strcpy_s( szName, ptr );
    int nDataBytes = (int) strlen( szName ) + 1;
    ptr += nDataBytes;
    MakeAlnum( szName, MAX_NAMELENGTH );
    printf( "Markerset Name: %s\n", szName );

    // marker data
    int nMarkers = 0; memcpy( &nMarkers, ptr, 4 ); ptr += 4;
    printf( "Marker Count : %d\n", nMarkers );

    for( int j = 0; j < nMarkers; j++ )
    {
        char szName[MAX_NAMELENGTH];
        strcpy_s( szName, ptr );
        int nDataBytes = (int) strlen( ptr ) + 1;
        ptr += nDataBytes;
        MakeAlnum( szName, MAX_NAMELENGTH );
        printf( "  %3.1d Marker Name: %s\n", j, szName );
        if( ptr > targetPtr )
        {
            printf( "UnpackMarkersetDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
            return ptr;
        }
    }

    return ptr;
}


/**
 * \brief Unpack Rigid Body description and print it.
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackRigidBodyDescription( char* inptr, char* targetPtr, int major, int minor )
{
    char* ptr = inptr;
    int nBytes = 0; // common scratch variable
    if( ( major >= 2 ) || ( major == 0 ) )
    {
        // RB name
        char szName[MAX_NAMELENGTH];
        strcpy_s( szName, ptr );
        ptr += strlen( ptr ) + 1;
        MakeAlnum( szName, MAX_NAMELENGTH );
        printf( "  Rigid Body Name: %s\n", szName );
    }

    int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
    printf( "  RigidBody ID   : %d\n", ID );

    int parentID = 0; memcpy( &parentID, ptr, 4 ); ptr += 4;
    printf( "  Parent ID      : %d\n", parentID );

    // Offsets
    float xoffset = 0; memcpy( &xoffset, ptr, 4 ); ptr += 4;
    float yoffset = 0; memcpy( &yoffset, ptr, 4 ); ptr += 4;
    float zoffset = 0; memcpy( &zoffset, ptr, 4 ); ptr += 4;
    printf( "  Position       : %3.2f, %3.2f, %3.2f\n", xoffset, yoffset, zoffset );

    if( ptr > targetPtr )
    {
        printf( "UnpackRigidBodyDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
        return ptr;
    }

    if( ( major >= 3 ) || ( major == 0 ) )
    {
        int nMarkers = 0; memcpy( &nMarkers, ptr, 4 ); ptr += 4;
        printf( "  Number of Markers : %d\n", nMarkers );
        if( nMarkers > 16000 )
        {
            int nBytesProcessed = (int) ( targetPtr - ptr );
            printf( "UnpackRigidBodyDescription: UNPACK ERROR DETECTED: STOPPING DECODE at %d processed\n",
                nBytesProcessed );
            printf( "                           Unreasonable number of markers\n" );
            return targetPtr + 4;
        }

        if( nMarkers > 0 )
        {

            printf( "  Marker Positions:\n" );
            char* ptr2 = ptr + ( nMarkers * sizeof( float ) * 3 );
            char* ptr3 = ptr2 + ( nMarkers * sizeof( int ) );
            for( int markerIdx = 0; markerIdx < nMarkers; ++markerIdx )
            {
                float xpos, ypos, zpos;
                int32_t label;
                char szMarkerNameUTF8[MAX_NAMELENGTH] = { 0 };
                char szMarkerName[MAX_NAMELENGTH] = { 0 };
                // marker positions
                memcpy( &xpos, ptr, 4 ); ptr += 4;
                memcpy( &ypos, ptr, 4 ); ptr += 4;
                memcpy( &zpos, ptr, 4 ); ptr += 4;

                // Marker Required activeLabels
                memcpy( &label, ptr2, 4 ); ptr2 += 4;

                // Marker Name
                szMarkerName[0] = 0;
                if( ( major >= 4 ) || ( major == 0 ) )
                {
                    strcpy_s( szMarkerName, ptr3 );
                    ptr3 += strlen( ptr3 ) + 1;
                }

                printf( "    %3.1d Marker Label: %3.1d Position: %6.6f %6.6f %6.6f %s\n",
                    markerIdx, label, xpos, ypos, zpos, szMarkerName );
                if( ptr3 > targetPtr )
                {
                    printf( "UnpackRigidBodyDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
                    return ptr3;
                }
            }
            ptr = ptr3; // advance to the end of the labels & marker names
        }
    }

    if( ptr > targetPtr )
    {
        printf( "UnpackRigidBodyDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
        return ptr;
    }
    printf( "UnpackRigidBodyDescription processed %lld bytes\n", ( (long long) ptr - (long long) inptr ) );
    return ptr;
}


/**
 * \brief Unpack skeleton description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackSkeletonDescription( char* ptr, char* targetPtr, int major, int minor )
{
    char szName[MAX_NAMELENGTH];
    // Name
    strcpy_s( szName, ptr );
    ptr += strlen( ptr ) + 1;
    MakeAlnum( szName, MAX_NAMELENGTH );
    printf( "Name: %s\n", szName );

    // ID
    int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
    printf( "ID : %d\n", ID );

    // # of RigidBodies
    int nRigidBodies = 0; memcpy( &nRigidBodies, ptr, 4 ); ptr += 4;
    printf( "RigidBody (Bone) Count : %d\n", nRigidBodies );

    if( ptr > targetPtr )
    {
        printf( "UnpackSkeletonDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
        return ptr;
    }

    for( int i = 0; i < nRigidBodies; i++ )
    {
        printf( "Rigid Body (Bone) %d:\n", i );
        ptr = UnpackRigidBodyDescription( ptr, targetPtr, major, minor );
        if( ptr > targetPtr )
        {
            printf( "UnpackSkeletonDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
            return ptr;
        }
    }
    return ptr;
}


/**
 * \brief Unpack force plate description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackForcePlateDescription( char* ptr, char* targetPtr, int major, int minor )
{
    if( ( major >= 3 ) || ( major == 0 ) )
    {
        // ID
        int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
        printf( "ID : %d\n", ID );

        // Serial Number
        char strSerialNo[128];
        strcpy_s( strSerialNo, ptr );
        ptr += strlen( ptr ) + 1;
        printf( "Serial Number : %s\n", strSerialNo );

        // Dimensions
        float fWidth = 0; memcpy( &fWidth, ptr, 4 ); ptr += 4;
        printf( "Width : %3.2f\n", fWidth );

        float fLength = 0; memcpy( &fLength, ptr, 4 ); ptr += 4;
        printf( "Length : %3.2f\n", fLength );

        // Origin
        float fOriginX = 0; memcpy( &fOriginX, ptr, 4 ); ptr += 4;
        float fOriginY = 0; memcpy( &fOriginY, ptr, 4 ); ptr += 4;
        float fOriginZ = 0; memcpy( &fOriginZ, ptr, 4 ); ptr += 4;
        printf( "Origin : %3.2f,  %3.2f,  %3.2f\n", fOriginX, fOriginY, fOriginZ );

        // Calibration Matrix
        const int kCalMatX = 12;
        const int kCalMatY = 12;
        float fCalMat[kCalMatX][kCalMatY];
        printf( "Cal Matrix\n" );
        for( auto& calMatX : fCalMat )
        {
            printf( "  " );
            for( float& calMatY : calMatX )
            {
                memcpy( &calMatY, ptr, 4 ); ptr += 4;
                printf( "%3.3e ", calMatY );
            }
            printf( "\n" );
        }

        // Corners
        const int kCornerX = 4;
        const int kCornerY = 3;
        float fCorners[kCornerX][kCornerY] = { {0,0,0}, {0,0,0}, {0,0,0}, {0,0,0} };
        printf( "Corners\n" );
        for( auto& fCorner : fCorners )
        {
            printf( "  " );
            for( float& cornerY : fCorner )
            {
                memcpy( &cornerY, ptr, 4 ); ptr += 4;
                printf( "%3.3e ", cornerY );
            }
            printf( "\n" );
        }

        // Plate Type
        int iPlateType = 0; memcpy( &iPlateType, ptr, 4 ); ptr += 4;
        printf( "Plate Type : %d\n", iPlateType );

        // Channel Data Type
        int iChannelDataType = 0; memcpy( &iChannelDataType, ptr, 4 ); ptr += 4;
        printf( "Channel Data Type : %d\n", iChannelDataType );

        // Number of Channels
        int nChannels = 0; memcpy( &nChannels, ptr, 4 ); ptr += 4;
        printf( "  Number of Channels : %d\n", nChannels );
        if( ptr > targetPtr )
        {
            printf( "UnpackSkeletonDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
            return ptr;
        }

        for( int chNum = 0; chNum < nChannels; ++chNum )
        {
            char szName[MAX_NAMELENGTH];
            strcpy_s( szName, ptr );
            int nDataBytes = (int) strlen( szName ) + 1;
            ptr += nDataBytes;
            printf( "    Channel Name %d: %s\n", chNum, szName );
            if( ptr > targetPtr )
            {
                printf( "UnpackSkeletonDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
                return ptr;
            }
        }
    }
    return ptr;
}


/**
 * \brief Unpack device description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackDeviceDescription( char* ptr, char* targetPtr, int major, int minor )
{
    if( ( major >= 3 ) || ( major == 0 ) )
    {
        int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
        printf( "ID : %d\n", ID );

        // Name
        char strName[128];
        strcpy_s( strName, ptr );
        ptr += strlen( ptr ) + 1;
        printf( "Device Name :       %s\n", strName );

        // Serial Number
        char strSerialNo[128];
        strcpy_s( strSerialNo, ptr );
        ptr += strlen( ptr ) + 1;
        printf( "Serial Number :     %s\n", strSerialNo );

        int iDeviceType = 0; memcpy( &iDeviceType, ptr, 4 ); ptr += 4;
        printf( "Device Type :        %d\n", iDeviceType );

        int iChannelDataType = 0; memcpy( &iChannelDataType, ptr, 4 ); ptr += 4;
        printf( "Channel Data Type : %d\n", iChannelDataType );

        int nChannels = 0; memcpy( &nChannels, ptr, 4 ); ptr += 4;
        printf( "Number of Channels : %d\n", nChannels );
        char szChannelName[MAX_NAMELENGTH];

        if( ptr > targetPtr )
        {
            printf( "UnpackDeviceDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
            return ptr;
        }

        for( int chNum = 0; chNum < nChannels; ++chNum )
        {
            strcpy_s( szChannelName, ptr );
            ptr += strlen( ptr ) + 1;
            printf( "  Channel Name %d:     %s\n", chNum, szChannelName );
            if( ptr > targetPtr )
            {
                printf( "UnpackDeviceDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n" );
                return ptr;
            }
        }
    }

    return ptr;
}

/**
 * \brief Unpack camera description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackCameraDescription( char* ptr, char* targetPtr, int major, int minor )
{

    // Name
    char szName[MAX_NAMELENGTH];
    strcpy_s( szName, ptr );
    ptr += strlen( ptr ) + 1;
    MakeAlnum( szName, MAX_NAMELENGTH );
    printf( "Camera Name  : %s\n", szName );

    // Pos
    float cameraPosition[3];
    memcpy( cameraPosition + 0, ptr, 4 ); ptr += 4;
    memcpy( cameraPosition + 1, ptr, 4 ); ptr += 4;
    memcpy( cameraPosition + 2, ptr, 4 ); ptr += 4;
    printf( "  Position   : %3.2f, %3.2f, %3.2f\n",
        cameraPosition[0], cameraPosition[1],
        cameraPosition[2] );

    // Ori
    float cameraOriQuat[4]; // x, y, z, w
    memcpy( cameraOriQuat + 0, ptr, 4 ); ptr += 4;
    memcpy( cameraOriQuat + 1, ptr, 4 ); ptr += 4;
    memcpy( cameraOriQuat + 2, ptr, 4 ); ptr += 4;
    memcpy( cameraOriQuat + 3, ptr, 4 ); ptr += 4;
    printf( "  Orientation: %3.2f, %3.2f, %3.2f, %3.2f\n",
        cameraOriQuat[0], cameraOriQuat[1],
        cameraOriQuat[2], cameraOriQuat[3] );

    return ptr;
}

/**
 * \brief Unpack marker description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackMarkerDescription(char* ptr, char* targetPtr, int major, int minor)
{
    // Name
    char szName[MAX_NAMELENGTH];
    strcpy_s(szName, ptr);
    ptr += strlen(ptr) + 1;
    MakeAlnum(szName, MAX_NAMELENGTH);
    printf("Marker Name : %s\n", szName);

    // ID
    int ID = 0; memcpy(&ID, ptr, 4); ptr += 4;
    printf("ID : %d\n", ID);

    // initial position
    float pos[3];
    memcpy(pos + 0, ptr, 4); ptr += 4;
    memcpy(pos + 1, ptr, 4); ptr += 4;
    memcpy(pos + 2, ptr, 4); ptr += 4;
    printf("  Initial Position   : %3.2f, %3.2f, %3.2f\n",
        pos[0], pos[1], pos[2]);

    // size
    float size = 0;
    memcpy(&size, ptr, 4); ptr += 4;
    printf("size : %.2f\n", size);

    // params
    int16_t params = 0;
    memcpy(&params, ptr, 2); ptr += 2;
    printf("params : %d\n", params);

    return ptr;
}

/**
 * \brief Unpack asset description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackAssetDescription(char* ptr, char* targetPtr, int major, int minor)
{
    char szName[MAX_NAMELENGTH];
    // Name
    strcpy_s(szName, ptr);
    ptr += strlen(ptr) + 1;
    MakeAlnum(szName, MAX_NAMELENGTH);
    printf("Name: %s\n", szName);

    // asset type
    int type = 0; memcpy(&type, ptr, 4); ptr += 4;
    printf("type : %d\n", type);

    // ID
    int ID = 0; memcpy(&ID, ptr, 4); ptr += 4;
    printf("ID : %d\n", ID);

    // # of RigidBodies
    int nRigidBodies = 0; memcpy(&nRigidBodies, ptr, 4); ptr += 4;
    printf("RigidBody (Bone) Count : %d\n", nRigidBodies);

    if (ptr > targetPtr)
    {
        printf("UnpackAssetDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n");
        return ptr;
    }

    for (int i = 0; i < nRigidBodies; i++)
    {
        printf("Rigid Body (Bone) %d:\n", i);
        ptr = UnpackRigidBodyDescription(ptr, targetPtr, major, minor);
        if (ptr > targetPtr)
        {
            printf("UnpackAssetDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n");
            return ptr;
        }
    }

    // # of Markers
    int nMarkers = 0; memcpy(&nMarkers, ptr, 4); ptr += 4;
    printf("Marker Count : %d\n", nMarkers);
    for (int i = 0; i < nMarkers; i++)
    {
        printf("Marker %d:\n", i);
        ptr = UnpackMarkerDescription(ptr, targetPtr, major, minor);
        if (ptr > targetPtr)
        {
            printf("UnpackAssetDescription: UNPACK ERROR DETECTED: STOPPING DECODE\n");
            return ptr;
        }
    }

    return ptr;
}

/**
 * \brief Unpack frame description and print contents
 * \param ptr - input data stream pointer
 * \param targetPtr - pointer to maximum input memory location
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackFrameData( char* inptr, int nBytes, int major, int minor )
{
    char* ptr = inptr;
    
    ptr = UnpackFramePrefixData( ptr, major, minor );
    
    ptr = UnpackMarkersetData( ptr, major, minor );

    ptr = UnpackLegacyOtherMarkers( ptr, major, minor );

    ptr = UnpackRigidBodyData( ptr, major, minor );

    ptr = UnpackSkeletonData( ptr, major, minor );

    ptr = UnpackLabeledMarkerData( ptr, major, minor );

    ptr = UnpackForcePlateData( ptr, major, minor );

    ptr = UnpackDeviceData( ptr, major, minor );

    ptr = UnpackFrameSuffixData( ptr, major, minor );

    return ptr;
}

/**
 * \brief Unpack frame prefix data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackFramePrefixData( char* ptr, int major, int minor )
{
    // Next 4 Bytes is the frame number
    int frameNumber = 0; memcpy( &frameNumber, ptr, 4 ); ptr += 4;
    printf( "Frame #: %3.1d\n", frameNumber );
    return ptr;
}

/**
 * \brief legacy 'other' unlabeled marker and print contents (will be deprecated)
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackLegacyOtherMarkers(char* ptr, int major, int minor)
{
    // First 4 Bytes is the number of Other markers
    int nOtherMarkers = 0; memcpy(&nOtherMarkers, ptr, 4); ptr += 4;
    printf("Other Marker Count : %3.1d\n", nOtherMarkers);

    for (int j = 0; j < nOtherMarkers; j++)
    {
        float x = 0.0f; memcpy(&x, ptr, 4); ptr += 4;
        float y = 0.0f; memcpy(&y, ptr, 4); ptr += 4;
        float z = 0.0f; memcpy(&z, ptr, 4); ptr += 4;
        printf("  Marker %3.1d : [x=%3.2f,y=%3.2f,z=%3.2f]\n", j, x, y, z);
    }

    return ptr;
}

/**
 * \brief Unpack markerset data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackMarkersetData( char* ptr, int major, int minor )
{
    // First 4 Bytes is the number of data sets (markersets, rigidbodies, etc)
    int nMarkerSets = 0; memcpy( &nMarkerSets, ptr, 4 ); ptr += 4;
    printf( "Marker Set Count : %3.1d\n", nMarkerSets );

    // Loop through number of marker sets and get name and data
    for( int i = 0; i < nMarkerSets; i++ )
    {
        // Markerset name
        char szName[MAX_NAMELENGTH];
        strcpy_s( szName, ptr );
        int nDataBytes = (int) strlen( szName ) + 1;
        ptr += nDataBytes;
        // MakeAlnum( szName, MAX_NAMELENGTH );
        printf( "Model Name       : %s\n", szName );

        // marker data
        int nMarkers = 0; memcpy( &nMarkers, ptr, 4 ); ptr += 4;
        printf( "Marker Count     : %3.1d\n", nMarkers );

        for( int j = 0; j < nMarkers; j++ )
        {
            float x = 0; memcpy( &x, ptr, 4 ); ptr += 4;
            float y = 0; memcpy( &y, ptr, 4 ); ptr += 4;
            float z = 0; memcpy( &z, ptr, 4 ); ptr += 4;
            printf( "  Marker %3.1d : [x=%3.2f,y=%3.2f,z=%3.2f]\n", j, x, y, z );
        }
    }

    return ptr;
}


/**
 * \brief Unpack rigid body data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackRigidBodyData( char* ptr, int major, int minor )
{
    // Loop through rigidbodies
    int nRigidBodies = 0;
    memcpy( &nRigidBodies, ptr, 4 ); ptr += 4;
    printf( "Rigid Body Count : %3.1d\n", nRigidBodies );

    for( int j = 0; j < nRigidBodies; j++ )
    {
        // Rigid body position and orientation 
        int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
        float x = 0.0f; memcpy( &x, ptr, 4 ); ptr += 4;
        float y = 0.0f; memcpy( &y, ptr, 4 ); ptr += 4;
        float z = 0.0f; memcpy( &z, ptr, 4 ); ptr += 4;
        float qx = 0; memcpy( &qx, ptr, 4 ); ptr += 4;
        float qy = 0; memcpy( &qy, ptr, 4 ); ptr += 4;
        float qz = 0; memcpy( &qz, ptr, 4 ); ptr += 4;
        float qw = 0; memcpy( &qw, ptr, 4 ); ptr += 4;
        printf( "  RB: %3.1d ID : %3.1d\n", j, ID );
        printf( "    Position    : [%3.2f, %3.2f, %3.2f]\n", x, y, z );
        printf( "    Orientation : [%3.2f, %3.2f, %3.2f, %3.2f]\n", qx, qy, qz, qw );

        // Marker positions removed as redundant (since they can be derived from RB Pos/Ori plus initial offset) in NatNet 3.0 and later to optimize packet size
        if( major < 3 )
        {
            // Associated marker positions
            int nRigidMarkers = 0;  memcpy( &nRigidMarkers, ptr, 4 ); ptr += 4;
            printf( "Marker Count: %d\n", nRigidMarkers );
            int nBytes = nRigidMarkers * 3 * sizeof( float );
            float* markerData = (float*) malloc( nBytes );
            memcpy( markerData, ptr, nBytes );
            ptr += nBytes;

            // NatNet Version 2.0 and later
            if( major >= 2 )
            {
                // Associated marker IDs
                nBytes = nRigidMarkers * sizeof( int );
                int* markerIDs = (int*) malloc( nBytes );
                memcpy( markerIDs, ptr, nBytes );
                ptr += nBytes;

                // Associated marker sizes
                nBytes = nRigidMarkers * sizeof( float );
                float* markerSizes = (float*) malloc( nBytes );
                memcpy( markerSizes, ptr, nBytes );
                ptr += nBytes;

                for( int k = 0; k < nRigidMarkers; k++ )
                {
                    printf( "  Marker %d: id=%d  size=%3.1f  pos=[%3.2f, %3.2f, %3.2f]\n",
                        k, markerIDs[k], markerSizes[k],
                        markerData[k * 3], markerData[k * 3 + 1], markerData[k * 3 + 2] );
                }

                if( markerIDs )
                    free( markerIDs );
                if( markerSizes )
                    free( markerSizes );

            }
            // Print marker positions for all rigid bodies
            else
            {
                int k3;
                for( int k = 0; k < nRigidMarkers; k++ )
                {
                    k3 = k * 3;
                    printf( "  Marker %d: pos = [%3.2f, %3.2f, %3.2f]\n",
                        k, markerData[k3], markerData[k3 + 1], markerData[k3 + 2] );
                }
            }

            if( markerData )
                free( markerData );
        }

        // NatNet version 2.0 and later
        if( ( major >= 2 ) || ( major == 0 ) )
        {
            // Mean marker error
            float fError = 0.0f; memcpy( &fError, ptr, 4 ); ptr += 4;
            printf( "\tMean Marker Error: %3.2f\n", fError );
        }

        // NatNet version 2.6 and later
        if( ( ( major == 2 ) && ( minor >= 6 ) ) || ( major > 2 ) || ( major == 0 ) )
        {
            // params
            short params = 0; memcpy( &params, ptr, 2 ); ptr += 2;
            bool bTrackingValid = params & 0x01; // 0x01 : rigid body was successfully tracked in this frame
            printf( "\tTracking Valid: %s\n", ( bTrackingValid ) ? "True" : "False" );
        }

    } // Go to next rigid body

    return ptr;
}


/**
 * \brief Unpack skeleton data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackSkeletonData( char* ptr, int major, int minor )
{
    // Skeletons (NatNet version 2.1 and later)
    if( ( ( major == 2 ) && ( minor > 0 ) ) || ( major > 2 ) )
    {
        int nSkeletons = 0;
        memcpy( &nSkeletons, ptr, 4 ); ptr += 4;
        printf( "Skeleton Count : %d\n", nSkeletons );

        // Loop through skeletons
        for( int j = 0; j < nSkeletons; j++ )
        {
            // skeleton id
            int skeletonID = 0;
            memcpy( &skeletonID, ptr, 4 ); ptr += 4;
            printf( "  Skeleton %d ID=%d : BEGIN\n", j, skeletonID );

            // Number of rigid bodies (bones) in skeleton
            int nRigidBodies = 0;
            memcpy( &nRigidBodies, ptr, 4 ); ptr += 4;
            printf( "  Rigid Body Count : %d\n", nRigidBodies );

            // Loop through rigid bodies (bones) in skeleton
            for( int k = 0; k < nRigidBodies; k++ )
            {
                // Rigid body position and orientation
                int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
                float x = 0.0f; memcpy( &x, ptr, 4 ); ptr += 4;
                float y = 0.0f; memcpy( &y, ptr, 4 ); ptr += 4;
                float z = 0.0f; memcpy( &z, ptr, 4 ); ptr += 4;
                float qx = 0; memcpy( &qx, ptr, 4 ); ptr += 4;
                float qy = 0; memcpy( &qy, ptr, 4 ); ptr += 4;
                float qz = 0; memcpy( &qz, ptr, 4 ); ptr += 4;
                float qw = 0; memcpy( &qw, ptr, 4 ); ptr += 4;
                printf( "    RB: %3.1d ID : %3.1d\n", k, ID );
                printf( "      Position   : [%3.2f, %3.2f, %3.2f]\n", x, y, z );
                printf( "      Orientation: [%3.2f, %3.2f, %3.2f, %3.2f]\n", qx, qy, qz, qw );

                // Mean marker error (NatNet version 2.0 and later)
                if( major >= 2 )
                {
                    float fError = 0.0f; memcpy( &fError, ptr, 4 ); ptr += 4;
                    printf( "    Mean Marker Error: %3.2f\n", fError );
                }

                // Tracking flags (NatNet version 2.6 and later)
                if( ( ( major == 2 ) && ( minor >= 6 ) ) || ( major > 2 ) || ( major == 0 ) )
                {
                    // params
                    short params = 0; memcpy( &params, ptr, 2 ); ptr += 2;
                    bool bTrackingValid = params & 0x01; // 0x01 : rigid body was successfully tracked in this frame
                }
            } // next rigid body
            printf( "  Skeleton %d ID=%d : END\n", j, skeletonID );

        } // next skeleton
    }

    return ptr;
}

/**
 * \brief Unpack Asset data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackAssetData(char* ptr, int major, int minor)
{
    // Assets ( Motive 3.1 / NatNet 4.1 and greater)
    if (((major == 4) && (minor > 0)) || (major > 4))
    {
        int nAssets = 0;
        memcpy(&nAssets, ptr, 4); ptr += 4;
        printf("Asset Count : %d\n", nAssets);

        int nBytes=0;
        ptr = UnpackDataSize(ptr, major, minor,nBytes);

        for (int i = 0; i < nAssets; i++)
        {
            // asset id
            int assetID = 0;
            memcpy(&assetID, ptr, 4); ptr += 4;
            printf("Asset ID: %d\n", assetID);

            // # of Rigid Bodies
            int nRigidBodies = 0;
            memcpy(&nRigidBodies, ptr, 4); ptr += 4;
            printf("Rigid Bodies ( %d )\n", nRigidBodies);

            // Rigid Body data
            for (int j = 0; j < nRigidBodies; j++)
            {
                ptr = UnpackAssetRigidBodyData(ptr, major, minor);
            }

            // # of Markers
            int nMarkers = 0;
            memcpy(&nMarkers, ptr, 4); ptr += 4;
            printf("Markers ( %d )\n", nMarkers);

            // Marker data
            for (int j = 0; j < nMarkers; j++)
            {
                ptr = UnpackAssetMarkerData(ptr, major, minor);
            }
        }
    }

    return ptr;
}

/**
 * \brief Asset Rigid Body data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackAssetRigidBodyData(char* ptr, int major, int minor)
{
    // Rigid body position and orientation 
    int ID = 0; memcpy(&ID, ptr, 4); ptr += 4;
    float x = 0.0f; memcpy(&x, ptr, 4); ptr += 4;
    float y = 0.0f; memcpy(&y, ptr, 4); ptr += 4;
    float z = 0.0f; memcpy(&z, ptr, 4); ptr += 4;
    float qx = 0; memcpy(&qx, ptr, 4); ptr += 4;
    float qy = 0; memcpy(&qy, ptr, 4); ptr += 4;
    float qz = 0; memcpy(&qz, ptr, 4); ptr += 4;
    float qw = 0; memcpy(&qw, ptr, 4); ptr += 4;
    printf("  RB ID : %d\n", ID);
    printf("    Position    : [%3.2f, %3.2f, %3.2f]\n", x, y, z);
    printf("    Orientation : [%3.2f, %3.2f, %3.2f, %3.2f]\n", qx, qy, qz, qw);

    // Mean error
    float fError = 0.0f; memcpy(&fError, ptr, 4); ptr += 4;
    printf("    Mean err: %3.2f\n", fError);

    // params
    short params = 0; memcpy(&params, ptr, 2); ptr += 2;
    printf("    params : %d\n", params);

    return ptr;
}

/**
 * \brief Asset marker data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackAssetMarkerData(char* ptr, int major, int minor)
{
    // ID
    int ID = 0;
    memcpy(&ID, ptr, 4); ptr += 4;

    // X
    float x = 0.0f;
    memcpy(&x, ptr, 4); ptr += 4;

    // Y
    float y = 0.0f;
    memcpy(&y, ptr, 4); ptr += 4;

    // Z
    float z = 0.0f;
    memcpy(&z, ptr, 4); ptr += 4;

    // size
    float size = 0.0f;
    memcpy(&size, ptr, 4); ptr += 4;

    // params
    int16_t params = 0;
    memcpy(&params, ptr, 2); ptr += 2;

    // residual
    float residual = 0.0f;
    memcpy(&residual, ptr, 4); ptr += 4;

    printf("  Marker %d\t(pos=(%3.2f, %3.2f, %3.2f)\tsize=%3.2f\terr=%3.2f\tparams=%d\n",
                ID, x, y, z, size, residual, params);

    return ptr;
}

/**
 * \brief Unpack labeled marker data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackLabeledMarkerData( char* ptr, int major, int minor )
{
    // labeled markers (NatNet version 2.3 and later)
// labeled markers - this includes all markers: Active, Passive, and 'unlabeled' (markers with no asset but a PointCloud ID)
    if( ( ( major == 2 ) && ( minor >= 3 ) ) || ( major > 2 ) )
    {
        int nLabeledMarkers = 0;
        memcpy( &nLabeledMarkers, ptr, 4 ); ptr += 4;
        printf( "Labeled Marker Count : %d\n", nLabeledMarkers );

        // Loop through labeled markers
        for( int j = 0; j < nLabeledMarkers; j++ )
        {
            // id
            // Marker ID Scheme:
            // Active Markers:
            //   ID = ActiveID, correlates to RB ActiveLabels list
            // Passive Markers: 
            //   If Asset with Legacy Labels
            //      AssetID 	(Hi Word)
            //      MemberID	(Lo Word)
            //   Else
            //      PointCloud ID
            int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;
            int modelID, markerID;
            DecodeMarkerID( ID, &modelID, &markerID );


            // x
            float x = 0.0f; memcpy( &x, ptr, 4 ); ptr += 4;
            // y
            float y = 0.0f; memcpy( &y, ptr, 4 ); ptr += 4;
            // z
            float z = 0.0f; memcpy( &z, ptr, 4 ); ptr += 4;
            // size
            float size = 0.0f; memcpy( &size, ptr, 4 ); ptr += 4;

            // NatNet version 2.6 and later
            if( ( ( major == 2 ) && ( minor >= 6 ) ) || ( major > 2 ) || ( major == 0 ) )
            {
                // marker params
                short params = 0; memcpy( &params, ptr, 2 ); ptr += 2;
                bool bOccluded = ( params & 0x01 ) != 0;     // marker was not visible (occluded) in this frame
                bool bPCSolved = ( params & 0x02 ) != 0;     // position provided by point cloud solve
                bool bModelSolved = ( params & 0x04 ) != 0;  // position provided by model solve
                if( ( major >= 3 ) || ( major == 0 ) )
                {
                    bool bHasModel = ( params & 0x08 ) != 0;     // marker has an associated asset in the data stream
                    bool bUnlabeled = ( params & 0x10 ) != 0;    // marker is 'unlabeled', but has a point cloud ID
                    bool bActiveMarker = ( params & 0x20 ) != 0; // marker is an actively labeled LED marker
                }
            }

            // NatNet version 3.0 and later
            float residual = 0.0f;
            if( ( major >= 3 ) || ( major == 0 ) )
            {
                // Marker residual
                memcpy( &residual, ptr, 4 ); ptr += 4;
                residual *= 1000.0;
            }

            printf( "%3.1d ID  : [MarkerID: %d] [ModelID: %d]\n", j, markerID, modelID );
            printf( "    pos : [%3.2f, %3.2f, %3.2f]\n", x, y, z );
            printf( "    size: [%3.2f]\n", size );
            printf( "    err:  [%3.2f]\n", residual );
        }
    }
    return ptr;
}

/**
 * \brief Unpack number of bytes of data for a given data type. 
 * Useful if you want to skip this type of data. 
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackDataSize(char* ptr, int major, int minor, int& nBytes, bool skip /*= false*/ )
{
    nBytes = 0;

    // size of all data for this data type (in bytes);
    if (((major == 4) && (minor > 0)) || (major > 4))
    {
        memcpy(&nBytes, ptr, 4); ptr += 4;
        printf("Byte Count: %d\n", nBytes);
        if (skip)
        {
            ptr += nBytes;
        }
    }
    return ptr;
}

/**
 * \brief Unpack force plate data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackForcePlateData( char* ptr, int major, int minor )
{
    // Force Plate data (NatNet version 2.9 and later)
    if( ( ( major == 2 ) && ( minor >= 9 ) ) || ( major > 2 ) )
    {
        int nForcePlates;
        const int kNFramesShowMax = 4;
        memcpy( &nForcePlates, ptr, 4 ); ptr += 4;
        printf( "Force Plate Count: %d\n", nForcePlates );

        for( int iForcePlate = 0; iForcePlate < nForcePlates; iForcePlate++ )
        {
            // ID
            int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;

            // Channel Count
            int nChannels = 0; memcpy( &nChannels, ptr, 4 ); ptr += 4;

            printf( "Force Plate %3.1d ID: %3.1d Num Channels: %3.1d\n", iForcePlate, ID, nChannels );

            // Channel Data
            for( int i = 0; i < nChannels; i++ )
            {
                printf( "  Channel %d : ", i );
                int nFrames = 0; memcpy( &nFrames, ptr, 4 ); ptr += 4;
                printf( "  %3.1d Frames - Frame Data: ", nFrames );

                // Force plate frames
                int nFramesShow = min( nFrames, kNFramesShowMax );
                for( int j = 0; j < nFrames; j++ )
                {
                    float val = 0.0f;  memcpy( &val, ptr, 4 ); ptr += 4;
                    if( j < nFramesShow )
                        printf( "%3.2f   ", val );
                }
                if( nFramesShow < nFrames )
                {
                    printf( " showing %3.1d of %3.1d frames", nFramesShow, nFrames );
                }
                printf( "\n" );
            }
        }
    }
    return ptr;
}


/**
 * \brief Unpack device data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackDeviceData( char* ptr, int major, int minor )
{
    // Device data (NatNet version 3.0 and later)
    if( ( ( major == 2 ) && ( minor >= 11 ) ) || ( major > 2 ) )
    {
        const int kNFramesShowMax = 4;
        int nDevices;
        memcpy( &nDevices, ptr, 4 ); ptr += 4;
        printf( "Device Count: %d\n", nDevices );

        for( int iDevice = 0; iDevice < nDevices; iDevice++ )
        {
            // ID
            int ID = 0; memcpy( &ID, ptr, 4 ); ptr += 4;

            // Channel Count
            int nChannels = 0; memcpy( &nChannels, ptr, 4 ); ptr += 4;

            printf( "Device %3.1d      ID: %3.1d Num Channels: %3.1d\n", iDevice, ID, nChannels );

            // Channel Data
            for( int i = 0; i < nChannels; i++ )
            {
                printf( "  Channel %d : ", i );
                int nFrames = 0; memcpy( &nFrames, ptr, 4 ); ptr += 4;
                printf( "  %3.1d Frames - Frame Data: ", nFrames );
                // Device frames
                int nFramesShow = min( nFrames, kNFramesShowMax );
                for( int j = 0; j < nFrames; j++ )
                {
                    float val = 0.0f;  memcpy( &val, ptr, 4 ); ptr += 4;
                    if( j < nFramesShow )
                        printf( "%3.2f   ", val );
                }
                if( nFramesShow < nFrames )
                {
                    printf( " showing %3.1d of %3.1d frames", nFramesShow, nFrames );
                }
                printf( "\n" );
            }
        }
    }

    return ptr;
}

/**
 * \brief Unpack suffix data and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackFrameSuffixData( char* ptr, int major, int minor )
{

    // software latency (removed in version 3.0)
    // if( major < 3 )
    // {
    //     float softwareLatency = 0.0f; memcpy( &softwareLatency, ptr, 4 );	ptr += 4;
    //     printf( "software latency : %3.3f\n", softwareLatency );
    // }

    // timecode
    unsigned int timecode = 0; 	memcpy( &timecode, ptr, 4 );	ptr += 4;
    unsigned int timecodeSub = 0; memcpy( &timecodeSub, ptr, 4 ); ptr += 4;
    char szTimecode[128] = "";
    TimecodeStringify( timecode, timecodeSub, szTimecode, 128 );

    // timestamp
    double timestamp = 0.0f;

    // NatNet version 2.7 and later - increased from single to double precision
    if( ( ( major == 2 ) && ( minor >= 7 ) ) || ( major > 2 ) )
    {
        memcpy( &timestamp, ptr, 8 ); ptr += 8;
    }
    else
    {
        float fTemp = 0.0f;
        memcpy( &fTemp, ptr, 4 ); ptr += 4;
        timestamp = (double) fTemp;
    }
    printf( "Timestamp : %3.3f\n", timestamp );

    // high res timestamps (version 3.0 and later)
    if( ( major >= 3 ) || ( major == 0 ) )
    {
        uint64_t cameraMidExposureTimestamp = 0;
        memcpy( &cameraMidExposureTimestamp, ptr, 8 ); ptr += 8;
        printf( "Mid-exposure timestamp         : %" PRIu64"\n", cameraMidExposureTimestamp );

        uint64_t cameraDataReceivedTimestamp = 0;
        memcpy( &cameraDataReceivedTimestamp, ptr, 8 ); ptr += 8;
        printf( "Camera data received timestamp : %" PRIu64"\n", cameraDataReceivedTimestamp );

        uint64_t transmitTimestamp = 0;
        memcpy( &transmitTimestamp, ptr, 8 ); ptr += 8;
        printf( "Transmit timestamp             : %" PRIu64"\n", transmitTimestamp );
    }

    // // precision timestamps (optionally present) (NatNet 4.1 and later)
    // if (((major == 4) && (minor > 0)) || (major > 4) || (major == 0))
    // {
    //     uint32_t PrecisionTimestampSecs = 0;
    //     memcpy(&PrecisionTimestampSecs, ptr, 4); ptr += 4;
    //     printf("Precision timestamp seconds : %d\n", PrecisionTimestampSecs);

    //     uint32_t PrecisionTimestampFractionalSecs = 0;
    //     memcpy(&PrecisionTimestampFractionalSecs, ptr, 4); ptr += 4;
    //     printf("Precision timestamp fractional seconds : %d\n", PrecisionTimestampFractionalSecs);
    // }

    // frame params
    short params = 0;  memcpy( &params, ptr, 2 ); ptr += 2;
    bool bIsRecording = ( params & 0x01 ) != 0;                  // 0x01 Motive is recording
    bool bTrackedModelsChanged = ( params & 0x02 ) != 0;         // 0x02 Actively tracked model list has changed
    bool bLiveMode = ( params & 0x03 ) != 0;                     // 0x03 Live or Edit mode
    gBitstreamVersionChanged = ( params & 0x04 ) != 0;           // 0x04 Bitstream syntax version has changed
    if( gBitstreamVersionChanged )
        gBitstreamChangePending = false;

    // end of data tag
    int eod = 0; memcpy( &eod, ptr, 4 ); ptr += 4;
    /*End Packet*/

    return ptr;
}

/**
 * \brief Unpack packet header and print contents
 * \param ptr - input data stream pointer
 * \param major - NatNet major version
 * \param minor - NatNet minor version
 * \return - pointer after decoded object
*/
char* UnpackPacketHeader( char* ptr, int& messageID, int& nBytes, int& nBytesTotal )
{
    // First 2 Bytes is message ID
    memcpy( &messageID, ptr, 2 ); ptr += 2;

    // Second 2 Bytes is the size of the packet
    memcpy( &nBytes, ptr, 2 ); ptr += 2;
    nBytesTotal = nBytes + 4;
    return ptr;
}


/**
 *      Receives pointer to bytes that represent a packet of data
 *
 *      There are lots of print statements that show what
 *      data is being stored
 *
 *      Most memcpy functions will assign the data to a variable.
 *      Use this variable at your descretion.
 *      Variables created for storing data do not exceed the
 *      scope of this function.
 * 
 * \brief Unpack data stream and print contents
 * \param ptr - input data stream pointer
 * \return - pointer after decoded object
*/
char* Unpack( char* pData )
{
    // Checks for NatNet Version number. Used later in function. 
    // Packets may be different depending on NatNet version.
    int major = gNatNetVersion[0];
    int minor = gNatNetVersion[1];
    bool packetProcessed = true;
    char* ptr = pData;

    printf( "Begin Packet\n-----------------\n" );
    printf( "NatNetVersion %d %d %d %d\n",
        gNatNetVersion[0], gNatNetVersion[1],
        gNatNetVersion[2], gNatNetVersion[3] );

    int messageID = 0;
    int nBytes = 0;
    int nBytesTotal = 0;
    ptr = UnpackPacketHeader( ptr, messageID, nBytes, nBytesTotal );

    switch( messageID )
    {
    case NAT_CONNECT:
        printf( "Message ID  : %d NAT_CONNECT\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_SERVERINFO:
        printf( "Message ID  : %d NAT_SERVERINFO\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_REQUEST:
        printf( "Message ID  : %d NAT_REQUEST\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_RESPONSE:
        printf( "Message ID  : %d NAT_RESPONSE\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_REQUEST_MODELDEF:
        printf( "Message ID  : %d NAT_REQUEST_MODELDEF\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_MODELDEF:
        // Data Descriptions
    {
        printf( "Message ID  : %d NAT_MODELDEF\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        ptr = UnpackDescription( ptr, nBytes, major, minor );
    }
    break;
    case NAT_REQUEST_FRAMEOFDATA:
        printf( "Message ID  : %d NAT_REQUEST_FRAMEOFDATA\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_FRAMEOFDATA:
    {
        // FRAME OF MOCAP DATA packet
        printf("Message ID  : %d NAT_FRAMEOFDATA\n", messageID);
        printf("Packet Size : %d\n", nBytes);
        
        // Extract frame data flags (last 2 bytes in packet)
        uint16_t params;
        char* ptrToParams = ptr + ( nBytes - 6 );                     // 4 bytes for terminating 0 + 2 bytes for params
        memcpy( &params, ptrToParams, 2 );
        bool bIsRecording = ( params & 0x01 ) != 0;                   // 0x01 Motive is recording
        bool bTrackedModelsChanged = ( params & 0x02 ) != 0;          // 0x02 Actively tracked model list has changed
        bool bLiveMode = ( params & 0x04 ) != 0;                      // 0x03 Live or Edit mode
        gBitstreamVersionChanged = ( params & 0x08 ) != 0;            // 0x04 Bitstream syntax version has changed
        if( gBitstreamChangePending )
        {
            printf( "========================================================================================\n" );
            printf( " BITSTREAM CHANGE IN - PROGRESS\n" );
            if( gBitstreamVersionChanged )
            {
                gBitstreamChangePending = false;
                printf( "  -> Bitstream Changed\n" );
            }
            else
            {
                printf( "   -> Skipping Frame\n" );
                packetProcessed = false;
            }
        }
        if( !gBitstreamChangePending )
        {
            ptr = UnpackFrameData( ptr, nBytes, major, minor );
            packetProcessed = true;
        }
    }
    break;
    case NAT_MESSAGESTRING:
        printf( "Message ID  : %d NAT_MESSAGESTRING\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_DISCONNECT:
        printf( "Message ID  : %d NAT_DISCONNECT\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_KEEPALIVE:
        printf( "Message ID  : %d NAT_KEEPALIVE\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    case NAT_UNRECOGNIZED_REQUEST:
        printf( "Message ID  : %d NAT_UNRECOGNIZED_REQUEST\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
        break;
    default:
    {
        printf( "Unrecognized Packet Type.\n" );
        printf( "Message ID  : %d\n", messageID );
        printf( "Packet Size : %d\n", nBytes );
    }
    break;
    }

    printf( "End Packet\n-----------------\n" );

    // check for full packet processing
    if( packetProcessed )
    {
        long long nBytesProcessed = (long long) ptr - (long long) pData;
        if( nBytesTotal != nBytesProcessed )
        {
            printf( "WARNING: %d expected but %lld bytes processed\n",
                nBytesTotal, nBytesProcessed );
            if( nBytesTotal > nBytesProcessed )
            {
                int count = 0, countLimit = 8 * 25;// put on 8 byte boundary
                printf( "Sample of remaining bytes:\n" );
                char* ptr_start = ptr;
                int nCount = (int) nBytesProcessed;
                char tmpChars[9] = { "        " };
                int charPos = ( (long long) ptr % 8 );
                char tmpChar;
                // add spaces for first row
                if( charPos > 0 )
                {
                    for( int i = 0; i < charPos; ++i )
                    {
                        printf( "   " );
                        if( i == 4 )
                        {
                            printf( "    " );
                        }
                    }
                }
                countLimit = countLimit - ( charPos + 1 );
                while( nCount < nBytesTotal )
                {
                    tmpChar = ' ';
                    if( isalnum( *ptr ) )
                    {
                        tmpChar = *ptr;
                    }
                    tmpChars[charPos] = tmpChar;
                    printf( "%2.2x ", (unsigned char) *ptr );
                    ptr += 1;
                    charPos = (long long) ptr % 8;
                    if( charPos == 0 )
                    {
                        printf( "    " );
                        for( int i = 0; i < 8; ++i )
                        {
                            printf( "%c", tmpChars[i] );
                        }
                        printf( "\n" );
                    }
                    else if( charPos == 4 )
                    {
                        printf( "    " );
                    }
                    if( ++count > countLimit )
                    {
                        break;
                    }
                    ++nCount;
                }
                if( (long long) ptr % 8 )
                {
                    printf( "\n" );
                }
            }
        }
    }

    // return the beginning of the possible next packet
    // assuming no additional termination
    ptr = pData + nBytesTotal;
    return ptr;
}

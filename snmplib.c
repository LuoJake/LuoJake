#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "w5500.h"
#include "socket.h"
#include "ctype.h"

//#include "config.h"

#include "snmplib.h"
#include "snmpdemo.h"

#define SOCK_SNMP	      3

struct messageStruct request_msg;
struct messageStruct response_msg;

uint8 errorStatus, errorIndex;
uint8 non_repeaters, max_repetitions;

#define COPY_SEGMENT_TEMP2014(x) \
{ \
	request_msg.index += seglen; \
	memcpy(&response_msg.buffer[response_msg.index], &request_msg.buffer[x.start], seglen ); \
	response_msg.index += seglen; \
}

void WDEBUG(char *fmt, ...)
{
	char zlog_string[100];
	va_list ap;	

	va_start(ap, fmt);
	vsprintf(zlog_string, fmt, ap);
	strcat(zlog_string, "\r\n");
	printf(zlog_string);	
	va_end(ap);	
}

int32 findEntry(uint8 *oid, int32 len)
{
	int32 i;

	for (i = 0 ; i < maxData ; i++)
	{
		if (len == snmpData[i].oidlen)
		{
			if (!memcmp(snmpData[i].oid, oid, len)) return(i);
		}
	}

	return OID_NOT_FOUND;
}


int32 getOID(int32 id, uint8 *oid, uint8 *len)
{
	int32 j;

	if (!((id >= 0) && (id < maxData))) return INVALID_ENTRY_ID;

	*len = snmpData[id].oidlen;

	for (j = 0 ; j < *len ; j++)
	{
		oid[j] = snmpData[id].oid[j];
	}

	return SUCCESS;
}


int32 getValue( uint8 *vptr, int32 vlen)
{
	int32 index = 0;
	int32 value = 0;

	while (index < vlen)
	{
		if (index != 0) value <<= 8;
		value |= vptr[index++];
	}

	return value;
}


int32 getEntry(int32 id, uint8 *dataType, void *ptr, int32 *len)
{
	if (!((id >= 0) && (id < maxData))) return INVALID_ENTRY_ID;

	*dataType = snmpData[id].dataType;

	switch(*dataType)
	{
	case SNMPDTYPE_OCTET_STRING :
	case SNMPDTYPE_OBJ_ID :
		{
			uint8 *string = ptr;
			int32 j;

			if (snmpData[id].getfunction != NULL)
			{
				snmpData[id].getfunction( (void *)&snmpData[id].u.octetstring, &snmpData[id].dataLen );
			}

			// if ( (*dataType)==SNMPDTYPE_OCTET_STRING )
			// {
			// 	snmpData[id].dataLen = (uint8)strlen((int8*)&snmpData[id].u.octetstring);
			// }

			*len = snmpData[id].dataLen;
			for (j = 0 ; j < *len ; j++)
			{
				string[j] = snmpData[id].u.octetstring[j];
			}
		}
		break;

	case SNMPDTYPE_INTEGER :
	case SNMPDTYPE_TIME_TICKS :
	case SNMPDTYPE_COUNTER :
	case SNMPDTYPE_GAUGE :
		{
			int32 *value = ( int32 * )ptr;

			if (snmpData[id].getfunction != NULL)
			{
				snmpData[id].getfunction( (void *)&snmpData[id].u.intval, &snmpData[id].dataLen );
			}

			*len = sizeof(uint32);
			*value = HTONL(snmpData[id].u.intval);
		}
		break;

	default : 
		return INVALID_DATA_TYPE;
	}

	return SUCCESS;
}


int32 setEntry(int32 id, void *val, int32 vlen, uint8 dataType, int32 index)
{

	int32 retStatus=OID_NOT_FOUND;
	int32 j;

	if (snmpData[id].dataType != dataType)
	{
		errorStatus = BAD_VALUE; 
		errorIndex = index;
		return INVALID_DATA_TYPE;
	}

	if(snmpData[id].type == read_only)
	{
		errorStatus = READ_ONLY; 
		errorIndex = index;
		return INVALID_DATA_TYPE;
	}

	if((dataType == SNMPDTYPE_INTEGER && vlen > 4) || (dataType == SNMPDTYPE_OCTET_STRING && vlen > 40))
	{
		errorStatus = TOO_BIG;
		errorIndex = index;
		return INVALID_DATA_TYPE;
	}
	
	switch(snmpData[id].dataType)
	{
	case SNMPDTYPE_OCTET_STRING :
	case SNMPDTYPE_OBJ_ID :
		{
			// if(vlen > 40)
			// {
            //     errorStatus = BAD_VALUE;
            //     errorIndex = index;
            //     return ILLEGAL_LENGTH; // 
			// }
			uint8 *string = val;
			for (j = 0 ; j < vlen ; j++)
			{
				snmpData[id].u.octetstring[j] = string[j];
			}
			// if(vlen != MAX_STRING)
			// {
			// 	snmpData[id].u.octetstring[vlen] = '\0';
			// }
			snmpData[id].dataLen = vlen;
		}
		retStatus = SUCCESS;
		break;

	case SNMPDTYPE_INTEGER :
	case SNMPDTYPE_TIME_TICKS :
	case SNMPDTYPE_COUNTER :
	case SNMPDTYPE_GAUGE :
		{
			// if (vlen > 4) \
            // {
            //     errorStatus = BAD_VALUE;
            //     errorIndex = index;
            //     return ILLEGAL_LENGTH; \
            // }
			
			snmpData[id].u.intval = getValue( (uint8 *)val, vlen);
			snmpData[id].dataLen = vlen;

			if (snmpData[id].setfunction != NULL)
			{
				snmpData[id].setfunction(snmpData[id].u.intval);
			}

		}
		retStatus = SUCCESS;
		break;

	default : 
		retStatus = INVALID_DATA_TYPE;
		break;

	}

	return retStatus;
}


int32 parseLength(const uint8 *msg, int32 *len)
{
	int32 i=1;

	if (msg[0] & 0x80)
	{
		int32 tlen = (msg[0] & 0x7f) - 1;
		*len = msg[i++];

		while (tlen--)
		{
			*len <<= 8;
			*len |= msg[i++];
		}
	}
	else
	{
		*len = msg[0];
	}

	return i;
}


int32 parseTLV(const uint8 *msg, int32 index, tlvStructType *tlv)
{
	int32 Llen = 0;

	tlv->start = index;

	Llen = parseLength((const uint8 *)&msg[index+1], &tlv->len );

	tlv->vstart = index + Llen + 1;

	switch (msg[index])
	{
	case SNMPDTYPE_SEQUENCE:
	case GET_REQUEST:
	case GET_NEXT_REQUEST:
	case SET_REQUEST:
		tlv->nstart = tlv->vstart;
		break;
	default:
		tlv->nstart = tlv->vstart + tlv->len;
		break;
	}

	return 0;
}


// void insertRespLen(int32 reqStart, int32 respStart, int32 size)
// {
// 	int32 indexStart, lenLength;
// 	uint32 mask = 0xff;
// 	int32 shift = 0;

// 	if (request_msg.buffer[reqStart+1] & 0x80)
// 	{
// 		lenLength = request_msg.buffer[reqStart+1] & 0x7f;
// 		indexStart = respStart+2;

// 		while (lenLength--)
// 		{
// 			response_msg.buffer[indexStart+lenLength] = 
// 				(uint8)((size & mask) >> shift);
// 			shift+=8;
// 			mask <<= shift;
// 		}
// 	}
// 	else
// 	{
// 		response_msg.buffer[respStart+1] = (uint8)(size & 0xff);
// 	}
// }

void insertRespLen(int32 respStart, int32 size)
{
	response_msg.buffer[respStart + 1] = 0x82;
	for(int i=1; i<3;i++)
	{
		response_msg.buffer[respStart + 1 + i] = (uint8)(size >> (8 * (2-i)));
	}
}

int32 parsebulkVarBind(int32 reqType, int32 index)
{
	int32 seglen = 0, id;
	tlvStructType name, value;
	int32 size = 0;

	extern const int32 maxData;

	if ( request_msg.buffer[request_msg.index] != SNMPDTYPE_SEQUENCE ) return -1;
	request_msg.index += 2;

	parseTLV(request_msg.buffer, request_msg.index, &name);
	seglen = name.nstart - name.start;

	if ( request_msg.buffer[request_msg.index] != SNMPDTYPE_OBJ_ID ) return -1;

	id = findEntry(&request_msg.buffer[name.vstart], name.len);

	int bulkCount = 0;

	uint8 dataType;
	int32 datalen, namelen;
		
	if(id == OID_NOT_FOUND)
	{
		response_msg.buffer[response_msg.index] = SNMPDTYPE_SEQUENCE_OF; //30
		int32 len_index = response_msg.index+1; //len
		response_msg.index += 2; 

		id = OID_NOT_FOUND;

		COPY_SEGMENT_TEMP2014(name);
		size += seglen;

		parseTLV(request_msg.buffer, request_msg.index, &value);

		seglen = value.nstart - value.start;
		COPY_SEGMENT_TEMP2014(value);
		size += seglen;

		response_msg.buffer[len_index] = size;

		errorIndex = index;
		errorStatus = NO_SUCH_NAME;

		size += 2;
		return size;
	}

	if(++id == maxData)
	{
		response_msg.buffer[response_msg.index] = SNMPDTYPE_SEQUENCE_OF; //30
		int32 len_index = response_msg.index+1; //len
		response_msg.index += 2; 

		id = END_OID;

		COPY_SEGMENT_TEMP2014(name);
		size += seglen;

		parseTLV(request_msg.buffer, request_msg.index, &value);

		seglen = value.nstart - value.start;
		// COPY_SEGMENT_TEMP2014(value);
		request_msg.index += seglen;
		response_msg.buffer[response_msg.index++] = End_of_Mib_View;
		response_msg.buffer[response_msg.index++] = 0x00;
		size += seglen;

		response_msg.buffer[len_index] = size;
		size += 2;
		return size;
	}
	request_msg.index += seglen;
	while(bulkCount < max_repetitions && id < maxData && id >= 0)
	{
		response_msg.buffer[response_msg.index] = SNMPDTYPE_SEQUENCE_OF; //30
		int32 len_index = response_msg.index+1;
		response_msg.index += 2; //len
		
		size += 2;

		response_msg.buffer[response_msg.index] = SNMPDTYPE_OBJ_ID;
		//get the next oid to the response for get next request
		getOID(id, &response_msg.buffer[response_msg.index+2], &response_msg.buffer[response_msg.index+1]);

		namelen = response_msg.buffer[response_msg.index+1];

		seglen = response_msg.buffer[response_msg.index+1]+2;
		response_msg.index += seglen ;
		size += seglen;

		getEntry(id, &dataType, &response_msg.buffer[response_msg.index+2], &datalen);

		response_msg.buffer[len_index] = (namelen + 2) + (datalen + 2);

		response_msg.buffer[response_msg.index] = dataType;
		response_msg.buffer[response_msg.index+1] = datalen;
		seglen = (2 + datalen);
		response_msg.index += seglen;
		size += seglen;

		bulkCount++;
		id++;
	}	
	parseTLV(request_msg.buffer, request_msg.index, &value);
	seglen = value.nstart - value.start;
	request_msg.index += seglen;
	return size;
}   

int32 parseVarBind(const int32 reqType, int32 index)// pase variable-bindings
{
	int32 seglen = 0, id;
	tlvStructType name, value;
	int32 size = 0;
	
	extern const int32 maxData;

	parseTLV(request_msg.buffer, request_msg.index, &name);

	if ( request_msg.buffer[name.start] != SNMPDTYPE_OBJ_ID ) return -1;

	id = findEntry(&request_msg.buffer[name.vstart], name.len);
        // find the number in the snmpData[]

	//  name
    if ((reqType == GET_REQUEST) || (reqType == SET_REQUEST))
	{
		seglen = name.nstart - name.start;
		COPY_SEGMENT_TEMP2014(name);
		size = seglen;
	}
	else if (reqType == GET_NEXT_REQUEST)
	{
		response_msg.buffer[response_msg.index] = request_msg.buffer[name.start];

		if (++id == maxData)
		{
			id = END_OID;
			seglen = name.nstart - name.start;
			COPY_SEGMENT_TEMP2014(name);
			size = seglen;
		}
		else if(id == OID_NOT_FOUND)
		{
			seglen = name.nstart - name.start;
			COPY_SEGMENT_TEMP2014(name);
			size = seglen;
		}
		else
		{
			request_msg.index += name.nstart - name.start;

			//get the next oid to the response for get next request
            getOID(id, &response_msg.buffer[response_msg.index+2], &response_msg.buffer[response_msg.index+1]);

			seglen = response_msg.buffer[response_msg.index+1]+2;
			response_msg.index += seglen ;
			size = seglen;
		}
	}
        // varible value
	parseTLV(request_msg.buffer, request_msg.index, &value);
       
	if (id != OID_NOT_FOUND && id != END_OID)// find this oid
	{
		uint8 dataType;
		int32 len;
                //get  entry
		if ((reqType == GET_REQUEST) || (reqType == GET_NEXT_REQUEST))
		{
                  
			getEntry(id, &dataType, &response_msg.buffer[response_msg.index+2], &len);

			response_msg.buffer[response_msg.index] = dataType;
			response_msg.buffer[response_msg.index+1] = len;
			seglen = (2 + len);
			response_msg.index += seglen;

			request_msg.index += (value.nstart - value.start);

		}
                //set entry  run the set fuciton 
		else if (reqType == SET_REQUEST)
		{
			setEntry(id, &request_msg.buffer[value.vstart], value.len, request_msg.buffer[value.start], index);
			seglen = value.nstart - value.start;
			COPY_SEGMENT_TEMP2014(value);
		}
	}
	else if(id == END_OID)//not find
	{
		seglen = value.nstart - value.start;
		// COPY_SEGMENT_TEMP2014(value);
		request_msg.index += seglen;
		response_msg.buffer[response_msg.index++] = End_of_Mib_View;
		response_msg.buffer[response_msg.index++] = 0x00;

		// errorIndex = index;
		// errorStatus = NO_SUCH_NAME;
	}
	else if(id == OID_NOT_FOUND)
	{
		seglen = value.nstart - value.start;
		COPY_SEGMENT_TEMP2014(value);

		errorIndex = index;
		errorStatus = NO_SUCH_NAME;
	}

	size += seglen;

	return size;
}


int32 parseSequence(const int32 reqType, int32 index) // parese sequence
{
	int32 seglen;
	tlvStructType seq;
	int32 size = 0, respLoc;

	parseTLV(request_msg.buffer, request_msg.index, &seq);

	if ( request_msg.buffer[seq.start] != SNMPDTYPE_SEQUENCE ) return -1;

	if(reqType == GET_BULK_REQUEST)
	{
		//seglen = seq.vstart - seq.start;
		size = parsebulkVarBind(reqType, index);
		//size += seglen;
		return size;
	}

	seglen = seq.vstart - seq.start;
	respLoc = response_msg.index;
	COPY_SEGMENT_TEMP2014(seq);
	response_msg.index += 2;

	size = parseVarBind( reqType, index );// parese  variable binding

	// insertRespLen(seq.start, respLoc, size);
	insertRespLen(respLoc, size);
	size += seglen + 2;

	return size;
}


int32 parseSequenceOf(const int32 reqType)// parse
{
	int32 seglen;
	tlvStructType seqof;
	int32 size = 0, respLoc;
	int32 index = 0;

	parseTLV(request_msg.buffer, request_msg.index, &seqof);

	if ( request_msg.buffer[seqof.start] != SNMPDTYPE_SEQUENCE_OF ) return -1;

	seglen = seqof.vstart - seqof.start;
	respLoc = response_msg.index;
	COPY_SEGMENT_TEMP2014(seqof);
	response_msg.index += 2;

	//why
	while (request_msg.index < request_msg.len)
	{
		size += parseSequence( reqType, index++ );
	}

	// insertRespLen(seqof.start, respLoc, size);
	
	insertRespLen(respLoc, size);
	size += 4;
	return size;
}


int32 parseRequest()
{
	int32 ret, seglen;
	tlvStructType snmpreq, requestid, errStatus, errIndex, nonRepeaters, maxRepetitions;
	int32 size = 0, respLoc, reqType, len_errstatus, len_errindex;

	parseTLV(request_msg.buffer, request_msg.index, &snmpreq);

	reqType = request_msg.buffer[snmpreq.start];

	if ( !VALID_REQUEST(reqType) ) return -1;

	//seglen = snmpreq.vstart - snmpreq.start;
	response_msg.buffer[response_msg.index] = GET_RESPONSE;
	respLoc = response_msg.index;
	//size += seglen + 2;
	//COPY_SEGMENT_TEMP2014(snmpreq);
	response_msg.index += 4;
	request_msg.index += 2;

	parseTLV(request_msg.buffer, request_msg.index, &requestid);
	seglen = requestid.nstart - requestid.start;
	size += seglen;
	COPY_SEGMENT_TEMP2014(requestid);// requestid 

	if(reqType == GET_BULK_REQUEST)
	{
		parseTLV(request_msg.buffer, request_msg.index, &nonRepeaters);
		non_repeaters = request_msg.buffer[nonRepeaters.vstart];
		seglen = nonRepeaters.vstart - nonRepeaters.start;
		size += seglen;

		len_errstatus = response_msg.index + 2;

		COPY_SEGMENT_TEMP2014(nonRepeaters);// nonRepeaters

		response_msg.buffer[response_msg.index] = NO_ERROR;
		response_msg.index += 1;
		request_msg.index += 1;
		size += 1;

		parseTLV(request_msg.buffer, request_msg.index, &maxRepetitions);
		max_repetitions = request_msg.buffer[maxRepetitions.vstart];
		seglen = maxRepetitions.vstart - maxRepetitions.start;
		size += seglen;

		len_errindex = response_msg.index + 2;

		COPY_SEGMENT_TEMP2014(maxRepetitions);// errindex

		response_msg.buffer[response_msg.index] = NO_ERROR;
		response_msg.index += 1;
		request_msg.index += 1;
		size += 1;
	}
	else
	{
		parseTLV(request_msg.buffer, request_msg.index, &errStatus);
		seglen = errStatus.nstart - errStatus.start;
		size += seglen;

		len_errstatus = response_msg.index + 2;

		COPY_SEGMENT_TEMP2014(errStatus);// errstatus

		parseTLV(request_msg.buffer, request_msg.index, &errIndex);
		seglen = errIndex.nstart - errIndex.start;
		size += seglen;

		len_errindex = response_msg.index + 2;

		COPY_SEGMENT_TEMP2014(errIndex);// errindex
	}

	ret = parseSequenceOf(reqType); //parse sequence 
	if (ret == -1) return -1;
	else size += ret;

	// insertRespLen(snmpreq.start, respLoc, size);
	insertRespLen(respLoc, size);
	size += 4;

	if (errorStatus)
	{
			response_msg.buffer[len_errstatus] = errorStatus;
			response_msg.buffer[len_errindex] = errorIndex + 1;
	}

	return size;
}

int32 parseCommunity()
{
	int32 seglen;
	tlvStructType community;
	int32 size=0;

	dataEntryType enterprise_oid = {read_only, 8, {0x2b, 6, 1, 4, 1, 0, 0x10, 0}, SNMPDTYPE_OBJ_ID, 8,{"\x2b\x06\x01\x04\x01\x00\x10\x00"}, NULL, NULL};

	parseTLV(request_msg.buffer, request_msg.index, &community);

	if (!(request_msg.buffer[community.start] == SNMPDTYPE_OCTET_STRING)) 
	{
		return -1;
	}

	if (!memcmp(&request_msg.buffer[community.vstart], (int8 *)COMMUNITY, COMMUNITY_SIZE))
	{
		seglen = community.nstart - community.start;  //community 字�?�所有长�?tlv
		size += seglen;
		COPY_SEGMENT_TEMP2014(community);

		size += parseRequest();// parse request
	}
	else
	{
		//发送authenticationFailure trap
		uint32 a = 150;
		uint32 *ptr = &a;
		SnmpXTrapSend("192.168.12.113", "192.168.12.114", "public", enterprise_oid, authenticationFailure, 0, ptr, 0);
		return -1;
	}

	return size;
}


int32 parseVersion()//parse version
{
	int32 size = 0, seglen;
	tlvStructType tlv;

	size = parseTLV(request_msg.buffer, request_msg.index, &tlv);

	if (!((request_msg.buffer[tlv.start] == SNMPDTYPE_INTEGER) && (request_msg.buffer[tlv.vstart] == SNMP_V1|| request_msg.buffer[tlv.vstart] == SNMP_V2)))
		return -1;

	seglen = tlv.nstart - tlv.start;
	size += seglen;
	COPY_SEGMENT_TEMP2014(tlv);
	size = parseCommunity();

	if (size == -1) return size;
	else return (size + seglen);
}


int32 parseSNMPMessage()
{
	int32 size = 0, seglen, respLoc;
	tlvStructType tlv;

	parseTLV(request_msg.buffer, request_msg.index, &tlv);

	if (request_msg.buffer[tlv.start] != SNMPDTYPE_SEQUENCE_OF) return -1;

	seglen = tlv.vstart - tlv.start;
	respLoc = tlv.start;
	COPY_SEGMENT_TEMP2014(tlv);
	response_msg.index += 2;

	size = parseVersion();

	if (size == -1) return -1;
	// else size += seglen;

	// insertRespLen(tlv.start, respLoc, size);
	insertRespLen(respLoc, size);

	return 0;
}


void dumpCode(int8* header, int8* tail, unsigned char *buff, int len) 
{ 
	int i;

	//printf(header);

	for (i=0; i<len; i++) 
	{ 
		if ( i%16==0 )	printf("0x%04x : ", i); 
		printf("%02x ",buff[i]); 

		if ( i%16-15==0 )
		{
			int j; 
			printf("  "); 
			for (j=i-15; j<=i; j++)
			{
				if ( isprint(buff[j]) )	printf("%c", buff[j]);
				else					printf(".");
			}
			printf("\r\n"); 
		} 
	}

	if ( i%16!=0 ) 
	{ 
		int j; 
		int spaces=(len-i+16-i%16)*3+2; 
		for (j=0; j<spaces; j++) 	printf(" ");
		for (j=i-i%16; j<len; j++) 
		{
			if ( isprint(buff[j]) )	printf("%c", buff[j]);
			else					printf(".");
		}
	} 
	printf(tail);
} 

void ipToByteArray(int8 *ip, uint8 *pDes)
{
	uint32 i, ip1=0, ip2=0, ip3=0, ip4=0;
	int8 buff[32];
	uint32 len = (uint32)strlen(ip);
	strcpy(buff, ip);

	for (i=0; i<len; i++)
	{
		if ( buff[i]=='.' )		buff[i] = ' ';
	}

	sscanf(buff, "%u %u %u %u", &ip1, &ip2, &ip3, &ip4);
	pDes[0] = ip1; pDes[1] = ip2; pDes[2] = ip3; pDes[3] = ip4;
}


int32 makeTrapVariableBindings(dataEntryType *oid_data, void *ptr, uint32 *len)
{
	uint32 j;

	((uint8*)ptr)[0] = 0x30;
	((uint8*)ptr)[1] = 0xff;
	((uint8*)ptr)[2] = 0x06;
	((uint8*)ptr)[3] = oid_data->oidlen;

	for (j = 0 ; j < oid_data->oidlen ; j++)
	{
		((uint8*)ptr)[j+4] = oid_data->oid[j];
	}

	switch(oid_data->dataType)
	{
	case SNMPDTYPE_OCTET_STRING :
	case SNMPDTYPE_OBJ_ID :
		{
			uint8 *string = &((uint8*)ptr)[4+oid_data->oidlen+2];

			if ( oid_data->dataType==SNMPDTYPE_OCTET_STRING )
			{
				oid_data->dataLen = (uint8)strlen((int8*)&oid_data->u.octetstring);
			}
			for (j = 0 ; j < oid_data->dataLen ; j++)
			{
				string[j] = oid_data->u.octetstring[j];
			}

			((uint8*)ptr)[4+oid_data->oidlen] = oid_data->dataType;
			((uint8*)ptr)[4+oid_data->oidlen+1] = oid_data->dataLen;
			((uint8*)ptr)[1] = 2 + oid_data->oidlen + 2 + oid_data->dataLen;
			*len = 4 + oid_data->oidlen + 2 + oid_data->dataLen;
		}
		break;

	case SNMPDTYPE_INTEGER :
	case SNMPDTYPE_TIME_TICKS :
	case SNMPDTYPE_COUNTER :
	case SNMPDTYPE_GAUGE :
		{
			oid_data->dataLen = 4;

			*(int32*)(&((uint8*)ptr)[4+oid_data->oidlen+2]) = HTONL(oid_data->u.intval);

			((uint8*)ptr)[4+oid_data->oidlen] = oid_data->dataType;
			((uint8*)ptr)[4+oid_data->oidlen+1] = oid_data->dataLen;
			((uint8*)ptr)[1] = 2 + oid_data->oidlen + 2 + oid_data->dataLen;
			*len = 4 + oid_data->oidlen + 2 + oid_data->dataLen;
		}
		break;

	default : 
		return INVALID_DATA_TYPE;
	}

	return SUCCESS;
}

int32 SnmpXInit()
{
#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int32 err = 0;

	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		WDEBUG("WSAStartup failed with error: %d", err);
		return 1;
	}
#endif

	initTable();
	return 0;
}

uint8 encodeObjectID(uint8 *ID, uint32* objectID, uint8 length) {
    int i = 0;
    uint8 index = 0;
    
    // Encode first two IDs
    ID[index++] = objectID[0] * 40 + objectID[1];

    // Encode subsequent IDs
    for (i = 2; i < length; i++) {
        if (objectID[i] < 128) {
            ID[index] = objectID[i];
            index++; // 使用固定的索引位�?进�?�赋�?
        } else {
            int value = objectID[i];
            int bytes[4];
            int j = 0;
            // Split the value into 7-bit chunks
            do {
                bytes[j] = value & 0x7F;
                value >>= 7;
                j++;
            } while (value > 0);
            
            // Encode the bytes
            for (j = j - 1; j >= 0; j--) {
                if (j > 0) {
                    bytes[j] |= 0x80; // Set the MSB for all but the last byte
                }
                ID[index] = bytes[j];
                index++; // 使用固定的索引位进行赋值
            }
        }
    }
    return index;
}

uint8 packet_trap[1024] = {0,};
int32 SnmpXTrapSend(int8* managerIP, int8* agentIP, int8* community, dataEntryType enterprise_oid, uint32 genericTrap, uint32 specificTrap, uint32 *timestamp, uint32 va_count, ...)
{
	uint32 i;
	int32 packet_index = 0;
	int32 packet_buff1 = 0;
	int32 packet_buff2 = 0;
	int32 packet_buff3 = 0;
	uint8 trap_agentip[4] = {0,};
	
	ipToByteArray(agentIP, trap_agentip);// change to byte array

	packet_trap[packet_index++] = 0x30; // ASN.1 Header

	packet_trap[packet_index] = 0xff; // pdu_length, temp
	packet_buff1 = packet_index++;

	packet_trap[packet_index++] = 0x02; // Version
	packet_trap[packet_index++] = 0x01; // length
	packet_trap[packet_index++] = 0x00; // Value
	//packet_trap[packet_index++] = 0x01; // Value
	
	packet_trap[packet_index++] = 0x04; // Community
	packet_trap[packet_index++] = (uint8)strlen(community);
	memcpy(&(packet_trap[packet_index]), community, strlen(community));

	packet_index = packet_index + (uint8)strlen(community);

	packet_trap[packet_index++] = 0xa4; // trap
	packet_trap[packet_index] = 0xff; // length, temp
	packet_buff2 = packet_index++;

	packet_trap[packet_index++] = 0x06; // enterprise_oid
	packet_trap[packet_index++] = enterprise_oid.oidlen;
	for (i=0; i<enterprise_oid.oidlen; i++)
	{
		packet_trap[packet_index++] = enterprise_oid.oid[i];
	}
	
	packet_trap[packet_index++] = 0x40; // agent ip
	packet_trap[packet_index++] = 0x04;
	packet_trap[packet_index++] = trap_agentip[0];
	packet_trap[packet_index++] = trap_agentip[1];
	packet_trap[packet_index++] = trap_agentip[2];
	packet_trap[packet_index++] = trap_agentip[3];

	packet_trap[packet_index++] = 0x02; // Generic Trap
	packet_trap[packet_index++] = 0x01;
	packet_trap[packet_index++] = (uint8)genericTrap;

	packet_trap[packet_index++] = 0x02; // Specific Trap
	packet_trap[packet_index++] = 0x01;
	packet_trap[packet_index++] = (uint8)specificTrap;

	packet_trap[packet_index++] = 0x43; // Timestamp

	uint8 count = 1;
	
	for(int i=1;i<4;i++)
	{
		if((uint8)(*timestamp >> (8 * i))>0)
		{
			count++;
		}
	}
	packet_trap[packet_index++] = count;
	for(int i = 1; i <= count; i++)
	{
		packet_trap[packet_index++] = (uint8)(*timestamp >> (8*(count - i)));
	}
	
	// packet_trap[packet_index++] = 0x00;

	packet_trap[packet_index++] = 0x30; // Sequence of variable-bindings
	packet_trap[packet_index] = 0xff;
	packet_buff3 = packet_index++;
	
	// variable-bindings
	{
		va_list ap;
		uint32 length_var_bindings = 0;
		uint32 length_buff = 0;

		va_start (ap, va_count); 

		for (i=0; i<va_count; i++) 
		{
			dataEntryType* fff = va_arg(ap, dataEntryType*);
			makeTrapVariableBindings(fff, &(packet_trap[packet_index]), &length_buff);
			packet_index = packet_index + length_buff;
			length_var_bindings = length_var_bindings + length_buff;
		}

		packet_trap[packet_buff3] = length_var_bindings;

		va_end (ap);
	}
	packet_trap[packet_buff1] = packet_index - 2;
	packet_trap[packet_buff2] = packet_index - (9 + (uint8)strlen(community));

	// Send Packet
	{
		uint8 svr_addr[6];
        socket(SOCK_SNMP,Sn_MR_UDP,162,0);
		ipToByteArray(managerIP, svr_addr);
		sendto(SOCK_SNMP, packet_trap, packet_index, svr_addr, 162);
		close(SOCK_SNMP);

		return 0;
	}
}

//SNMPv2 Trap_send
int32 Snmp2TrapSend(int8* managerIP, int8* community, uint32 genericTrap, uint32 specificTrap, uint32 va_count, ...)
{
	uint32 i;
	int32 packet_index = 0;
	int32 packet_buff1 = 0;
	int32 packet_buff2 = 0;
	int32 packet_buff3 = 0;

	packet_trap[packet_index++] = 0x30; // ASN.1 Header
	packet_trap[packet_index] = 0xff; // pdu_length, temp
	packet_buff1 = packet_index++;

	packet_trap[packet_index++] = 0x02; // Version
	packet_trap[packet_index++] = 0x01; // length
	packet_trap[packet_index++] = 0x01; // Value
	
	packet_trap[packet_index++] = 0x04; // Community
	packet_trap[packet_index++] = (uint8)strlen(community); //len
	memcpy(&(packet_trap[packet_index]), community, strlen(community)); //value

	packet_index = packet_index + (uint8)strlen(community);

	packet_trap[packet_index++] = 0xa7; // trap
	packet_trap[packet_index] = 0xff; // length
	packet_buff2 = packet_index++;

	packet_trap[packet_index++] = 0x02; // request_id
	packet_trap[packet_index++] = 0x04; //len
	packet_trap[packet_index++] = 0x00;
	packet_trap[packet_index++] = 0x06;
	packet_trap[packet_index++] = 0x06;
	packet_trap[packet_index++] = 0x06;

	packet_trap[packet_index++] = 0x02; // Error Status
	packet_trap[packet_index++] = 0x01;
	packet_trap[packet_index++] = (uint8)genericTrap;

	packet_trap[packet_index++] = 0x02; // Error Index
	packet_trap[packet_index++] = 0x01;
	packet_trap[packet_index++] = (uint8)specificTrap;


	packet_trap[packet_index++] = 0x30; // Sequence of variable-bindings
	packet_trap[packet_index] = 0xff;
	packet_buff3 = packet_index++;
	
	// variable-bindings
	{
		va_list ap;
		uint32 length_var_bindings = 0;
		uint32 length_buff = 0;

		va_start (ap, va_count); 

		for (i=0; i<va_count; i++) 
		{
			dataEntryType* fff = va_arg(ap, dataEntryType*);
			makeTrapVariableBindings(fff, &(packet_trap[packet_index]), &length_buff);
			packet_index = packet_index + length_buff;
			length_var_bindings = length_var_bindings + length_buff;
		}

		packet_trap[packet_buff3] = length_var_bindings;

		va_end (ap);
	}
	packet_trap[packet_buff1] = packet_index - 2;
	packet_trap[packet_buff2] = packet_index - (9 + (uint8)strlen(community));

	// Send Packet
	{
		uint8 svr_addr[6];
        socket(SOCK_SNMP,Sn_MR_UDP,162,0);
		ipToByteArray(managerIP, svr_addr);
		sendto(SOCK_SNMP, packet_trap, packet_index, svr_addr, 162);
		close(SOCK_SNMP);

		return 0;
	}
}


// Function: SnmpXDaemon
// Description: This function implements a simple SNMP (Simple Network Management Protocol) agent (daemon) that listens for SNMP requests, processes them, and sends back responses.
// Parameters: None
// Returns: 0 upon successful completion

int32 SnmpXDaemon()
{
//    int32 snmpfd = 0; // File descriptor for SNMP socket
//    int32 fromlen = 0; // Length of the address of the sender
//    int32 retStatus = 0; // Return status
    int32 len = 0; // Length of received data
    uint8 loopsnmpd = 1; // Flag for controlling the main loop
    uint8 svr_addr[6]; // Array to store server address
    uint16 svr_port; // Server port number

//    UNUSED(snmpfd); // Macro to indicate that the variable is intentionally unused
//    UNUSED(fromlen);
//    UNUSED(retStatus);
        
    socket(SOCK_SNMP, Sn_MR_UDP, 161, 0); // Open the agent socket for SNMP communication
    //WDEBUG("Start SNMP Daemon(Agent) ");

    while (loopsnmpd)
    {
		if(getSn_SR(SOCK_SNMP) == SOCK_CLOSED)	// Socket处于关闭状态
		{														
				socket(SOCK_SNMP,Sn_MR_UDP,161,0);												// 打开Socket，并配置为UDP模式，打开一个本地端口
		}

        if ((len = getSn_RX_RSR(SOCK_SNMP)) > 0) // Check if there is data available to read from the SNMP socket
        {
            // Receive the SNMP request message
            request_msg.len = recvfrom(SOCK_SNMP, (uint8 *)&request_msg.buffer[0], len, svr_addr, &svr_port);
        }
        else
        {
            request_msg.len = 0;
            continue;
        }

        if (request_msg.len > 0) // If a request message is received
        {
            // Display the received request message
            //dumpCode("\r\n[Request]\r\n", "\r\n", request_msg.buffer, request_msg.len);

            request_msg.index = 0;
            response_msg.index = 0;
            errorStatus = errorIndex = 0;

            if (parseSNMPMessage() != -1) // Parse the received SNMP message
            {
                // Send the response message back to the client
                sendto(SOCK_SNMP, response_msg.buffer, response_msg.index, svr_addr, svr_port);
            }

            // Display the generated response message
            //dumpCode("\r\n[Response]\r\n", "\r\n", response_msg.buffer, response_msg.index);
        } 
    }           

    close(SOCK_SNMP); // Close the SNMP socket
    return 0; // Return 0 upon successful completion
}

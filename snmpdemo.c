//#include "globalval.h"
//#include <FreeRTOS.h>
//#include <task.h>
#include "snmplib.h"
#include "snmpdemo.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "gd32f10x_gpio.h"

time_t startTime;
uint8 flag_test = 0;

dataEntryType snmpData[] =
{
	// System MIB

	// SysDescr Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 1, 0}, 
	SNMPDTYPE_OCTET_STRING, 30, {"WIZnet Embedded SNMP Agent"}, 
	NULL, NULL},

	// SysObjectID Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 2, 0}, 
	SNMPDTYPE_OBJ_ID, 8, {"\x2b\x06\x01\x02\x01\x01\x02\x00"},
	NULL, NULL},

	// SysUptime Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 3, 0}, 
	SNMPDTYPE_TIME_TICKS, 0, {""},
	currentUptime, NULL},

	// sysContact Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 4, 0}, 
	SNMPDTYPE_OCTET_STRING, 30, {"support@wiznet.co.kr"}, 
	NULL, NULL},

	// sysName Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 5, 0}, 
	SNMPDTYPE_OCTET_STRING, 30, {"http://www.wiznet.co.kr"}, 
	NULL, NULL},

	// Location Entry
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 6, 0}, 
	SNMPDTYPE_OCTET_STRING, 30, {"4F Humax Village"},
	NULL, NULL},

	// SysServices             
//	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 7, 0}, 
//	SNMPDTYPE_INTEGER, 4, {""}, 
//	NULL, NULL},
	
	//��������ֱ�ӳ�ʼ��
	{read_only, 8, {0x2b, 6, 1, 2, 1, 1, 7, 0}, 
	SNMPDTYPE_INTEGER, 4, 100, 
	NULL, NULL},

	// WIZnet LED 0x8C, 0xA6, 0x5E
//	{read_only, 8, {0x2b, 6, 1, 4, 1, 0, 1, 0}, 
//	SNMPDTYPE_OCTET_STRING, 30, {""},
//	getWIZnetLed, NULL},

//	{read_write, 8, {0x2b, 6, 1, 4, 1, 0, 2, 0}, 
//	SNMPDTYPE_INTEGER, 4, {""},
//	NULL, setWIZnetLed}
	
	{read_only, 10, {0x2B, 0x06, 0x01, 0x04, 0x01, 0x8C, 0xA6, 0x5E, 0x01, 0x00}, 
	SNMPDTYPE_OCTET_STRING, 30, {""},
	getWIZnetLed, NULL},

	{read_write, 10, {0x2B, 0x06, 0x01, 0x04, 0x01, 0x8C, 0xA6, 0x5E, 0x02, 0x00}, 
	SNMPDTYPE_INTEGER, 4, {""},
	NULL, setWIZnetLed}
};

const int32 maxData = (sizeof(snmpData) / sizeof(dataEntryType));

void initTable()
{
//	startTime = time(NULL);
	snmpData[6].u.intval = 5;

	snmpData[7].u.intval = 0;
	snmpData[8].u.intval = 0;

	for(int i=0;i<maxData;i++)
	{
		if(snmpData[i].dataType == SNMPDTYPE_OCTET_STRING)
		{
			snmpData[i].dataLen = (uint8)strlen((int8*)&snmpData[i].u.octetstring);
		}
	}

}

void currentUptime(void *ptr, uint8 *len)
{
//	time_t curTime = time(NULL);
//	*(uint32 *)ptr = (uint32)(curTime - startTime) * 100;
	*(uint32 *)ptr = 100;
	*len = 4;
}

//////////////////////////////////////////////////////////////////////////////////////////
int32 wiznetLedStatus = 0;

void getWIZnetLed(void *ptr, uint8 *len)
{
	if ( wiznetLedStatus==0 )	
             *len = sprintf((int8 *)ptr, "LED Off");
	else	
            *len = sprintf((int8 *)ptr, "LED On");
}

void setWIZnetLed(int32 val)
{
	wiznetLedStatus = val;
	if ( wiznetLedStatus==0 )	
//              GPIO_SetBits(GPIOA, LED3); // LED in the W5500-EVB     
	// gpio_bit_set(GPIOB, GPIO_PIN_15);
	flag_test = 1;
	else						
//           GPIO_ResetBits(GPIOA, LED3);
	// gpio_bit_reset(GPIOB, GPIO_PIN_15);   
	flag_test = 2;    
}

void UserSnmpDemo(void)
{
	//WDEBUG("\r\n\r\nStart UserSnmpDemo");
	SnmpXInit();
	
	{ 
//		dataEntryType enterprise_oid = {read_only, 8, {0x2b, 6, 1, 4, 1, 0, 0x10, 0}, SNMPDTYPE_OBJ_ID, 8,{"\x2b\x06\x01\x04\x01\x00\x10\x00"}, NULL, NULL};
		dataEntryType enterprise_oid = {read_only, 8, {0x2B, 0x06, 0x01, 0x04, 0x01, 0x8C, 0xA6, 0x5E}, SNMPDTYPE_OBJ_ID, 8,{"\x2b\x06\x01\x04\x01\x00\x10\x00"}, NULL, NULL};
		dataEntryType trap_oid1 = {read_only, 8, {0x2b, 6, 1, 4, 1, 0, 11, 0}, SNMPDTYPE_OCTET_STRING, 30, {""}, NULL, NULL};
		dataEntryType trap_oid2 = {read_only, 8, {0x2b, 6, 1, 4, 1, 0, 12, 0}, SNMPDTYPE_INTEGER, 4, {""}, NULL, NULL};

		strcpy((int8*)trap_oid1.u.octetstring, "Alert!!!");
		trap_oid2.u.intval = 123456;
		
		uint32 b = 100;
		uint32 c = 100000;
		uint32 *tim_stamp1 = &b;
		uint32 *tim_stamp2 = &c;
		
		// SnmpXTrapSend("192.168.12.113", "192.168.12.114", "public", enterprise_oid, warmStart, 0, tim_stamp1, 0);
		// SnmpXTrapSend("192.168.12.113", "192.168.12.114", "public", enterprise_oid, enterpriseSpecific, 0, tim_stamp2, 2, &trap_oid1, &trap_oid2);
		Snmp2TrapSend("192.168.12.113", "public", NO_ERROR, 0, 0);
		Snmp2TrapSend("192.168.12.113", "public", NO_ERROR, 0, 2, &trap_oid1, &trap_oid2);
		
	}

	SnmpXDaemon();
}

/*
#ifdef WIN32
int32 main(int32 argc, int8 *argv[])
{
	UserSnmpDemo();
	return 0;
}
#endif
*/


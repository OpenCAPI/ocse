/*
 * Copyright 2014,2017 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tlx_interface.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>


/* static void set_protocol_level(struct AFU_EVENT *event, uint32_t primary,
			       uint32_t secondary, uint32_t tertiary)
{
		printf("TLX_SOCKET:\tEntering set_protocol_level.\n");
	if ((event->proto_primary != primary) ||
	    (event->proto_secondary != secondary) ||
	    (event->proto_tertiary != tertiary)) {
		printf( "TLX_SOCKET:WARNING: Adjusting TLX interface protocol level!\n");
		printf( "TLX_SOCKET:\tPlease review changes between levels.\n");
		printf( "TLX_SOCKET:\tSupported TLX protocol level: %d.%d.%d\n",
		       event->proto_primary, event->proto_secondary,
		       event->proto_tertiary);
	}
	event->proto_primary = primary;
	event->proto_secondary = secondary;
	event->proto_tertiary = tertiary;
} */

static int establish_protocol(struct AFU_EVENT *event)
{
	int bc, bl, bp, i;
	bp = 0;
	bl = 16;
	fd_set watchset;	/* fds to read from */
	uint8_t byte;
	uint32_t primary, secondary, tertiary;

	// Send protocol ID to other side of socket connection
	event->tbuf[0] = 'T';
	event->tbuf[1] = 'L';
	event->tbuf[2] = 'X';
	event->tbuf[3] = '\0';
	for (i = 0; i < 4; i++) {
		event->tbuf[4 + i] =
		    ((event->proto_primary) >> ((3 - i) * 8)) & 0xFF;
	}
	for (i = 0; i < 4; i++) {
		event->tbuf[8 + i] =
		    ((event->proto_secondary) >> ((3 - i) * 8)) & 0xFF;
	}
	for (i = 0; i < 4; i++) {
		event->tbuf[12 + i] =
		    ((event->proto_tertiary) >> ((3 - i) * 8)) & 0xFF;
	}
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0) {
			fprintf(stderr, "ERROR: establish_protocol: send failed: %s\n",
							strerror(errno));
			return TLX_TRANSMISSION_ERROR;
		}
		bp += bc;
	}

	// Get protocol ID from other side of socket connection
	bc = 0;
	FD_ZERO(&watchset);
	FD_SET(event->sockfd, &watchset);
	select(event->sockfd + 1, &watchset, NULL, NULL, NULL);
	while ((event->rbp < 16) && (bc != -1)) {
		if ((bc =
		     recv(event->sockfd, &(event->rbuf[event->rbp]), 1,
			  0)) == -1) {
			if (errno == EWOULDBLOCK) {
				select(event->sockfd + 1, &watchset, NULL, NULL,
				       NULL);
				continue;
			} else {
				return TLX_BAD_SOCKET;
			}
		}
		event->rbp += bc;
	}
	event->rbp = 0;

	if (strcmp((char *)event->rbuf, "TLX") != 0) {
		if (strcmp((char *)event->rbuf, "OCSE") == 0) {
			fprintf(stderr, "ERROR: establish_protocol: OCSE client attempted"
							" to connect directly, instead of relaying through the"
							" ocse server.\n");
		} else {
			fprintf(stderr, "ERROR: establish_protocol: Unrecognized protocol.\n");
		}
		return TLX_BAD_SOCKET;
	}

	primary = 0;
	for (i = 4; i < 8; i++) {
		byte = event->rbuf[i];
		primary <<= 8;
		primary += (uint32_t) byte;
	}

	secondary = 0;
	for (i = 8; i < 12; i++) {
		byte = event->rbuf[i];
		secondary <<= 8;
		secondary += (uint32_t) byte;
	}

	tertiary = 0;
	for (i = 12; i < 16; i++) {
		byte = event->rbuf[i];
		tertiary <<= 8;
		tertiary += (uint32_t) byte;
	}

	
	// Check for mis-matched primary level and error out if found
	if (primary != event->proto_primary) {
		printf("ERROR: Remote tlx_interface code using different TLX revision level!!\n");
		printf("\tLocal tlx_interface level:%d.%d.%d\n",
		       event->proto_primary, event->proto_secondary,
		       event->proto_tertiary);
		printf("\tRemote tlx_interface level:%d.%d.%d\n",
		       primary, secondary, tertiary);
		printf("Please check your #define setting in common/tlx_interface_t.h!!\n");
		printf("Please recompile libocl, ocse, your AFU and your application before rerunning!!\n");

		return TLX_VERSION_ERROR;
	}
	else 
		return TLX_SUCCESS;


}

/* Call this at startup to reset all the event indicators */

void tlx_event_reset(struct AFU_EVENT *event)
{
	memset(event, 0, sizeof(*event));
	event->proto_primary = PROTOCOL_PRIMARY;
	event->proto_secondary = PROTOCOL_SECONDARY;
	event->proto_tertiary = PROTOCOL_TERTIARY;
}

/* Call this once after creation to initialize the AFU_EVENT structure and
 * open a socket conection to an AFU server.  This function initializes the
 * TLX side of the interface which is the client in the socket connection
 * server_host should be the name of the server hosting the simulation of
 * the AFU and port is the active port on that server. */

int tlx_init_afu_event(struct AFU_EVENT *event, char *server_host, int port)
{
	tlx_event_reset(event);
	//event->room = 64;
	event->rbp = 0;
	struct hostent *he;
	if ((he = gethostbyname(server_host)) == NULL) {
		herror("gethostbyname");
		return TLX_BAD_SOCKET;
	}
	struct sockaddr_in ssadr;
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	event->sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (event->sockfd == 0) {
		perror("socket");
		return TLX_BAD_SOCKET;
	}
	if (connect(event->sockfd, (struct sockaddr *)&ssadr, sizeof(ssadr)) <
	    0) {
		perror("connect");
		return TLX_BAD_SOCKET;
	}
	fcntl(event->sockfd, F_SETFL, O_NONBLOCK);

	int rc = establish_protocol(event);
	printf("TLX_SOCKET: Using TLX protocol level : %d.%d.%d\n",
	       event->proto_primary, event->proto_secondary,
	       event->proto_tertiary);

	return rc;
}

/* Call this to close the socket connection from either side */

int tlx_close_afu_event(struct AFU_EVENT *event)
{
	char buffer[4096];

	// Shutdown socket traffic
	if (shutdown(event->sockfd, SHUT_RDWR))
		return TLX_CLOSE_ERROR;

	// Drain any data in socket
	while (recv(event->sockfd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT) >
	       0) ;

	// Close socket
	if (close(event->sockfd))
		return TLX_CLOSE_ERROR;
	event->sockfd = -1;

	return TLX_SUCCESS;
}

/* Call this once after creation to initialize the AFU_EVENT structure. */
/* This function initializes the AFU side of the interface which is the
 * server in the socket connection. */

int tlx_serv_afu_event(struct AFU_EVENT *event, int port)
{
	int cs = -1;
	tlx_event_reset(event);
	event->rbp = 0;
	event->tlx_afu_cmd_resp_initial_credit = MAX_CMD_RESP_CREDITS; //TODO what should this really be?
	event->tlx_afu_data_initial_credit = MAX_DATA_CREDITS; //TODO what should this really be?
	struct sockaddr_in ssadr, csadr;
	unsigned int csalen = sizeof(csadr);
	memset(&ssadr, 0, sizeof(ssadr));
	ssadr.sin_family = AF_UNSPEC;
	ssadr.sin_addr.s_addr = INADDR_ANY;
	ssadr.sin_port = htons(port);
	event->sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (event->sockfd < 0) {
		perror("socket");
		return TLX_BAD_SOCKET;
	}
	if (bind(event->sockfd, (struct sockaddr *)&ssadr, sizeof(ssadr)) == -1) {
		perror("bind");
		tlx_close_afu_event(event);
		return TLX_BAD_SOCKET;
	}
	char hostname[1024];
	hostname[1023] = '\0';
	gethostname(hostname, 1023);
	printf("AFU Server is waiting for connection on %s:%d\n", hostname,
	       port);
	fflush(stdout);
	if (listen(event->sockfd, 10) == -1) {
		perror("listen");
		tlx_close_afu_event(event);
		return TLX_BAD_SOCKET;
	}
	while (cs < 0) {
		cs = accept(event->sockfd, (struct sockaddr *)&csadr, &csalen);
		if ((cs < 0) && (errno != EINTR)) {
			perror("accept");
			tlx_close_afu_event(event);
			return TLX_BAD_SOCKET;
		}
	}
	close(event->sockfd);
	event->sockfd = cs;
	fcntl(event->sockfd, F_SETFL, O_NONBLOCK);
	char clientname[1024];
	clientname[1023] = '\0';
	getnameinfo((struct sockaddr *)&csadr, sizeof(csadr), clientname, 1024,
		    NULL, 0, 0);
	printf("TLX client connection from %s\n", clientname);

	int rc = establish_protocol(event);
	printf("Using TLX protocol level : %d.%d.%d\n", event->proto_primary,
	       event->proto_secondary, event->proto_tertiary);

	return rc;
}

/* Call this from ocse to send a  response  to tlx/afu*/

int tlx_afu_send_resp(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag)

{
	if (event->tlx_afu_resp_valid) {
		return TLX_AFU_DOUBLE_RESP;
	} else {
		event->tlx_afu_resp_valid = 1;
		event->tlx_afu_resp_opcode = tlx_resp_opcode;
		event->tlx_afu_resp_afutag = resp_afutag;
		event->tlx_afu_resp_code = resp_code;
		event->tlx_afu_resp_pg_size = resp_pg_size;
		event->tlx_afu_resp_dl = resp_dl;
		event->tlx_afu_resp_dp = resp_dp;
		event->tlx_afu_resp_addr_tag = resp_addr_tag;
#ifdef TLX4
		event->tlx_afu_resp_host_tag = resp_host_tag;
		event->tlx_afu_resp_cache_state = resp_cache_state;
#endif
		return TLX_SUCCESS;
	}
}


int tlx_afu_send_resp_data(struct AFU_EVENT *event,
		 uint8_t DATA_RESP_CONTINUATION,
		 uint8_t resp_data_bdi,uint8_t * resp_data)

{
	printf("THIS FUNCTION ISN'T SUPPORTED YET \n");
	return TLX_AFU_RESP_DATA_NOT_VALID;
}


/* Call this from ocse to send both response & response data to tlx/afu  */
/* This is where we create multiple resp/resp data packets w/varying dl ?? 
 * OR, do we expect ocse to fragment and just send us packets to pass on?
 * AND do we really need rd_req and rd_cnt in our implementation?? */

int tlx_afu_send_resp_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag,
		 uint8_t resp_data_bdi,uint8_t * resp_data)

{
	if ((event->tlx_afu_resp_valid ==1) || (event->tlx_afu_resp_data_valid == 1)) {
		return TLX_AFU_DOUBLE_RESP_AND_DATA;
	} else {
		event->tlx_afu_resp_valid = 1;
		event->tlx_afu_resp_data_valid = 1;
		event->tlx_afu_resp_opcode = tlx_resp_opcode;
		event->tlx_afu_resp_afutag = resp_afutag;
		event->tlx_afu_resp_code = resp_code;
		event->tlx_afu_resp_pg_size = resp_pg_size;
		event->tlx_afu_resp_dl = resp_dl;
		event->tlx_afu_resp_dp = resp_dp;
		event->tlx_afu_resp_addr_tag = resp_addr_tag;
#ifdef TLX4
		event->tlx_afu_resp_host_tag = resp_host_tag;
		event->tlx_afu_resp_cache_state = resp_cache_state;
#endif
		event->tlx_afu_resp_data_bdi = resp_data_bdi;
		// TODO FOR NOW WE ALWAYS COPY 8 BYTES of DATA - OCSE ALWAYS
		// SENDS 8 BYTES 
		memcpy(event->tlx_afu_resp_data, resp_data, 8);
		return TLX_SUCCESS;
	}
}


/* Call this from ocse to send a command to tlx/afu */

int tlx_afu_send_cmd(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
#ifdef TLX4
		 uint8_t cmd_os, uint8_t cmd_flag,
#endif
		 uint64_t cmd_pa)

{ 
	if (event->tlx_afu_cmd_valid) {
		return TLX_AFU_DOUBLE_COMMAND;
	} else {
		event->tlx_afu_cmd_valid = 1;
		event->tlx_afu_cmd_opcode = tlx_cmd_opcode;
		event->tlx_afu_cmd_capptag = cmd_capptag;
		event->tlx_afu_cmd_dl = cmd_dl;
		event->tlx_afu_cmd_pl = cmd_pl;
		event->tlx_afu_cmd_be = cmd_be;
		event->tlx_afu_cmd_end = cmd_end;
		event->tlx_afu_cmd_t = cmd_t;
		event->tlx_afu_cmd_pa = cmd_pa;
#ifdef TLX4
		event->tlx_afu_cmd_flag = cmd_flag;
		event->tlx_afu_cmd_os = cmd_os;
#endif
		return TLX_SUCCESS;
	}
}

int tlx_afu_send_cmd_data(struct AFU_EVENT *event,
		 uint8_t DATA_RESP_CONTINUATION,
		 uint8_t cmd_data_bdi,uint8_t * cmd_data)

{
	printf("THIS FUNCTION ISN'T SUPPORTED YET \n");
	return TLX_AFU_CMD_DATA_NOT_VALID;
}


/* Call this from ocse to send both command & command data to tlx/afu */
/* This is where we create multiple cmd/resp data packets w/varying dl ?? 
 * OR, do we expect ocse to fragment and just send us packets to pass on?
 * AND do we really need rd_req and rd_cnt in our implementation?? */

int tlx_afu_send_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
		 uint64_t cmd_pa,  
#ifdef TLX4
		 uint8_t cmd_os, uint8_t cmd_flag,
#endif
		 uint8_t cmd_data_bdi,uint8_t * cmd_data)
{
	if ((event->tlx_afu_cmd_valid ==1) || (event->tlx_afu_cmd_data_valid == 1)) {
		return TLX_AFU_DOUBLE_CMD_AND_DATA;
	} else {
		event->tlx_afu_cmd_valid = 1;
		event->tlx_afu_cmd_data_valid = 1;
		event->tlx_afu_cmd_opcode = tlx_cmd_opcode;
		event->tlx_afu_cmd_capptag = cmd_capptag;
		event->tlx_afu_cmd_dl = cmd_dl;
		event->tlx_afu_cmd_pl = cmd_pl;
		event->tlx_afu_cmd_be = cmd_be;
		event->tlx_afu_cmd_end = cmd_end;
		event->tlx_afu_cmd_t = cmd_t;
		event->tlx_afu_cmd_pa = cmd_pa;
#ifdef TLX4
		event->tlx_afu_cmd_flag = cmd_flag;
		event->tlx_afu_cmd_os = cmd_os;
#endif
		event->tlx_afu_cmd_data_bdi = cmd_data_bdi;
		// TODO FOR NOW WE ALWAYS SEND 4 BYTES of DATA - OCSE ALWAYS
		// SENDS 4 BYTES 
		memcpy(event->tlx_afu_cmd_data_bus, cmd_data, 4);
		return TLX_SUCCESS;
	}
}


/* Call this from ocse to read AFU response. This reads both afu_tlx resp AND resp data interfaces */

int afu_tlx_read_resp_and_data(struct AFU_EVENT *event,
		    uint8_t * afu_resp_opcode, uint8_t * resp_dl,
		    uint16_t * resp_capptag, uint8_t * resp_dp,
		    uint8_t * resp_data_is_valid, uint8_t * resp_code, uint8_t * rdata_bus, uint8_t * rdata_bad)

{ 
	if (!event->afu_tlx_resp_valid) {
		return AFU_TLX_RESP_NOT_VALID;
	} else {
		event->afu_tlx_resp_valid = 0;
		*afu_resp_opcode = event->afu_tlx_resp_opcode;
		*resp_dl = event->afu_tlx_resp_dl;
		*resp_capptag = event->afu_tlx_resp_capptag;
		*resp_dp = event->afu_tlx_resp_dp;
		*resp_code = event->afu_tlx_resp_code;
		*resp_data_is_valid = 0;
		if (event->afu_tlx_rdata_valid) {
	// should we return some sort of RC other than 0 if there is no data? Should calling function be 
	// smart enough to know if data is expected? Or should we set a bit to indicate that there is data 
	// on the data bus? Call it data valid, BUT caller still has to check bdi? Or does bdi kill interface
	// at the TLX level??
			event->afu_tlx_rdata_valid = 0;
			*resp_data_is_valid = 1;
			*rdata_bad = event->afu_tlx_rdata_bad;
			// TODO FOR NOW WE ALWAYS COPY 4 BYTES of DATA - AFU
			// SENDS 4 BYTES 
			memcpy(rdata_bus, event->afu_tlx_rdata_bus, 4);
			//return TLX_SUCCESS;
		}
	//	return AFU_TLX_RESP_NO_DATA;
		return TLX_SUCCESS;
	}
}


/* Call this from ocse to read AFU command. This reads both afu_tlx cmd AND cmd data interfaces */

int afu_tlx_read_cmd_and_data(struct AFU_EVENT *event,
  		    uint8_t * afu_cmd_opcode, uint16_t * cmd_actag,             
  		    uint8_t * cmd_stream_id, uint8_t * cmd_ea_or_obj,  
 		    uint16_t * cmd_afutag, uint8_t * cmd_dl,                 
  		    uint8_t * cmd_pl, 
#ifdef TLX4
		    uint8_t * cmd_os,
#endif                 
		    uint64_t * cmd_be, uint8_t * cmd_flag,               
 		    uint8_t * cmd_endian, uint16_t * cmd_bdf,               
  	  	    uint32_t * cmd_pasid, uint8_t * cmd_pg_size, uint8_t * cmd_data_is_valid,           
 		    uint8_t * cdata_bus, uint8_t * cdata_bad)

{
	if (!event->afu_tlx_cmd_valid) {
		return AFU_TLX_CMD_NOT_VALID;
	} else {
		event->afu_tlx_cmd_valid = 0;
		*afu_cmd_opcode = event->afu_tlx_cmd_opcode;
		*cmd_actag = event->afu_tlx_cmd_actag;
		*cmd_stream_id = event->afu_tlx_cmd_stream_id;
		memcpy(cmd_ea_or_obj, event->afu_tlx_cmd_ea_or_obj,9);
		*cmd_afutag = event->afu_tlx_cmd_afutag;
		*cmd_dl = event->afu_tlx_cmd_dl;
		*cmd_pl = event->afu_tlx_cmd_pl;
#ifdef TLX4
		*cmd_os = event->afu_tlx_cmd_os;
#endif
		*cmd_be = event->afu_tlx_cmd_be;
		*cmd_flag = event->afu_tlx_cmd_flag;
		*cmd_endian = event->afu_tlx_cmd_endian;
		*cmd_bdf = event->afu_tlx_cmd_bdf;
		*cmd_pasid = event->afu_tlx_cmd_pasid;
		*cmd_pg_size = event->afu_tlx_cmd_pg_size;
		cmd_data_is_valid = 0;
		if (event->afu_tlx_cdata_valid) {
	// should we return some sort of RC other than 0 if there is no data? Should calling function be 
	// smart enough to know if data is expected? Or should we set a bit to indicate that there is data 
	// on the data bus? Call it data valid, BUT caller still has to check bdi? Or does bdi kill interface
	// at the TLX level??

			event->afu_tlx_cdata_valid = 0;
			*cmd_data_is_valid = 1;
			*cdata_bad = event->afu_tlx_cdata_bad;
			// TODO FOR NOW WE ALWAYS COPY 8 BYTES of DATA - AFU
			// SENDS 8 BYTES 
			memcpy(cdata_bus, event->afu_tlx_cdata_bus, 8);
			//return TLX_SUCCESS;
		}
		//return AFU_TLX_CMD_NO_DATA;
		return TLX_SUCCESS;
	}
}



/* Call this to send an event to the AFU model after calling one or more of:
 * tlx_send_cmd, tlx_send_resp, tlx_send_cmd_and_data, tlx_send_resp_and_data */

int tlx_signal_afu_model(struct AFU_EVENT *event)
{ 
	int i, bc, bl;
	int bp = 1;
	if (event->clock != 0)
		return TLX_TRANSMISSION_ERROR;
	event->clock = 1;
	event->tbuf[0] = 0x40;
	if (event->tlx_afu_cmd_valid != 0) { //There are 23 bytes to xfer in this group (25 for TLX4)
		event->tbuf[0] = event->tbuf[0] | 0x10;
		printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = event->tlx_afu_cmd_opcode;
		event->tbuf[bp++] = ((event->tlx_afu_cmd_capptag) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->tlx_afu_cmd_capptag & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->tlx_afu_cmd_dl & 0x03);
		event->tbuf[bp++] = (event->tlx_afu_cmd_pl & 0x03);
		for (i = 0; i < 8; i++) { // And what, exactly, do I do with this?
			event->tbuf[bp++] =
			    ((event->tlx_afu_cmd_be) >> ((7 - i) * 8)) & 0xFF;
		}
		event->tbuf[bp++] = (event->tlx_afu_cmd_end & 0x01);
		event->tbuf[bp++] = (event->tlx_afu_cmd_t & 0x01);
		for (i = 0; i < 8; i++) { // And what, exactly, do I do with this?
			event->tbuf[bp++] =
			    ((event->tlx_afu_cmd_pa) >> ((7 - i) * 8)) & 0xFF;
		}
#ifdef TLX4
		event->tbuf[bp++] = (event->tlx_afu_cmd_flag & 0x0f);
		event->tbuf[bp++] = (event->tlx_afu_cmd_os & 0x01);
#endif
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->tlx_afu_cmd_valid = 0;
	}
	if (event->tlx_afu_cmd_data_valid != 0) { //There are 5  bytes to xfer  TODO limited to 4B right now
		event->tbuf[0] = event->tbuf[0] | 0x08;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = (event->tlx_afu_cmd_data_bdi  & 0x01 );
		//printf("event->tbuf[bp] is 0x%2x and bp is 0x%2x \n", event->tbuf[bp], bp);
		for (i = 0; i < 4; i++) {
			event->tbuf[bp++] = event->tlx_afu_cmd_data_bus[i];
		}
		//printf("event->tbuf[3] is 0x%2x and bp-1 is 0x%2x \n", event->tbuf[3], bp-1);
		event->tlx_afu_cmd_data_valid = 0;
	}
	if (event->tlx_afu_resp_valid != 0) { //There are 7 bytes to xfer in this group
		event->tbuf[0] = event->tbuf[0] | 0x04;
		event->tbuf[bp++] = event->tlx_afu_resp_opcode;
		event->tbuf[bp++] = ((event->tlx_afu_resp_afutag) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->tlx_afu_resp_afutag & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->tlx_afu_resp_code & 0x0f);
		event->tbuf[bp++] = (event->tlx_afu_resp_pg_size & 0x3f);
		event->tbuf[bp++] = (event->tlx_afu_resp_dl & 0x03);
		event->tbuf[bp++] = (event->tlx_afu_resp_dp & 0x03);
		event->tlx_afu_resp_valid = 0;
	}
	if (event->tlx_afu_resp_data_valid != 0) { // There are 9 bytes to xfer
		event->tbuf[0] = event->tbuf[0] | 0x02;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = (event->tlx_afu_resp_data_bdi  & 0x01 );
		//printf("event->tbuf[bp] is 0x%2x and bp is 0x%2x \n", event->tbuf[bp], bp);
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] = event->tlx_afu_resp_data[i];
		}
		event->tlx_afu_resp_data_valid = 0;
	}

	// dump tbuf
	if ( bp > 1 ) {
	  printf( "lgt: tlx_signal_afu_model: tbuf length:0x%02x tbuf: 0x", bp ); 
	  for ( i = 0; i < bp; i++ ) printf( "%02x", event->tbuf[i] );
	  printf( "\n" );
	}

	bl = bp;
	bp = 0;
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0)
			return TLX_TRANSMISSION_ERROR;
		bp += bc;
	}
	return TLX_SUCCESS;
}

/* AFU calls this to send an event to the TLX model */
/* Now static as it's called in tlx_get_tlx_events() */

static int tlx_signal_tlx_model(struct AFU_EVENT *event)
{
	int i, bc, bl;
	int bp = 1;
	if (event->clock != 1)
		return TLX_SUCCESS;
	event->clock = 0;
	event->tbuf[0] = 0x10;
	if (event->afu_tlx_cmd_valid != 0) { //TODO FIX THIS COUNT!!! There are 24 bytes to xfer in this group (25 for TLX4 )
		event->tbuf[0] = event->tbuf[0] | 0x02;
		// printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = event->afu_tlx_cmd_opcode;
		event->tbuf[bp++] = ((event->afu_tlx_cmd_actag) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->afu_tlx_cmd_actag & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->afu_tlx_cmd_stream_id & 0x0f);
		for (i = 0; i < 9; i++) {
			event->tbuf[bp++] = event->afu_tlx_cmd_ea_or_obj[i];
		}
		event->tbuf[bp++] = ((event->afu_tlx_cmd_afutag) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->afu_tlx_cmd_afutag & 0xFF);
		event->tbuf[bp++] = (event->afu_tlx_cmd_dl & 0x03);
		event->tbuf[bp++] = (event->afu_tlx_cmd_pl & 0x03);
#ifdef TLX4
		event->tbuf[bp++] = (event->afu_tlx_cmd_os & 0x01);
#endif
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->afu_tlx_cmd_be) >> ((7 - i) * 8)) & 0xFF;
		}
		event->tbuf[bp++] = (event->afu_tlx_cmd_flag & 0x0f);
		event->tbuf[bp++] = (event->afu_tlx_cmd_endian & 0x01);
		event->tbuf[bp++] = ((event->afu_tlx_cmd_bdf) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->afu_tlx_cmd_bdf & 0xFF);
		for (i = 0; i < 4; i++) { // And what, exactly, do I do with this?
			event->tbuf[bp++] = 
			    ((event->afu_tlx_cmd_pasid) >> ((3 - i) * 4)) & 0xFF;
		}
		event->tbuf[bp++] = (event->afu_tlx_cmd_pg_size & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->afu_tlx_cmd_valid = 0;
	}
	if (event->afu_tlx_cdata_valid != 0) { //There are 9  bytes to xfer 
		event->tbuf[0] = event->tbuf[0] | 0x04;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = (event->afu_tlx_cdata_bad  & 0x01 );
		//printf("event->tbuf[bp] is 0x%2x and bp is 0x%2x \n", event->tbuf[bp], bp);
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] = event->afu_tlx_cdata_bus[i];
		}
		//printf("event->tbuf[3] is 0x%2x and bp-1 is 0x%2x \n", event->tbuf[3], bp-1);
		event->afu_tlx_cdata_valid = 0;
	}
	if (event->afu_tlx_resp_valid != 0) { //There are 6 bytes to xfer in this group
		event->tbuf[0] = event->tbuf[0] | 0x08;
		event->tbuf[bp++] = event->afu_tlx_resp_opcode;
		event->tbuf[bp++] = (event->afu_tlx_resp_dl & 0x03);
		event->tbuf[bp++] = ((event->afu_tlx_resp_capptag) >> 8) & 0x0F;
		event->tbuf[bp++] = (event->afu_tlx_resp_capptag & 0xFF);
		event->tbuf[bp++] = (event->afu_tlx_resp_dp & 0x03);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->afu_tlx_resp_code & 0x0f);
		event->afu_tlx_resp_valid = 0;
	}
	if (event->afu_tlx_rdata_valid != 0) { // There are 5 bytes to xfer TODO ONLY SEND 4B now
		event->tbuf[0] = event->tbuf[0] | 0x20;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = (event->afu_tlx_rdata_bad  & 0x01 );
		//printf("event->tbuf[bp] is 0x%2x and bp is 0x%2x \n", event->tbuf[bp], bp);
		for (i = 0; i < 4; i++) {
			event->tbuf[bp++] = event->afu_tlx_rdata_bus[i];
		}
		event->afu_tlx_rdata_valid = 0;
	}



        // dump tbuf
	if ( bp > 1 ) {
	  printf( "lgt: tlx_signal_tlx_model: tbuf length:0x%02x tbuf: 0x", bp ); 
	  for ( i = 0; i < bp; i++ ) printf( "%02x", event->tbuf[i] );
	  printf( "\n" );
	}

	bl = bp;
	bp = 0;
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0) {
			return TLX_TRANSMISSION_ERROR; }
		bp += bc;
//if ((event->tbuf[0] & 0x20) != 0)
//printf("sent ok on afu side \n");
	}
	return TLX_SUCCESS;
}

/* This function checks the socket connection for data from the external AFU
 * simulator. It needs to be called periodically to poll the socket connection.
 * It will update the AFU_EVENT structure.
 * It returns a 1 if there are new events to process, 0 if not, -1 on error or
 * close.  On a 1 return, the following functions should be called to retrieve
 * the individual event:
 * afu_tlx_read_cmd_and_data
 * afu_tlz_read_resp_and_data
 */

int tlx_get_afu_events(struct AFU_EVENT *event)
{
	int i = 0;
	int bc = 0;
	uint32_t rbc = 1;
	fd_set watchset;	
	FD_ZERO(&watchset);
	FD_SET(event->sockfd, &watchset);
	select(event->sockfd + 1, &watchset, NULL, NULL, NULL);
	if (event->rbp == 0) {
		if ((bc = recv(event->sockfd, event->rbuf, 1, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		event->rbp += bc;
	}
	if (bc == 0)
		return -1;
	if (event->rbp != 0) {
		if ((event->rbuf[0] & 0x10) != 0) {
			event->clock = 0;
			if (event->rbuf[0] == 0x10) {
				event->rbp = 0;
				return 1;
			}
		}
//printf("TLX_GET_AFU_EVENT-1 - rbuf[0] is 0x%02x and e->rbp = %2d  \n", event->rbuf[0], event->rbp);
		if ((event->rbuf[0] & 0x20) != 0)
			rbc += 5; //TODO for now, resp data always 5B total
		if ((event->rbuf[0] & 0x08) != 0)
			rbc += 6; // resp always 6B
	 	if ((event->rbuf[0] & 0x04) != 0)
			rbc += 9; //TODO for now, cmd data always 9B total
		if ((event->rbuf[0] & 0x02) != 0)
			rbc += 34; // for TLX4 cmds, value will increase by 1

//printf("TLX_GET_AFU_EVENT-2 - rbuf[0] is 0x%02x and rbc is %2d \n", event->rbuf[0], rbc);
	}
	if ((bc =
	     recv(event->sockfd, event->rbuf + event->rbp, rbc - event->rbp,
		  0)) == -1) {
		if (errno == EWOULDBLOCK) {
			return 0;
		} else {
			return -1;
		}
	}
	if (bc == 0)
		return -1;
	event->rbp += bc;
	if (event->rbp < rbc)
		return 0;

	// dump rbuf
	printf( "lgt: tlx_get_afu_events: rbuf length:0x%02x rbuf: 0x", rbc ); 
	for ( i = 0; i < rbc; i++ ) printf( "%02x", event->rbuf[i] );
	printf( "\n" ); 

	rbc = 1;
	if ((event->rbuf[0] & 0x02) != 0) {
		event->afu_tlx_cmd_valid = 1;
//printf("event->afu_tlx_cmd_valid is 1  and rbc is 0x%2x \n", rbc);
		
		event->afu_tlx_cmd_opcode = event->rbuf[rbc++];;
		event->afu_tlx_cmd_actag = event->rbuf[rbc++]; 
		event->afu_tlx_cmd_actag = ((event->afu_tlx_cmd_actag << 8) || event->rbuf[rbc++]);;
		event->afu_tlx_cmd_stream_id = event->rbuf[rbc++]; 
		for (i = 0; i < 9; i++) {
			event->afu_tlx_cmd_ea_or_obj[i] = event->rbuf[rbc++] ;
		}
		event->afu_tlx_cmd_afutag = event->rbuf[rbc++]; 
		event->afu_tlx_cmd_afutag = ((event->afu_tlx_cmd_afutag << 8) || event->rbuf[rbc++]);;
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		event->afu_tlx_cmd_dl = event->rbuf[rbc++];
		event->afu_tlx_cmd_pl = event->rbuf[rbc++];
#ifdef TLX4
		event->afu_tlx_cmd_os = event->rbuf[rbc++];;
#endif
		event->afu_tlx_cmd_be = 0;
		for (bc = 0; bc < 8; bc++) {
			event->afu_tlx_cmd_be  =
			    ((event->afu_tlx_cmd_be) << 8) |
			    event->rbuf[rbc++];
		}
		event->afu_tlx_cmd_flag = event->rbuf[rbc++];
		event->afu_tlx_cmd_endian = event->rbuf[rbc++];
		event->afu_tlx_cmd_bdf = event->rbuf[rbc++];
		event->afu_tlx_cmd_bdf = ((event->afu_tlx_cmd_bdf << 8) || event->rbuf[rbc++]);;
		event->afu_tlx_cmd_pasid = 0;
		for (bc = 0; bc < 4; bc++) {
			event->afu_tlx_cmd_pasid  =
			    ((event->afu_tlx_cmd_pasid) << 8) |
			    event->rbuf[rbc++];
		}
		event->afu_tlx_cmd_pg_size = event->rbuf[rbc++];
		
	} else {
		event->afu_tlx_cmd_valid = 0;
	}

	if ((event->rbuf[0] & 0x04) != 0) {
		event->afu_tlx_cdata_valid = 1;
		event->afu_tlx_cdata_bad = event->rbuf[rbc++] ;
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		for (i = 0; i < 8; i++) {
			event->afu_tlx_cdata_bus[i] = event->rbuf[rbc++] ;
		}
	} else {
		event->afu_tlx_cdata_valid = 0;
	}
	if ((event->rbuf[0] & 0x08) != 0) {
		event->afu_tlx_resp_valid = 1;
		event->afu_tlx_resp_opcode = event->rbuf[rbc++];
		event->afu_tlx_resp_dl = event->rbuf[rbc++];
		event->afu_tlx_resp_capptag = event->rbuf[rbc++];
		event->afu_tlx_resp_capptag = ((event->afu_tlx_resp_capptag << 8) || event->rbuf[rbc++]);;
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		event->afu_tlx_resp_dp = event->rbuf[rbc++];
		event->afu_tlx_resp_code = event->rbuf[rbc++];
	} else {
		event->afu_tlx_resp_valid = 0;
	}
	if ((event->rbuf[0] & 0x20) != 0) {
		event->afu_tlx_rdata_valid = 1;
		event->afu_tlx_rdata_bad= event->rbuf[rbc++];
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		for (i = 0; i < 4; i++) {
			event->afu_tlx_rdata_bus[i]= event->rbuf[rbc++];
		}
		
	} else {
		event->afu_tlx_rdata_valid = 0;
	}

	event->rbp = 0;
	return 1;
}

/* This function checks the socket connection for data from the external TLX
 * simulator. It needs to be called periodically to poll the socket connection.
 * (every clock cycle)  It will update the AFU_EVENT structure and returns a 1
 * if there are new events to process. */

int tlx_get_tlx_events(struct AFU_EVENT *event)
{
        int bc, i;
	uint32_t rbc = 1;
	if (event->rbp == 0) {
		if ((bc = recv(event->sockfd, event->rbuf, 1, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		if (bc == 0)
			return -1;
		event->rbp += bc;
	}
	if (event->rbp != 0) {
		if ((event->rbuf[0] & 0x40) != 0) {
			event->clock = 1;
			tlx_signal_tlx_model(event);
			if (event->rbuf[0] == 0x40) {
				event->rbp = 0;
				return 1;
			}
		}
		if ((event->rbuf[0] & 0x10) != 0)
			rbc += 23; // for TLX4 cmds, value will increase by 2
		if ((event->rbuf[0] & 0x08) != 0)
			rbc += 5; //TODO for now, cmd data always 5B total
		if ((event->rbuf[0] & 0x04) != 0)
			rbc += 11; // for TLX4 resp, will increase by 5B
		if ((event->rbuf[0] & 0x02) != 0)
			rbc += 9; //TODO for now, resp data always 9B total
		if ((bc =
		     recv(event->sockfd, event->rbuf + event->rbp,
			  rbc - event->rbp, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		if (bc == 0)
			return -1;
		event->rbp += bc;
	}
	if (event->rbp < rbc)
		return 0;
	
	// dump rbuf
	printf( "lgt: tlx_get_tlx_events: rbuf length:0x%02x rbuf: 0x", rbc ); 
	for ( i = 0; i < rbc; i++ ) printf( "%02x", event->rbuf[i] );
	printf( "\n" ); 

	rbc = 1;
//printf("TLX_GET_TLX_EVENTS event->rbuf[0] is 0x%2x and event->rbuf[1] is 0x%2x \n", event->rbuf[0], event->rbuf[1]);
	if (event->rbuf[0] & 0x10) {
		event->tlx_afu_cmd_valid = 1;
		event->tlx_afu_cmd_opcode = event->rbuf[rbc++];
		event->tlx_afu_cmd_capptag = event->rbuf[rbc++];
		event->tlx_afu_cmd_capptag = ((event->tlx_afu_cmd_capptag << 8) || event->rbuf[rbc++]);;
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		event->tlx_afu_cmd_dl = event->rbuf[rbc++];
		event->tlx_afu_cmd_pl = event->rbuf[rbc++];
		event->tlx_afu_cmd_be = 0;
		for (bc = 0; bc < 8; bc++) {
			event->tlx_afu_cmd_be  =
			    ((event->tlx_afu_cmd_be) << 8) |
			    event->rbuf[rbc++];
		}
		event->tlx_afu_cmd_end = event->rbuf[rbc++];
		event->tlx_afu_cmd_t = event->rbuf[rbc++];
		for (bc = 0; bc < 8; bc++) {
			event->tlx_afu_cmd_pa  =
			    ((event->tlx_afu_cmd_pa) << 8) |
			    event->rbuf[rbc++];
		}
#ifdef TLX4
		event->tlx_afu_cmd_flag  = event->rbuf[rbc++];
		event->tlx_afu_cmd_os  = event->rbuf[rbc++];
#endif
	} else {
		event->tlx_afu_cmd_valid = 0;
	}
	if (event->rbuf[0] & 0x08) {
		event->tlx_afu_cmd_data_valid = 1;
		event->tlx_afu_cmd_data_bdi = event->rbuf[rbc++];
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		for (i = 0; i < 4; i++) {
			event->tlx_afu_cmd_data_bus[i] = event->rbuf[rbc++] ;
		}

	} else {
		event->tlx_afu_cmd_data_valid = 0;
	}
	if (event->rbuf[0] & 0x04) {
		event->tlx_afu_resp_valid = 1;
		event->tlx_afu_resp_opcode = event->rbuf[rbc++];
		event->tlx_afu_resp_afutag = event->rbuf[rbc++];
		event->tlx_afu_resp_afutag = ((event->tlx_afu_resp_afutag << 8) || event->rbuf[rbc++]);;
		event->tlx_afu_resp_code = event->rbuf[rbc++];
		event->tlx_afu_resp_pg_size = event->rbuf[rbc++];
		event->tlx_afu_resp_dl = event->rbuf[rbc++];
		event->tlx_afu_resp_dp = event->rbuf[rbc++];
	} else {
		event->tlx_afu_resp_valid = 0;
	}
	if (event->rbuf[0] & 0x02) {
		event->tlx_afu_resp_data_valid = 1;
		event->tlx_afu_resp_data_bdi = event->rbuf[rbc++] ;
		//printf("event->rbuf[%x] is 0x%2x \n", rbc-1, event->rbuf[rbc-1]);
		for (i = 0; i < 8; i++) {
			event->tlx_afu_resp_data[i] = event->rbuf[rbc++] ;
		}
	} else {
		event->tlx_afu_resp_data_valid = 0;
	}
	event->rbp = 0;
	return 1;
}



///
/* Call this on the AFU side to send a response to ocse.  */

int afu_tlx_send_resp(struct AFU_EVENT *event,
 		 uint8_t afu_resp_opcode,            
 		 uint8_t resp_dl, uint16_t resp_capptag,          
 		 uint8_t resp_dp, uint8_t resp_code)
{
	if (event->afu_tlx_resp_valid) {
		return AFU_TLX_DOUBLE_RESP;
	} else {
		event->afu_tlx_resp_valid = 1;
		event->afu_tlx_resp_opcode = afu_resp_opcode;
		event->afu_tlx_resp_capptag = resp_capptag;
		event->afu_tlx_resp_code = resp_code;
		event->afu_tlx_resp_dl = resp_dl;
		event->afu_tlx_resp_dp = resp_dp;
		return TLX_SUCCESS;
	}
}


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from afu to send response data to ocse   assume can only send 64B 
 * @ time to FIFO ?*/

int afu_tlx_send_resp_data(struct AFU_EVENT *event,
		 uint8_t DATA_RESP_CONTINUATION,
		 uint8_t rdata_bad,uint8_t resp_dp,
		 uint8_t resp_dl,uint8_t * rdata_bus)

{
	printf("THIS FUNCTION ISN'T SUPPORTED YET \n");
	return AFU_TLX_RESP_DATA_NOT_VALID;
}




/* Call this on the AFU side to send a response and response data to ocse.  */

int afu_tlx_send_resp_and_data(struct AFU_EVENT *event,
 		 uint8_t afu_resp_opcode,            
 		 uint8_t resp_dl, uint16_t resp_capptag,          
 		 uint8_t resp_dp, uint8_t resp_code,              
  		 uint8_t rdata_valid, uint8_t * rdata_bus,    
 		 uint8_t rdata_bad)

{
	if ((event->afu_tlx_resp_valid ==1) || (event->afu_tlx_rdata_valid == 1)) {
		return AFU_TLX_DOUBLE_RESP_AND_DATA;
	} else {
		event->afu_tlx_resp_valid = 1;
		event->afu_tlx_rdata_valid = 1;
		event->afu_tlx_resp_opcode = afu_resp_opcode;
		event->afu_tlx_resp_capptag = resp_capptag;
		event->afu_tlx_resp_code = resp_code;
		event->afu_tlx_resp_dl = resp_dl;
		event->afu_tlx_resp_dp = resp_dp;
		event->afu_tlx_rdata_bad = rdata_bad;
		// TODO FOR NOW WE ALWAYS COPY 4 BYTES of DATA - AFU ALWAYS
		// SENDS 4 BYTES 
		memcpy(event->afu_tlx_rdata_bus, rdata_bus, 4);
		return TLX_SUCCESS;
	}
}


/* Call this on the AFU side to send a command to ocse */

int afu_tlx_send_cmd(struct AFU_EVENT *event,
		 uint8_t afu_cmd_opcode, uint16_t cmd_actag,             
  	 	 uint8_t cmd_stream_id, uint8_t * cmd_ea_or_obj, 
  		 uint16_t cmd_afutag, uint8_t cmd_dl,  
  		 uint8_t cmd_pl,                 
#ifdef TLX4
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
  	 	 uint64_t cmd_be,uint8_t cmd_flag,               
		 uint8_t cmd_endian, uint16_t cmd_bdf,               
 		 uint32_t cmd_pasid, uint8_t cmd_pg_size)

{
	if (event->afu_tlx_cmd_valid) {
		return AFU_TLX_DOUBLE_COMMAND;
	} else {
		event->afu_tlx_cmd_valid = 1;
		event->afu_tlx_cmd_opcode = afu_cmd_opcode;
		event->afu_tlx_cmd_actag = cmd_actag;
		event->afu_tlx_cmd_stream_id = cmd_stream_id;
		memcpy(event->afu_tlx_cmd_ea_or_obj,cmd_ea_or_obj,0x9); 
		event->afu_tlx_cmd_afutag = cmd_afutag;
		event->afu_tlx_cmd_dl = cmd_dl;
		event->afu_tlx_cmd_pl = cmd_pl;
#ifdef TLX4
		event->afu_tlx_cmd_os = cmd_os;
#endif
		event->afu_tlx_cmd_be = cmd_be;
		event->afu_tlx_cmd_flag = cmd_flag;
		event->afu_tlx_cmd_endian = cmd_endian;
		event->afu_tlx_cmd_bdf = cmd_bdf;
		event->afu_tlx_cmd_pasid = cmd_pasid;
		event->afu_tlx_cmd_pg_size = cmd_pg_size;
		return TLX_SUCCESS;
	}
}


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from afu to send command data to ocse   assume can only send 64B 
 * @ time to FIFO ?*/

int afu_tlx_send_cmd_data(struct AFU_EVENT *event,
		 uint8_t DATA_CMD_CONTINUATION,
		 uint8_t cdata_bad,uint8_t cmd_pl,
		 uint8_t cmd_dl,uint8_t * cdata_bus)
{
	printf("THIS FUNCTION ISN'T SUPPORTED YET \n");
	return AFU_TLX_CMD_DATA_NOT_VALID;
}


/* Call this on the AFU side to send a command and cmd data to ocse */

int afu_tlx_send_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t afu_cmd_opcode, uint16_t cmd_actag,             
  	 	 uint8_t cmd_stream_id, uint8_t * cmd_ea_or_obj, 
  		 uint16_t cmd_afutag, uint8_t cmd_dl,  /* combine dl and pl ??? */
  		 uint8_t cmd_pl,                 
#ifdef TLX4
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
  	 	 uint64_t cmd_be,uint8_t cmd_flag,               
		 uint8_t cmd_endian, uint16_t cmd_bdf,               
 		 uint32_t cmd_pasid, uint8_t cmd_pg_size,            
  		 uint8_t * cdata_bus, uint8_t cdata_bad)

{
	if ((event->afu_tlx_cmd_valid == 1) || (event->afu_tlx_cdata_valid == 1)) {
		return AFU_TLX_DOUBLE_CMD_AND_DATA;
	} else {
		event->afu_tlx_cmd_valid = 1;
		event->afu_tlx_cdata_valid = 1;
		event->afu_tlx_cmd_opcode = afu_cmd_opcode;
		event->afu_tlx_cmd_actag = cmd_actag;
		event->afu_tlx_cmd_stream_id = cmd_stream_id;
		memcpy(event->afu_tlx_cmd_ea_or_obj,cmd_ea_or_obj,9); 
		event->afu_tlx_cmd_afutag = cmd_afutag;
		event->afu_tlx_cmd_dl = cmd_dl;
		event->afu_tlx_cmd_pl = cmd_pl;
#ifdef TLX4
		event->afu_tlx_cmd_os = cmd_os;
#endif
		event->afu_tlx_cmd_be = cmd_be;
		event->afu_tlx_cmd_flag = cmd_flag;
		event->afu_tlx_cmd_endian = cmd_endian;
		event->afu_tlx_cmd_bdf = cmd_bdf;
		event->afu_tlx_cmd_pasid = cmd_pasid;
		event->afu_tlx_cmd_pg_size = cmd_pg_size;
		event->afu_tlx_cdata_bad = cdata_bad;
		// TODO FOR NOW WE ALWAYS COPY 8 BYTES of DATA - AFU ALWAYS
		// SENDS 8 BYTES 
		memcpy(event->afu_tlx_cdata_bus, cdata_bus, 8);
		return TLX_SUCCESS;
	}
}


/* Call this from AFU to read ocse (CAPP/TL) response. This reads both tlx_afu resp AND resp data interfaces */

int tlx_afu_read_resp_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag,
		 uint8_t resp_data_is_valid, uint8_t resp_data_bdi,uint8_t * resp_data)

{
	if (!event->tlx_afu_resp_valid) {
		return TLX_AFU_RESP_NOT_VALID;
	} else {
		event->tlx_afu_resp_valid = 0;
		tlx_resp_opcode = event->tlx_afu_resp_opcode;
		resp_afutag = event->tlx_afu_resp_afutag;
		resp_code = event->tlx_afu_resp_code;
		resp_pg_size = event->tlx_afu_resp_pg_size;
		resp_dl = event->tlx_afu_resp_dl;
#ifdef TLX4
		resp_host_tag = event->tlx_afu_host_tag;
		resp_cache_state = event->tlx_afu_resp_cache_state;
#endif
		resp_dp = event->tlx_afu_resp_dp;
		resp_addr_tag = event->tlx_afu_resp_addr_tag;
		resp_data_is_valid = 0;
		if (event->tlx_afu_resp_data_valid) {
	// should we return some sort of RC other than 0 if there is no data? Should calling function be 
	// smart enough to know if data is expected? Or should we set a bit to indicate that there is data 
	// on the data bus? Call it data valid, BUT caller still has to check bdi? Or does bdi kill interface
	// at the TLX level??
			event->tlx_afu_resp_data_valid = 0;
			resp_data_is_valid = 1;
			resp_data_bdi = event->tlx_afu_resp_data_bdi;
			// TODO FOR NOW WE ALWAYS COPY 8 BYTES of DATA -OCSE 
			// SENDS 8 BYTES 
			memcpy(resp_data, event->tlx_afu_resp_data, 8);
			//return TLX_SUCCESS;
		}
	//	return TLX_AFU_RESP_NO_DATA;
		return TLX_SUCCESS;
	}
}


/* Call this from AFU to read ocse (CAPP/TL) command. This reads both tlx_afu cmd AND cmd data interfaces */

int tlx_afu_read_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
		 uint64_t cmd_pa, uint8_t cmd_flag, 
#ifdef TLX4
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
		 uint8_t cmd_data_is_valid, uint8_t cmd_data_bdi,uint8_t * cmd_data)

{
	if (!event->tlx_afu_cmd_valid) {
		return TLX_AFU_CMD_NOT_VALID;
	} else {
		event->tlx_afu_cmd_valid = 0;
		tlx_cmd_opcode = event->tlx_afu_cmd_opcode;
		cmd_capptag = event->tlx_afu_cmd_capptag;
		cmd_dl = event->tlx_afu_cmd_dl;
		cmd_pl = event->tlx_afu_cmd_pl;
		cmd_be = event->tlx_afu_cmd_be;
		cmd_end = event->tlx_afu_cmd_end;
		cmd_t = event->tlx_afu_cmd_t;
		cmd_pa = event->tlx_afu_cmd_pa;
#ifdef TLX4
		cmd_flag = event->tlx_afu_cmd_flag;
		cmd_os = event->tlx_afu_cmd_os;
#endif
		cmd_data_is_valid = 0;
		if (event->tlx_afu_cmd_data_valid) {
	// should we return some sort of RC other than 0 if there is no data? Should calling function be 
	// smart enough to know if data is expected? Or should we set a bit to indicate that there is data 
	// on the data bus? Call it data valid, BUT caller still has to check bdi? Or does bdi kill interface
	// at the TLX level??
			event->tlx_afu_cmd_data_valid = 0;
			cmd_data_is_valid = 1;
			cmd_data_bdi = event->tlx_afu_cmd_data_bdi;
			// TODO FOR NOW WE ALWAYS COPY 4 BYTES of DATA - OCSE
			// SENDS 4 BYTES 
			memcpy(cmd_data, event->tlx_afu_cmd_data_bus, 4);
			//return TLX_SUCCESS;
		}
		//return TLX_AFU_CMD_NO_DATA;
		return TLX_SUCCESS;
	}
}


// TODO Still to come - add credits to interfaces.....




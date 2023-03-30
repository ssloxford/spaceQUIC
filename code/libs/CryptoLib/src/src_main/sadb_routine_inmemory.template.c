/*
 * Copyright 2021, by the California Institute of Technology.
 * ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
 * Any commercial use must be negotiated with the Office of Technology
 * Transfer at the California Institute of Technology.
 *
 * This software may be subject to U.S. export control laws. By accepting
 * this software, the user agrees to comply with all applicable U.S.
 * export laws and regulations. User has the responsibility to obtain
 * export licenses, or other export authority as may be required before
 * exporting such information to foreign countries or providing access to
 * foreign persons.
 */

#include <string.h>
#include "crypto.h"

// Security Association Initialization Functions
static int32_t sadb_config(void);
static int32_t sadb_init(void);
static int32_t sadb_close(void);
// Security Association Interaction Functions
static int32_t sadb_get_sa_from_spi(uint16_t, SecurityAssociation_t **);
static int32_t sadb_get_operational_sa_from_gvcid(uint8_t, uint16_t, uint16_t, uint8_t, SecurityAssociation_t **);
static int32_t sadb_save_sa(SecurityAssociation_t *sa);
// Security Association Utility Functions
static int32_t sadb_sa_stop(void);
static int32_t sadb_sa_start(TC_t *tc_frame);
static int32_t sadb_sa_expire(void);
static int32_t sadb_sa_rekey(void);
static int32_t sadb_sa_status(uint8_t *);
static int32_t sadb_sa_create(void);
static int32_t sadb_sa_setARSN(void);
static int32_t sadb_sa_setARSNW(void);
static int32_t sadb_sa_delete(void);

/*
** Global Variables
*/
// Security
static SadbRoutineStruct sadb_routine_struct;
static SecurityAssociation_t sa[NUM_SA];

/**
 * @brief Function: get_sadb_routine_inmemory
 * @return SadbRoutine
 **/
SadbRoutine get_sadb_routine_inmemory(void) {
    sadb_routine_struct.sadb_config = sadb_config;
    sadb_routine_struct.sadb_init = sadb_init;
    sadb_routine_struct.sadb_close = sadb_close;
    sadb_routine_struct.sadb_get_sa_from_spi = sadb_get_sa_from_spi;
    sadb_routine_struct.sadb_get_operational_sa_from_gvcid = sadb_get_operational_sa_from_gvcid;
    sadb_routine_struct.sadb_sa_stop = sadb_sa_stop;
    sadb_routine_struct.sadb_save_sa = sadb_save_sa;
    sadb_routine_struct.sadb_sa_start = sadb_sa_start;
    sadb_routine_struct.sadb_sa_expire = sadb_sa_expire;
    sadb_routine_struct.sadb_sa_rekey = sadb_sa_rekey;
    sadb_routine_struct.sadb_sa_status = sadb_sa_status;
    sadb_routine_struct.sadb_sa_create = sadb_sa_create;
    sadb_routine_struct.sadb_sa_setARSN = sadb_sa_setARSN;
    sadb_routine_struct.sadb_sa_setARSNW = sadb_sa_setARSNW;
    sadb_routine_struct.sadb_sa_delete = sadb_sa_delete;
    return &sadb_routine_struct;
}

/**
 * @brief Function; sadb_config
 * @return int32: Success/Failure
 **/
int32_t sadb_config(void) {
    sadb_init();

    sa[0].spi = 0;
    sa[0].ekid = 130;
    sa[0].sa_state = SA_OPERATIONAL;
    sa[0].est = 1;
    sa[0].ast = 1;
    sa[0].ecs_len = 1;
    sa[0].ecs = calloc(1, sa[0].ecs_len * sizeof(uint8_t));
    *sa[0].ecs = CRYPTO_CIPHER_AES256_GCM;
    sa[0].shivf_len = 12;
    sa[0].iv_len = 12;
    sa[0].stmacf_len = 16;
    sa[0].iv = (uint8_t *) calloc(1, sa[0].shivf_len * sizeof(uint8_t));
    *(sa[0].iv + sa[0].shivf_len - 1) = 0;
    sa[0].abm_len = ABM_SIZE; // 20
    sa[0].abm = (uint8_t *) calloc(1, sa[0].abm_len * sizeof(uint8_t));
    sa[0].abm[0] = 0xf0;
    sa[0].abm[1] = 0xf0;
    sa[0].abm[2] = 0xa0;
    sa[0].abm[3] = 0xb0;
    sa[0].abm[4] = 0x50;
    sa[0].abm[5] = 0x70;
    sa[0].abm[6] = 0xf6;
    sa[0].abm[7] = 0x80;
    sa[0].abm[8] = 0x00;
    sa[0].abm[9] = 0xf0;
    sa[0].abm[10] = 0x55;
    sa[0].abm[11] = 0x14;
    sa[0].abm[12] = 0xa4;
    sa[0].abm[13] = 0xb4;
    sa[0].abm[14] = 0xc4;
    sa[0].abm[15] = 0x1f;
    sa[0].abm[16] = 0x15;
    sa[0].abm[17] = 0x74;
    sa[0].abm[18] = 0x84;
    sa[0].abm[19] = 0x94;
    sa[0].arsnw_len = 1;
    sa[0].arsnw = 5;
    sa[0].arsn_len = 0;
    sa[0].arsn = NULL;
    sa[0].gvcid_tc_blk.tfvn = 0;
    sa[0].gvcid_tc_blk.mapid = TYPE_TC;
    sa[0].gvcid_tc_blk.scid = 0;
    sa[0].gvcid_tc_blk.vcid = 0;

    //////////

    sa[1].spi = 1;
    sa[1].ekid = 131;
    sa[1].sa_state = SA_OPERATIONAL;
    sa[1].est = 1;
    sa[1].ast = 1;
    sa[1].ecs_len = 1;
    sa[1].ecs = calloc(1, sa[1].ecs_len * sizeof(uint8_t));
    *sa[1].ecs = CRYPTO_CIPHER_AES256_GCM;
    sa[1].shivf_len = 12;
    sa[1].iv_len = 12;
    sa[1].stmacf_len = 16;
    sa[1].iv = (uint8_t *) calloc(1, sa[1].shivf_len * sizeof(uint8_t));
    *(sa[1].iv + sa[1].shivf_len - 1) = 0;
    sa[1].abm_len = ABM_SIZE; // 20
    sa[1].abm = (uint8_t *) calloc(1, sa[1].abm_len * sizeof(uint8_t));
    sa[1].abm[0] = 0xf0;
    sa[1].abm[1] = 0xf0;
    sa[1].abm[2] = 0xa0;
    sa[1].abm[3] = 0xb0;
    sa[1].abm[4] = 0x50;
    sa[1].abm[5] = 0x70;
    sa[1].abm[6] = 0xf6;
    sa[1].abm[7] = 0x80;
    sa[1].abm[8] = 0x00;
    sa[1].abm[9] = 0xf0;
    sa[1].abm[10] = 0x55;
    sa[1].abm[11] = 0x14;
    sa[1].abm[12] = 0xa4;
    sa[1].abm[13] = 0xb4;
    sa[1].abm[14] = 0xc4;
    sa[1].abm[15] = 0x1f;
    sa[1].abm[16] = 0x15;
    sa[1].abm[17] = 0x74;
    sa[1].abm[18] = 0x84;
    sa[1].abm[19] = 0x94;
    sa[1].arsnw_len = 1;
    sa[1].arsnw = 5;
    sa[1].arsn_len = 0;
    sa[1].arsn = NULL;
    sa[1].gvcid_tc_blk.tfvn = 0;
    sa[1].gvcid_tc_blk.mapid = TYPE_TC;
    sa[1].gvcid_tc_blk.scid = 1;
    sa[1].gvcid_tc_blk.vcid = 0;

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_init
 * @return int32: Success/Failure
 **/
int32_t sadb_init(void) {
    int32_t status = CRYPTO_LIB_SUCCESS;
    int x;

    for (x = 0; x < NUM_SA; x++) {
        sa[x].ekid = x;
        sa[x].akid = x;
        sa[x].sa_state = SA_NONE;
        sa[x].ecs_len = 0;
        sa[x].ecs = NULL;
        sa[x].shivf_len = 0;
        sa[x].iv = NULL;
        sa[x].iv_len = 0;
        sa[x].abm = NULL;
        sa[x].abm_len = 0;
        sa[x].acs_len = 0;
        sa[x].acs = NULL;
        sa[x].shsnf_len = 0;
        sa[x].arsn_len = 0;
        sa[x].arsn = NULL;
    }
    return status;
}

/**
 * @brief Function: sadb_close
 * @return int32: Success/Failure
 **/
static int32_t sadb_close(void) {
    int32_t status = CRYPTO_LIB_SUCCESS;
    int x;

    for (x = 0; x < NUM_SA; x++) {
        if (sa[x].ecs != NULL) free(sa[x].ecs);
        if (sa[x].iv != NULL) free(sa[x].iv);
        if (sa[x].abm != NULL) free(sa[x].abm);
        if (sa[x].arsn != NULL) free(sa[x].arsn);
    }
    return status;
}

/*
** Security Association Interaction Functions
*/
/**
 * @brief Function: sadb_get_sa_from_spi
 * @param spi: uint16
 * @param security_association: SecurityAssociation_t**
 * @return int32: Success/Failure
 **/
static int32_t sadb_get_sa_from_spi(uint16_t spi, SecurityAssociation_t **security_association) {
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa == NULL) {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    *security_association = &sa[spi];
    if (sa[spi].iv == NULL && (sa[spi].ast == 1 || sa[spi].est == 1)) {
        return CRYPTO_LIB_ERR_NULL_IV;
    } // Must have IV if doing encryption or authentication
    if (sa[spi].abm == NULL && sa[spi].ast) {
        return CRYPTO_LIB_ERR_NULL_ABM;
    } // Must have IV if doing encryption or authentication
#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing local copy of SA Entry for current SPI.\n" RESET);
    Crypto_saPrint(*security_association);
#endif
    return status;
}

/**
 * @brief Function: sadb_get_operational_sa_from_gvcid
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint16
 * @param mapid: uint8
 * @param security_association: SecurityAssociation_t**
 * @return int32: Success/Failure
 **/
static int32_t sadb_get_operational_sa_from_gvcid(uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid,
                                                  SecurityAssociation_t **security_association) {
    int32_t status = CRYPTO_LIB_ERR_NO_OPERATIONAL_SA;
    int i;

    if (sa == NULL) {
        return CRYPTO_LIB_ERR_NO_INIT;
    }

    for (i = 0; i < 10; i++) {
        if ((sa[i].gvcid_tc_blk.tfvn == tfvn) && (sa[i].gvcid_tc_blk.scid == scid) &&
            (sa[i].gvcid_tc_blk.vcid == vcid) && (sa[i].sa_state == SA_OPERATIONAL) &&
            (crypto_config->unique_sa_per_mapid == TC_UNIQUE_SA_PER_MAP_ID_FALSE ||
             sa[i].gvcid_tc_blk.mapid == mapid)) // only require MapID match is unique SA per MapID set (only relevant
            // when using segmentation hdrs)
        {
            *security_association = &sa[i];
            if (sa[i].iv == NULL && (sa[i].ast == 1 || sa[i].est == 1)) {
                return CRYPTO_LIB_ERR_NULL_IV;
            }
            if (sa[i].abm == NULL && sa[i].ast) {
                return CRYPTO_LIB_ERR_NULL_ABM;
            } // Must have IV if doing encryption or authentication

#ifdef SA_DEBUG
            printf("Valid operational SA found at index %d.\n", i);
#endif

            status = CRYPTO_LIB_SUCCESS;
            break;
        }
    }

    // If not a success, attempt to generate a meaningful error code
    if (status != CRYPTO_LIB_SUCCESS) {
#ifdef SA_DEBUG
        printf(KRED "Error - Making best attempt at a useful error code:\n\t" RESET);
#endif

        for (i = 0; i < NUM_SA; i++) {
            // Could possibly have more than one field mismatched,
            // ordering so the 'most accurate' SA's error is returned
            // (determined by matching header fields L to R)
            if ((sa[i].gvcid_tc_blk.tfvn != tfvn) && (sa[i].gvcid_tc_blk.scid == scid) &&
                (sa[i].gvcid_tc_blk.vcid == vcid) &&
                (sa[i].gvcid_tc_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL)) {
#ifdef SA_DEBUG
                printf(KRED "An operational SA was found - but mismatched tfvn.\n" RESET);
#endif
                status = CRYPTO_LIB_ERR_INVALID_TFVN;
            }
            if ((sa[i].gvcid_tc_blk.tfvn == tfvn) && (sa[i].gvcid_tc_blk.scid != scid) &&
                (sa[i].gvcid_tc_blk.vcid == vcid) &&
                (sa[i].gvcid_tc_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL)) {
#ifdef SA_DEBUG
                printf(KRED "An operational SA was found - but mismatched scid.\n" RESET);
#endif
                status = CRYPTO_LIB_ERR_INVALID_SCID;
            }
            if ((sa[i].gvcid_tc_blk.tfvn == tfvn) && (sa[i].gvcid_tc_blk.scid == scid) &&
                (sa[i].gvcid_tc_blk.vcid != vcid) &&
                (sa[i].gvcid_tc_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL)) {
#ifdef SA_DEBUG
                printf(KRED "An operational SA was found - but mismatched vcid.\n" RESET);
#endif
                status = CRYPTO_LIB_ERR_INVALID_VCID;
            }
            if ((sa[i].gvcid_tc_blk.tfvn == tfvn) && (sa[i].gvcid_tc_blk.scid == scid) &&
                (sa[i].gvcid_tc_blk.vcid == vcid) &&
                (sa[i].gvcid_tc_blk.mapid != mapid && sa[i].sa_state == SA_OPERATIONAL)) {
#ifdef SA_DEBUG
                printf(KRED "An operational SA was found - but mismatched mapid.\n" RESET);
#endif
                status = CRYPTO_LIB_ERR_INVALID_MAPID;
            }
            if ((sa[i].gvcid_tc_blk.tfvn == tfvn) && (sa[i].gvcid_tc_blk.scid == scid) &&
                (sa[i].gvcid_tc_blk.vcid == vcid) &&
                (sa[i].gvcid_tc_blk.mapid == mapid && sa[i].sa_state != SA_OPERATIONAL)) {
#ifdef SA_DEBUG
                printf(KRED "A valid but non-operational SA was found.\n" RESET);
#endif
                status = CRYPTO_LIB_ERR_NO_OPERATIONAL_SA;
            }
        }
        // Detailed debug block
#ifdef SA_DEBUG
        printf(KYEL "Incoming frame parameters:\n" RESET);
        printf(KYEL "\ttfvn %02X\n" RESET, tfvn);
        printf(KYEL "\tscid %04X\n" RESET, scid);
        printf(KYEL "\tvcid %02X\n" RESET, vcid);
        printf(KYEL "\tmapid %02X\n" RESET, mapid);
#endif
    }

    return status;
}

// TODO: Nothing actually happens here
/**
 * @brief Function: sadb_save_sa
 * @param sa: SecurityAssociation_t*
 * @return int32: Success/Failure
 * @note Nothing currently actually happens in this function
 **/
static int32_t sadb_save_sa(SecurityAssociation_t *sa) {
    int32_t status = CRYPTO_LIB_SUCCESS;
    sa = sa; // TODO - use argument
    // We could do a memory copy of the SA into the sa[NUM_SA] array at the given SPI, however, the inmemory code
    // currently updates in place so no need for that.
    //  If we change the in-place update logic, we should update this function to actually update the SA.
    return status;
}

/*
** Security Association Management Services
*/
/**
 * @brief sadb_sa_start
 * @param tc_frame: TC_t
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_start(TC_t *tc_frame) {
    // Local variables
    uint8_t count = 0;
    uint16_t spi = 0x0000;
    crypto_gvcid_t gvcid;
    int x;
    int i;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA) {
        if (sa[spi].sa_state == SA_KEYED) {
            count = 2;

            for (x = 0; x <= ((sdls_frame.pdu.pdu_len - 2) / 4); x++) { // Read in GVCID
                gvcid.tfvn = (sdls_frame.pdu.data[count] >> 4);
                gvcid.scid = (sdls_frame.pdu.data[count] << 12) | (sdls_frame.pdu.data[count + 1] << 4) |
                             (sdls_frame.pdu.data[count + 2] >> 4);
                gvcid.vcid = (sdls_frame.pdu.data[count + 2] << 4) | (sdls_frame.pdu.data[count + 3] && 0x3F);
                if (current_managed_parameters->has_segmentation_hdr == TC_HAS_SEGMENT_HDRS) {
                    gvcid.mapid = (sdls_frame.pdu.data[count + 3]);
                } else {
                    gvcid.mapid = 0;
                }

                // TC
                if (gvcid.vcid != tc_frame->tc_header.vcid) { // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TC) {
                        sa[spi].gvcid_tc_blk.tfvn = 0;
                        sa[spi].gvcid_tc_blk.scid = 0;
                        sa[spi].gvcid_tc_blk.vcid = 0;
                        sa[spi].gvcid_tc_blk.mapid = 0;
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP) { // TC
                        sa[spi].gvcid_tc_blk.tfvn = gvcid.tfvn;
                        sa[spi].gvcid_tc_blk.scid = gvcid.scid;
                        sa[spi].gvcid_tc_blk.mapid = gvcid.mapid;
                    } else {
                        // TODO: Handle TYPE_MAP
                    }
                }
                // TM
                if (gvcid.vcid != tm_frame.tm_header.vcid) { // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TM) {
                        for (i = 0; i < NUM_GVCID; i++) { // TM
                            sa[spi].gvcid_tm_blk[x].tfvn = 0;
                            sa[spi].gvcid_tm_blk[x].scid = 0;
                            sa[spi].gvcid_tm_blk[x].vcid = 0;
                            sa[spi].gvcid_tm_blk[x].mapid = 0;
                        }
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP) { // TM
                        sa[spi].gvcid_tm_blk[gvcid.vcid].tfvn = gvcid.tfvn;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].scid = gvcid.scid;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].vcid = gvcid.vcid;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].mapid = gvcid.mapid;
                    } else {
                        // TODO: Handle TYPE_MAP
                    }
                }

#ifdef PDU_DEBUG
                printf("SPI %d changed to OPERATIONAL state. \n", spi);
                switch (gvcid.mapid)
                {
                case TYPE_TC:
                    printf("Type TC, ");
                    break;
                case TYPE_MAP:
                    printf("Type MAP, ");
                    break;
                case TYPE_TM:
                    printf("Type TM, ");
                    break;
                default:
                    printf("Type Unknown, ");
                    break;
                }
#endif

                // Change to operational state
                sa[spi].sa_state = SA_OPERATIONAL;
            }
        } else {
            printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    } else {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    printf("\t spi = %d \n", spi);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_stop
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_stop(void) {
    // Local variables
    uint16_t spi = 0x0000;
    int x;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Active' state
    if (spi < NUM_SA) {
        if (sa[spi].sa_state == SA_OPERATIONAL) {
            // Remove all GVC/GMAP IDs
            sa[spi].gvcid_tc_blk.tfvn = 0;
            sa[spi].gvcid_tc_blk.scid = 0;
            sa[spi].gvcid_tc_blk.vcid = 0;
            sa[spi].gvcid_tc_blk.mapid = 0;
            for (x = 0; x < NUM_GVCID; x++) {
                // TM
                sa[spi].gvcid_tm_blk[x].tfvn = 0;
                sa[spi].gvcid_tm_blk[x].scid = 0;
                sa[spi].gvcid_tm_blk[x].vcid = 0;
                sa[spi].gvcid_tm_blk[x].mapid = 0;
            }

            // Change to operational state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to KEYED state. \n", spi);
#endif
        } else {
            printf(KRED "ERROR: SPI %d is not in the OPERATIONAL state.\n" RESET, spi);
        }
    } else {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    printf("\t spi = %d \n", spi);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_rekey
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_rekey(void) {
    // Local variables
    uint16_t spi = 0x0000;
    int count = 0;
    int x = 0;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[count] << 8) | (uint8_t) sdls_frame.pdu.data[count + 1];
    count = count + 2;

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA) {
        if (sa[spi].sa_state == SA_UNKEYED) { // Encryption Key
            sa[spi].ekid = ((uint8_t) sdls_frame.pdu.data[count] << 8) | (uint8_t) sdls_frame.pdu.data[count + 1];
            count = count + 2;

            // Authentication Key
            // sa[spi].akid = ((uint8_t)sdls_frame.pdu.data[count] << 8) | (uint8_t)sdls_frame.pdu.data[count+1];
            // count = count + 2;

            // Anti-Replay Seq Num
#ifdef PDU_DEBUG
            printf("SPI %d IV updated to: 0x", spi);
#endif
            if (sa[spi].shivf_len > 0) { // Set IV - authenticated encryption
                for (x = count; x < (sa[spi].shivf_len + count); x++) {
                    // TODO: Uncomment once fixed in ESA implementation
                    // TODO: Assuming this was fixed...
                    *(sa[spi].iv + x - count) = (uint8_t) sdls_frame.pdu.data[x];
#ifdef PDU_DEBUG
                    printf("%02x", sdls_frame.pdu.data[x]);
#endif
                }
            } else { // Set SN
                // TODO
            }
#ifdef PDU_DEBUG
            printf("\n");
#endif

            // Change to keyed state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to KEYED state with encrypted Key ID %d. \n", spi, sa[spi].ekid);
#endif
        } else {
            printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
        }
    } else {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    printf("\t spi  = %d \n", spi);
    printf("\t ekid = %d \n", sa[spi].ekid);
    // printf("\t akid = %d \n", sa[spi].akid);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_expire
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_expire(void) {
    // Local variables
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA) {
        if (sa[spi].sa_state == SA_KEYED) { // Change to 'Unkeyed' state
            sa[spi].sa_state = SA_UNKEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to UNKEYED state. \n", spi);
#endif
        } else {
            printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    } else {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_create
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_create(void) {
    // Local variables
    uint8_t count = 6;
    uint16_t spi = 0x0000;
    int x;

    // Read sdls_frame.pdu.data
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Write SA Configuration
    sa[spi].est = ((uint8_t) sdls_frame.pdu.data[2] & 0x80) >> 7;
    sa[spi].ast = ((uint8_t) sdls_frame.pdu.data[2] & 0x40) >> 6;
    sa[spi].shivf_len = ((uint8_t) sdls_frame.pdu.data[2] & 0x3F);
    if (sa[spi].iv != NULL) {
        free(sa[spi].iv);
    }
    sa[spi].iv = (uint8_t *) calloc(1, sa[spi].shivf_len * sizeof(uint8_t));
    sa[spi].shsnf_len = ((uint8_t) sdls_frame.pdu.data[3] & 0xFC) >> 2;
    sa[spi].shplf_len = ((uint8_t) sdls_frame.pdu.data[3] & 0x03);
    sa[spi].stmacf_len = ((uint8_t) sdls_frame.pdu.data[4]);
    sa[spi].ecs_len = ((uint8_t) sdls_frame.pdu.data[5]);
    for (x = 0; x < sa[spi].ecs_len; x++) {
        *(sa[spi].ecs + x) = ((uint8_t) sdls_frame.pdu.data[count++]);
    }
    sa[spi].shivf_len = ((uint8_t) sdls_frame.pdu.data[count++]);
    for (x = 0; x < sa[spi].shivf_len; x++) {
        *(sa[spi].iv + x) = ((uint8_t) sdls_frame.pdu.data[count++]);
    }
    sa[spi].acs_len = ((uint8_t) sdls_frame.pdu.data[count++]);
    for (x = 0; x < sa[spi].acs_len; x++) {
        *sa[spi].acs = ((uint8_t) sdls_frame.pdu.data[count++]);
    }
    sa[spi].abm_len = (uint8_t) ((sdls_frame.pdu.data[count] << 8) | (sdls_frame.pdu.data[count + 1]));
    count = count + 2;
    for (x = 0; x < sa[spi].abm_len; x++) {
        sa[spi].abm[x] = ((uint8_t) sdls_frame.pdu.data[count++]);
    }
    sa[spi].arsn_len = ((uint8_t) sdls_frame.pdu.data[count++]);
    if (sa[spi].arsn != NULL) {
        free(sa[spi].arsn);
    }
    sa[spi].arsn = (uint8_t *) calloc(1, sa[spi].arsn_len * sizeof(uint8_t));
    for (x = 0; x < sa[spi].arsn_len; x++) {
        *(sa[spi].arsn + x) = ((uint8_t) sdls_frame.pdu.data[count++]);
    }
    sa[spi].arsnw_len = ((uint8_t) sdls_frame.pdu.data[count++]);
    for (x = 0; x < sa[spi].arsnw_len; x++) {
        sa[spi].arsnw = sa[spi].arsnw | (((uint8_t) sdls_frame.pdu.data[count++]) << (sa[spi].arsnw_len - x));
    }

    // TODO: Checks for valid data

    // Set state to unkeyed
    sa[spi].sa_state = SA_UNKEYED;

#ifdef PDU_DEBUG
    Crypto_saPrint(&sa[spi]);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_delete
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_delete(void) {
    // Local variables
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid =
            (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA) {
        if (sa[spi].sa_state == SA_UNKEYED) { // Change to 'None' state
            sa[spi].sa_state = SA_NONE;
#ifdef PDU_DEBUG
            printf("SPI %d changed to NONE state. \n", spi);
#endif

            // TODO: Zero entire SA
        } else {
            printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
        }
    } else {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_setASRN
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_setARSN(void) {
    // Local variables
    uint16_t spi = 0x0000;
    int x;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // TODO: Check SA type (authenticated, encrypted, both) and set appropriately
    // TODO: Add more checks on bounds

    // Check SPI exists
    if (spi < NUM_SA) {
#ifdef PDU_DEBUG
        printf("SPI %d IV updated to: 0x", spi);
#endif
        if (sa[spi].shivf_len > 0) { // Set IV - authenticated encryption
            for (x = 0; x < IV_SIZE; x++) {
                *(sa[spi].iv + x) = (uint8_t) sdls_frame.pdu.data[x + 2];
#ifdef PDU_DEBUG
                printf("%02x", *(sa[spi].iv + x));
#endif
            }
            Crypto_increment(sa[spi].iv, sa[spi].shivf_len);
        } else { // Set SN
            // TODO
        }
#ifdef PDU_DEBUG
        printf("\n");
#endif
    } else {
        printf("sadb_sa_setARSN ERROR: SPI %d does not exist.\n", spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_setARSNW
 * @return int32: Success/Failure
 **/
static int32_t sadb_sa_setARSNW(void) {
    // Local variables
    uint16_t spi = 0x0000;
    int x;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Check SPI exists
    if (spi < NUM_SA) {
        sa[spi].arsnw_len = (uint8_t) sdls_frame.pdu.data[2];

        // Check for out of bounds
        if (sa[spi].arsnw_len > (ARSN_SIZE)) {
            sa[spi].arsnw_len = ARSN_SIZE;
        }

        for (x = 0; x < sa[spi].arsnw_len; x++) {
            sa[spi].arsnw = (((uint8_t) sdls_frame.pdu.data[x + 3]) << (sa[spi].arsnw_len - x));
        }
    } else {
        printf("sadb_sa_setARSNW ERROR: SPI %d does not exist.\n", spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sadb_sa_status
 * @param ingest: uint8_t*
 * @return int32: count
 **/
static int32_t sadb_sa_status(uint8_t *ingest) {
    if (ingest == NULL) return CRYPTO_LIB_ERROR;

    // Local variables
    int count = 0;
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t) sdls_frame.pdu.data[0] << 8) | (uint8_t) sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Check SPI exists
    if (spi < NUM_SA) {
        // Prepare for Reply
        sdls_frame.pdu.pdu_len = 3;
        sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
        count = Crypto_Prep_Reply(ingest, 128);
        // PDU
        ingest[count++] = (spi & 0xFF00) >> 8;
        ingest[count++] = (spi & 0x00FF);
        ingest[count++] = sa[spi].lpid;
    } else {
        printf("sadb_sa_status ERROR: SPI %d does not exist.\n", spi);
    }

#ifdef SA_DEBUG
    Crypto_saPrint(&sa[spi]);
#endif

    return count;
}